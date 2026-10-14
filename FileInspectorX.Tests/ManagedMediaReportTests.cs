using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class ManagedMediaReportTests
{
    [Fact]
    public void WaveFactsRetainDeclaredAndDerivedEvidenceWithoutDecodingPayload()
    {
        var report = Analyze(Wave(), "recording.wav");
        Assert.Equal("wave-metadata", report.Content.Reader);
        Assert.Equal("48000", Fact(report, "Audio.SampleRate").Value);
        Assert.Equal("2", Fact(report, "Audio.Channels").Value);
        Assert.Equal("1", Fact(report, "Audio.DeclaredDurationSeconds").Value);
        Assert.Equal(ReportFactOrigin.Embedded, Fact(report, "Audio.SampleRate").Origin);
        Assert.Equal(24, Fact(report, "Audio.SampleRate").Source!.ByteOffset);
        Assert.Equal(ReportFactOrigin.Derived, Fact(report, "Audio.DeclaredDurationSeconds").Origin);
        Assert.Contains("media:payload-not-decoded", report.Content.Issues);
    }

    [Fact]
    public void FlacStreamInfoAndCommentsAreBoundedContainerClaims()
    {
        var info = new byte[34]; info[1] = 16; info[3] = 16;
        ulong packed = (ulong)44100 << 44 | 1UL << 41 | 15UL << 36 | 88200;
        for (int i = 0; i < 8; i++) info[10 + i] = (byte)(packed >> (56 - 8 * i));
        var comment = Encoding.UTF8.GetBytes("TITLE=Quarterly meeting");
        using var comments = new MemoryStream(); using (var writer = new BinaryWriter(comments, Encoding.UTF8, true))
        { writer.Write(0); writer.Write(1); writer.Write(comment.Length); writer.Write(comment); }
        using var input = new MemoryStream(); input.Write(Encoding.ASCII.GetBytes("fLaC"), 0, 4);
        input.Write(new byte[] { 0, 0, 0, 34 }, 0, 4); input.Write(info, 0, info.Length);
        var text = comments.ToArray(); input.Write(new[] { (byte)132, (byte)0, (byte)0, (byte)text.Length }, 0, 4); input.Write(text, 0, text.Length);
        var report = Analyze(input.ToArray(), "recording.flac");
        Assert.Equal("flac-metadata", report.Content.Reader);
        Assert.Equal("2", Fact(report, "Audio.DeclaredDurationSeconds").Value);
        Assert.Equal("Quarterly meeting", Fact(report, "Vorbis.TITLE").Value);
        Assert.Equal(ReportFactOrigin.Embedded, Fact(report, "Vorbis.TITLE").Origin);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public void Id3VersionsDecodeSelectedTextFramesAndPreserveDuplicateIdentity(int version)
    {
        var report = Analyze(Id3(version, "First", "Second"), "tags.mp3");
        var facts = report.Content.Facts.Where(f => f.Name == (version == 2 ? "Id3.TT2" : "Id3.TIT2")).ToArray();
        Assert.Equal(new[] { "First", "Second" }, facts.Select(f => f.Value));
        Assert.NotEqual(facts[0].Source!.Part, facts[1].Source!.Part);
        Assert.DoesNotContain(report.Content.Facts, f => f.Name.Contains("Duration"));
    }

    [Fact]
    public void Id3UnsupportedTransformAndMalformedLengthDoNotInventText()
    {
        var transformed = Id3(4, "Unread text"); transformed[19] = 2;
        var report = Analyze(transformed, "tags.mp3");
        Assert.DoesNotContain(report.Content.Facts, f => f.Name == "Id3.TIT2");
        Assert.Contains("media:id3-frame-transform-unsupported", report.Content.Issues);
        transformed = Id3(4, "Unread text"); transformed[6] = 128;
        report = Analyze(transformed, "tags.mp3");
        Assert.Equal(InspectionStageStatus.Failed, report.Content.Status);
    }

    [Fact]
    public void IsoBmffReadsTailMovieMetadataAndNeverTreatsEditedDurationAsPlaybackTime()
    {
        var report = Analyze(Movie(false), "film.mp4");
        Assert.Equal("iso-bmff-metadata", report.Content.Reader);
        Assert.Equal("avc1", Fact(report, "Track.CodecIdentifier").Value);
        Assert.Equal("1920", Fact(report, "Track.DeclaredWidth").Value);
        Assert.Equal("1080", Fact(report, "Track.DeclaredHeight").Value);
        Assert.Equal("2.5", Fact(report, "Track.DeclaredMediaDurationSeconds").Value);
        Assert.True(Fact(report, "Track.Id").Source!.ByteOffset > 300_000);
        var edited = Analyze(Movie(true), "film.mp4");
        Assert.DoesNotContain(edited.Content.Facts, f => f.Name == "Track.DeclaredMediaDurationSeconds");
        Assert.Contains("media:edit-list-not-applied", edited.Content.Issues);
    }

    [Fact]
    public void MetadataBudgetStopsTailParsingWithExplicitPartialCoverage()
    {
        var report = Analyze(Movie(false), "film.mp4", new InspectionReportOptions { MaxMetadataBytes = 16 });
        Assert.Contains("media:metadata-read-limit", report.Content.Issues);
        Assert.DoesNotContain(report.Content.Facts, f => f.Name == "Track.CodecIdentifier");
        Assert.Equal(InspectionOutcome.Partial, report.Outcome);
    }

    [Fact]
    public void FactBudgetsMarkTextPrefixesAndNeverShortenNumericClaims()
    {
        var report = Analyze(Id3(4, "😀😀"), "tags.mp3", new InspectionReportOptions { MaxFactCharacters = 3 });
        var text = Fact(report, "Id3.TIT2"); Assert.Equal("😀", text.Value); Assert.True(text.Truncated);
        report = Analyze(Wave(), "recording.wav", new InspectionReportOptions { MaxFactCharacters = 2 });
        Assert.DoesNotContain(report.Content.Facts, f => f.Name == "Audio.SampleRate");
        Assert.Equal("2", Fact(report, "Audio.Channels").Value);
        Assert.Contains("content:fact-character-limit", report.Content.Issues);
    }

    [Fact]
    public void TextLimitCannotRetainHalfOfAUnicodeScalar()
    {
        var report = Analyze(Encoding.UTF8.GetBytes("😀 document"), "document.txt", new InspectionReportOptions { MaxTextCharacters = 1 });
        Assert.Empty(report.Content.Text);
        Assert.Contains("content:text-character-limit", report.Content.Issues);
    }

    [Fact]
    public void MalformedContainerLengthsFailWithoutRetainingNonsensicalValues()
    {
        var wave = Wave(); wave[4] = wave[5] = wave[6] = wave[7] = 255;
        var report = Analyze(wave, "recording.wav");
        Assert.Equal(InspectionStageStatus.Failed, report.Content.Status);
        Assert.Empty(report.Content.Facts);
        var movie = Movie(false); movie[0] = 128;
        report = Analyze(movie, "film.mp4");
        Assert.Equal(InspectionStageStatus.Failed, report.Content.Status);
    }

#if NET8_0_OR_GREATER
    [Fact]
    public void DiskSnapshotPreservesExactIdentityCallerPositionAndCleansItsPrivateFile()
    {
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        try
        {
            var bytes = Movie(false); using var stream = new MemoryStream(bytes); stream.Position = 19;
            var report = FileInspector.AnalyzeReport(stream, "film.mp4", new InspectionReportOptions { SnapshotDirectory = directory, MaxMemorySnapshotBytes = 1024 });
            Assert.Equal(FileInspector.ReportHash(bytes), report.File.Sha256);
            Assert.Equal(19, stream.Position); Assert.True(stream.CanRead);
            Assert.Empty(Directory.GetFiles(directory));
            var saved = System.Text.Json.JsonSerializer.Deserialize<InspectionReport>(System.Text.Json.JsonSerializer.Serialize(report))!;
            Assert.Equal(report.Content.Facts.Select(f => (f.Name, f.Value, f.Kind, f.Origin, f.Source?.ByteOffset)),
                saved.Content.Facts.Select(f => (f.Name, f.Value, f.Kind, f.Origin, f.Source?.ByteOffset)));
            Assert.Equal(report.Content.Regions.Select(r => (r.Sha256, r.HashBytes)), saved.Content.Regions.Select(r => (r.Sha256, r.HashBytes)));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void SnapshotFailureRemovesSpilledBytesAndRestoresCallerOwnership()
    {
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        try
        {
            using var stream = new MemoryStream(Movie(false)); stream.Position = 7;
            var error = Assert.Throws<InspectionInputSizeLimitException>(() => FileInspector.AnalyzeReport(stream, "film.mp4",
                new InspectionReportOptions { SnapshotDirectory = directory, MaxInputBytes = 16384, MaxMemorySnapshotBytes = 1024 }));
            Assert.Equal(16384, error.MaximumBytes); Assert.True(error.ObservedBytes > error.MaximumBytes);
            Assert.Equal(7, stream.Position); Assert.True(stream.CanRead); Assert.Empty(Directory.GetFiles(directory));
        }
        finally { Directory.Delete(directory, true); }
    }
#endif

    private static InspectionReport Analyze(byte[] bytes, string name, InspectionReportOptions? options = null)
    { using var stream = new MemoryStream(bytes); return FileInspector.AnalyzeReport(stream, name, options); }
    private static ReportFact Fact(InspectionReport report, string name) => Assert.Single(report.Content.Facts, f => f.Name == name);

    private static byte[] Wave()
    {
        using var stream = new MemoryStream(); using var writer = new BinaryWriter(stream);
        writer.Write(Encoding.ASCII.GetBytes("RIFF")); writer.Write(192036); writer.Write(Encoding.ASCII.GetBytes("WAVEfmt "));
        writer.Write(16); writer.Write((ushort)1); writer.Write((ushort)2); writer.Write(48000); writer.Write(192000);
        writer.Write((ushort)4); writer.Write((ushort)16); writer.Write(Encoding.ASCII.GetBytes("data")); writer.Write(192000); writer.Write(new byte[192000]);
        return stream.ToArray();
    }

    private static byte[] Id3(int version, params string[] values)
    {
        using var payload = new MemoryStream();
        foreach (var value in values)
        {
            var text = Encoding.UTF8.GetBytes(value); int size = text.Length + 1;
            var id = Encoding.ASCII.GetBytes(version == 2 ? "TT2" : "TIT2"); payload.Write(id, 0, id.Length);
            var length = version == 2 ? new byte[] { 0, 0, (byte)size } : new byte[] { 0, 0, 0, (byte)size };
            payload.Write(length, 0, length.Length); if (version != 2) payload.Write(new byte[2], 0, 2);
            payload.WriteByte((byte)(version == 4 ? 3 : 0)); payload.Write(text, 0, text.Length);
        }
        var data = payload.ToArray(); using var stream = new MemoryStream();
        stream.Write(new byte[] { 73, 68, 51, (byte)version, 0, 0, 0, 0, (byte)(data.Length >> 7), (byte)(data.Length & 127) }, 0, 10);
        stream.Write(data, 0, data.Length); return stream.ToArray();
    }

    private static byte[] Movie(bool edited)
    {
        var track = new byte[84]; Set32(track, 12, 1); Set32(track, 76, 1920 * 65536); Set32(track, 80, 1080 * 65536);
        var media = new byte[24]; Set32(media, 12, 1000); Set32(media, 16, 2500);
        var handler = new byte[12]; Encoding.ASCII.GetBytes("vide").CopyTo(handler, 8);
        var sample = new byte[16]; Set32(sample, 4, 1); Set32(sample, 8, 8); Encoding.ASCII.GetBytes("avc1").CopyTo(sample, 12);
        var mdia = Box("mdia", Box("mdhd", media), Box("hdlr", handler), Box("minf", Box("stbl", Box("stsd", sample))));
        var trak = edited ? Box("trak", Box("tkhd", track), mdia, Box("edts", Box("elst", new byte[8]))) : Box("trak", Box("tkhd", track), mdia);
        return Join(Box("ftyp", Encoding.ASCII.GetBytes("isom\0\0\0\0isom")), Box("mdat", new byte[300_000]), Box("moov", trak));
    }
    private static byte[] Box(string name, params byte[][] payload)
    { var content = Join(payload); var bytes = new byte[content.Length + 8]; Set32(bytes, 0, bytes.Length); Encoding.ASCII.GetBytes(name).CopyTo(bytes, 4); content.CopyTo(bytes, 8); return bytes; }
    private static byte[] Join(params byte[][] data)
    { using var stream = new MemoryStream(); foreach (var part in data) stream.Write(part, 0, part.Length); return stream.ToArray(); }
    private static void Set32(byte[] data, int offset, int value)
    { for (int i = 0; i < 4; i++) data[offset + i] = (byte)((uint)value >> (24 - 8 * i)); }
}
