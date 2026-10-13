using System.Globalization;
using System.Text;

namespace FileInspectorX;

/// <summary>Bounded container metadata readers. No codec, playback, network or transcription engine is invoked.</summary>
internal static partial class ReportMediaReader
{
    internal static bool TryRead(Stream source, byte[] prefix, ContentProfile profile, Dictionary<string, string> metadata,
        HashSet<string> issues, InspectionReportOptions options)
    {
        var probe = new Probe(source, prefix, options, issues);
        string? reader = null;
        try
        {
            if (prefix.Length >= 12 && Ascii(prefix, 0, 4) == "RIFF" && Ascii(prefix, 8, 4) == "WAVE")
            { reader = "wave-metadata"; ReadWave(probe); }
            else if (prefix.Length >= 4 && Ascii(prefix, 0, 4) == "fLaC")
            { reader = "flac-metadata"; ReadFlac(probe); }
            else if (prefix.Length >= 10 && Ascii(prefix, 0, 3) == "ID3")
            { reader = "id3-metadata"; ReadId3(probe); }
            else if (prefix.Length >= 16 && Ascii(prefix, 4, 4) == "ftyp")
            { reader = "iso-bmff-metadata"; ReadIsoBmff(probe); }
            else return false;
        }
        catch (MetadataLimitException) { issues.Add("media:metadata-read-limit"); }
        catch (InvalidDataException) { issues.Add("media:container-invalid-or-truncated"); profile.Status = InspectionStageStatus.Failed; }
        catch (DecoderFallbackException) { issues.Add("media:tag-text-invalid"); }
        profile.Reader = reader!;
        profile.Facts = probe.Facts;
        foreach (var fact in probe.Facts) metadata[fact.Name + (fact.Source?.Part is { } part ? " (" + part + ")" : "")] = fact.Value;
        issues.Add("media:payload-not-decoded");
        return true;
    }

    private static string Ascii(byte[] data, int start, int length) => Encoding.ASCII.GetString(data, start, length);
    private static uint U32(byte[] data, int offset, bool little = false) => little
        ? (uint)(data[offset] | data[offset + 1] << 8 | data[offset + 2] << 16 | data[offset + 3] << 24)
        : (uint)(data[offset] << 24 | data[offset + 1] << 16 | data[offset + 2] << 8 | data[offset + 3]);
    private static ushort U16(byte[] data, int offset) => (ushort)(data[offset] | data[offset + 1] << 8);
    private static ulong U64(byte[] data, int offset) => (ulong)U32(data, offset) << 32 | U32(data, offset + 4);

    private sealed class MetadataLimitException : IOException { }

    private sealed class Probe
    {
        private readonly Stream _source;
        private readonly InspectionReportOptions _options;
        private readonly byte[] _prefix;
        private readonly HashSet<string> _issues;
        private int _bytes;
        private int _records;
        internal readonly List<ReportFact> Facts = new();
        internal long Length => _source.Length;
        internal Probe(Stream source, byte[] prefix, InspectionReportOptions options, HashSet<string> issues)
        { _source = source; _prefix = prefix; _bytes = prefix.Length; _options = options; _issues = issues; }

        internal byte[] Read(long offset, int count)
        {
            InspectionOperation.CheckCancellation();
            if (count < 0 || offset < 0 || offset > Length || count > Length - offset) throw new InvalidDataException();
            if (offset <= _prefix.Length && count <= _prefix.Length - offset)
            {
                var cached = new byte[count]; Buffer.BlockCopy(_prefix, (int)offset, cached, 0, count); return cached;
            }
            if (count > _options.MaxMetadataBytes - _bytes) throw new MetadataLimitException();
            _bytes += count;
            var data = new byte[count]; _source.Position = offset;
            var read = 0;
            while (read < count)
            { InspectionOperation.CheckCancellation(); var n = _source.Read(data, read, count - read); if (n == 0) throw new InvalidDataException(); read += n; }
            return data;
        }

        internal void Record()
        {
            InspectionOperation.CheckCancellation();
            if (++_records > 4096) throw new MetadataLimitException();
        }

        internal void Issue(string value) => _issues.Add(value);
        internal void Fact(string name, object value, long offset, int bytes, string? part = null, bool derived = false)
        {
            if (Facts.Count >= _options.MaxFacts) { _issues.Add("content:fact-count-limit"); return; }
            if (name.Length > 256) { _issues.Add("media:tag-name-limit"); return; }
            var kind = value is bool ? ReportFactKind.Boolean : value is double or decimal ? ReportFactKind.Decimal :
                value is byte or ushort or uint or ulong or int or long ? ReportFactKind.Integer : ReportFactKind.Text;
            var text = value is bool boolean ? (boolean ? "true" : "false") : Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty;
            bool truncated = false;
            if (text.Length > _options.MaxFactCharacters)
            {
                if (kind != ReportFactKind.Text) { _issues.Add("content:fact-character-limit"); return; }
                int length = _options.MaxFactCharacters;
                if (length > 0 && char.IsHighSurrogate(text[length - 1])) length--;
                text = text.Substring(0, length); truncated = true; _issues.Add("content:fact-character-limit");
            }
            Facts.Add(new ReportFact { Name = name, Kind = kind, Value = text, Truncated = truncated, Origin = derived ? ReportFactOrigin.Derived : ReportFactOrigin.Embedded,
                Source = new ReportSourceLocation { Part = part, ByteOffset = offset, ByteLength = bytes } });
        }
    }
}
