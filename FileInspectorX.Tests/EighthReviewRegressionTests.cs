using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class EighthReviewRegressionTests
{
    [Fact]
    public void LargeJavaClassHasByteStreamAndPathParity()
    {
        var bytes = LargeJavaClass();

        Assert.True(bytes.Length > Settings.HeaderReadBytes);
        AssertParity(bytes, "class", "High");

        var truncated = bytes.Take(bytes.Length - 1).ToArray();
        Assert.NotEqual("class", FileInspector.Detect(truncated)?.Extension);
    }

    [Fact]
    public void SampledMatroskaRootVoidRetainsContainerIdentityAtMediumConfidence()
    {
        var bytes = MatroskaWithLargeRootVoid();
        using var stream = new NonSeekableReadStream(bytes);

        var result = FileInspector.Detect(stream);

        Assert.Equal("matroska", result?.Extension);
        Assert.Equal("Medium", result?.Confidence);
        Assert.Equal("ebml:doctype=matroska;sampled-root-void", result?.Reason);
    }

    [Fact]
    public void FtypScansPastTheFormerSixtyBrandLimit()
        => AssertParity(FtypWithDecisiveBrand(61), "avif", "High");

    [Fact]
    public void SeekableFtypScansCompatibilityListsBeyondTheHeaderSample()
    {
        var bytes = FtypWithDecisiveBrand(1100);

        Assert.True(bytes.Length > Settings.HeaderReadBytes);
        AssertParity(bytes, "avif", "High");

        using var stream = new NonSeekableReadStream(bytes);
        var sampled = FileInspector.Detect(stream);
        Assert.Equal("mp4", sampled?.Extension);
        Assert.Equal("Medium", sampled?.Confidence);
        Assert.Equal("ftyp:mp4;sampled-compatible-brands", sampled?.Reason);
    }

    [Fact]
    public void MidiRequiresBoundedTracksAndAnEndOfTrackEvent()
    {
        var valid = MinimalMidi();
        AssertParity(valid, "mid", "High");

        var oversizedTrack = (byte[])valid.Clone();
        WriteUInt32BigEndian(oversizedTrack, 18, uint.MaxValue);
        Assert.NotEqual("mid", FileInspector.Detect(oversizedTrack)?.Extension);

        var missingEndOfTrack = (byte[])valid.Clone();
        new byte[] { 0, 0x90, 60, 64 }.CopyTo(missingEndOfTrack, 22);
        Assert.NotEqual("mid", FileInspector.Detect(missingEndOfTrack)?.Extension);
    }

    [Fact]
    public void LargeMidiHasByteStreamAndPathParity()
    {
        var bytes = LargeMidi();

        Assert.True(bytes.Length > Settings.HeaderReadBytes);
        AssertParity(bytes, "mid", "High");
    }

    private static void AssertParity(byte[] bytes, string extension, string confidence)
    {
        var fromBytes = FileInspector.Detect(bytes);
        using var stream = new MemoryStream(bytes, writable: false);
        long originalPosition = Math.Min(7, stream.Length);
        stream.Position = originalPosition;
        var fromStream = FileInspector.Detect(stream);
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            File.WriteAllBytes(path, bytes);
            var fromPath = FileInspector.Detect(path);
            Assert.Equal(extension, fromBytes?.Extension);
            Assert.Equal(extension, fromStream?.Extension);
            Assert.Equal(extension, fromPath?.Extension);
            Assert.Equal(confidence, fromBytes?.Confidence);
            Assert.Equal(confidence, fromStream?.Confidence);
            Assert.Equal(confidence, fromPath?.Confidence);
            Assert.Equal(originalPosition, stream.Position);
        }
        finally
        {
            TestHelpers.SafeDelete(path);
        }
    }

    private static byte[] LargeJavaClass()
    {
        using var stream = new MemoryStream();
        WriteUInt32BigEndian(stream, 0xCAFEBABE);
        WriteUInt16BigEndian(stream, 0);
        WriteUInt16BigEndian(stream, 52);
        WriteUInt16BigEndian(stream, 6);
        WriteJavaUtf8(stream, "Test");
        stream.WriteByte(7);
        WriteUInt16BigEndian(stream, 1);
        WriteJavaUtf8(stream, "java/lang/Object");
        stream.WriteByte(7);
        WriteUInt16BigEndian(stream, 3);
        WriteJavaUtf8(stream, "Blob");
        WriteUInt16BigEndian(stream, 0x21);
        WriteUInt16BigEndian(stream, 2);
        WriteUInt16BigEndian(stream, 4);
        WriteUInt16BigEndian(stream, 0);
        WriteUInt16BigEndian(stream, 0);
        WriteUInt16BigEndian(stream, 0);
        WriteUInt16BigEndian(stream, 1);
        WriteUInt16BigEndian(stream, 5);
        WriteUInt32BigEndian(stream, 5000);
        stream.Write(new byte[5000], 0, 5000);
        return stream.ToArray();
    }

    private static void WriteJavaUtf8(Stream stream, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        stream.WriteByte(1);
        WriteUInt16BigEndian(stream, checked((ushort)bytes.Length));
        stream.Write(bytes, 0, bytes.Length);
    }

    private static byte[] MatroskaWithLargeRootVoid()
    {
        const int voidLength = 5000;
        byte[] segment = TestHelpers.CreateMinimalMatroska().Skip(16).ToArray();
        var bytes = new byte[16 + 3 + voidLength + segment.Length];
        new byte[] { 0x1A, 0x45, 0xDF, 0xA3, 0x8B, 0x42, 0x82, 0x88 }.CopyTo(bytes, 0);
        Encoding.ASCII.GetBytes("matroska").CopyTo(bytes, 8);
        bytes[16] = 0xEC;
        bytes[17] = 0x53;
        bytes[18] = 0x88;
        segment.CopyTo(bytes, 19 + voidLength);
        return bytes;
    }

    private static byte[] FtypWithDecisiveBrand(int compatibleBrandCount)
    {
        int fileTypeLength = 16 + compatibleBrandCount * 4;
        var bytes = new byte[fileTypeLength + 8];
        WriteUInt32BigEndian(bytes, 0, checked((uint)fileTypeLength));
        Encoding.ASCII.GetBytes("ftyp").CopyTo(bytes, 4);
        Encoding.ASCII.GetBytes("isom").CopyTo(bytes, 8);
        for (int index = 0; index < compatibleBrandCount; index++)
            Encoding.ASCII.GetBytes(index == compatibleBrandCount - 1 ? "avif" : "zzzz").CopyTo(bytes, 16 + index * 4);
        WriteUInt32BigEndian(bytes, fileTypeLength, 8);
        Encoding.ASCII.GetBytes("free").CopyTo(bytes, fileTypeLength + 4);
        return bytes;
    }

    private static byte[] MinimalMidi()
    {
        var bytes = new byte[26];
        Encoding.ASCII.GetBytes("MThd").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 6);
        WriteUInt16BigEndian(bytes, 8, 0);
        WriteUInt16BigEndian(bytes, 10, 1);
        WriteUInt16BigEndian(bytes, 12, 96);
        Encoding.ASCII.GetBytes("MTrk").CopyTo(bytes, 14);
        WriteUInt32BigEndian(bytes, 18, 4);
        new byte[] { 0, 0xFF, 0x2F, 0 }.CopyTo(bytes, 22);
        return bytes;
    }

    private static byte[] LargeMidi()
    {
        const int channelEvents = 1100;
        int trackLength = channelEvents * 4 + 4;
        var bytes = new byte[22 + trackLength];
        Encoding.ASCII.GetBytes("MThd").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 6);
        WriteUInt16BigEndian(bytes, 8, 0);
        WriteUInt16BigEndian(bytes, 10, 1);
        WriteUInt16BigEndian(bytes, 12, 96);
        Encoding.ASCII.GetBytes("MTrk").CopyTo(bytes, 14);
        WriteUInt32BigEndian(bytes, 18, (uint)trackLength);
        int cursor = 22;
        for (int index = 0; index < channelEvents; index++)
        {
            bytes[cursor++] = 0;
            bytes[cursor++] = 0x90;
            bytes[cursor++] = 60;
            bytes[cursor++] = 64;
        }
        new byte[] { 0, 0xFF, 0x2F, 0 }.CopyTo(bytes, cursor);
        return bytes;
    }

    private static void WriteUInt16BigEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)(value >> 8);
        bytes[offset + 1] = (byte)value;
    }

    private static void WriteUInt32BigEndian(byte[] bytes, int offset, uint value)
    {
        bytes[offset] = (byte)(value >> 24);
        bytes[offset + 1] = (byte)(value >> 16);
        bytes[offset + 2] = (byte)(value >> 8);
        bytes[offset + 3] = (byte)value;
    }

    private static void WriteUInt16BigEndian(Stream stream, ushort value)
    {
        stream.WriteByte((byte)(value >> 8));
        stream.WriteByte((byte)value);
    }

    private static void WriteUInt32BigEndian(Stream stream, uint value)
    {
        stream.WriteByte((byte)(value >> 24));
        stream.WriteByte((byte)(value >> 16));
        stream.WriteByte((byte)(value >> 8));
        stream.WriteByte((byte)value);
    }

    private sealed class NonSeekableReadStream : Stream
    {
        private readonly MemoryStream _inner;

        internal NonSeekableReadStream(byte[] bytes) => _inner = new MemoryStream(bytes, writable: false);
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing) _inner.Dispose();
            base.Dispose(disposing);
        }
    }
}
