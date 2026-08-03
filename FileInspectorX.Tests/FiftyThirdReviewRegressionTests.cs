using System.Net;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

[Collection(nameof(DetectionSettingsCollection))]
public sealed class FiftyThirdReviewRegressionTests
{
    [Fact]
    public void FullNonSeekableSampleDoesNotProbeForEof()
    {
        int sampleLength = Math.Max(256, Math.Min(Settings.HeaderReadBytes, 1 << 20));
        using var stream = new SingleReadNonSeekableStream(new byte[sampleLength]);

        _ = FileInspector.Detect(stream);

        Assert.Equal(1, stream.ReadCalls);
        Assert.Equal(sampleLength, stream.BytesRead);
    }

#if NETFRAMEWORK
    [Fact]
    public void LegacyDnsResolverLimitsOutstandingTimedOutWorkers()
    {
        using var release = new ManualResetEventSlim(false);
        int entered = 0;
        IPAddress[] BlockingResolver()
        {
            Interlocked.Increment(ref entered);
            release.Wait(TimeSpan.FromSeconds(5));
            return new[] { IPAddress.Loopback };
        }

        try
        {
            Assert.False(SecurityHeuristics.TryRunBoundedLegacyResolverForTest(BlockingResolver, 50));
            Assert.False(SecurityHeuristics.TryRunBoundedLegacyResolverForTest(BlockingResolver, 50));
            Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref entered) == 2, TimeSpan.FromSeconds(2)));

            var sw = System.Diagnostics.Stopwatch.StartNew();
            Assert.False(SecurityHeuristics.TryRunBoundedLegacyResolverForTest(BlockingResolver, 500));
            sw.Stop();
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(1), $"Resolver admission was not bounded: {sw.Elapsed}.");
        }
        finally
        {
            release.Set();
        }
        Assert.True(SpinWait.SpinUntil(
            () => SecurityHeuristics.TryRunBoundedLegacyResolverForTest(() => new[] { IPAddress.Loopback }, 200),
            TimeSpan.FromSeconds(2)));
    }
#endif

    [Fact]
    public void SeekableJavaUtf8ParsingStopsAtTheReadBudget()
    {
        int originalBudget = Settings.DetectionReadBudgetBytes;
        try
        {
            Settings.DetectionReadBudgetBytes = 64;
            using var stream = new CountingMemoryStream(JavaClassWithLargeUnusedUtf8());

            Assert.True(Signatures.TryMatchJavaClass(stream, out ContentTypeDetectionResult? result));
            Assert.Equal("class", result?.Extension);
            Assert.Equal("Medium", result?.Confidence);
            Assert.Contains("sampled-read-budget", result?.Reason);
            Assert.InRange(stream.BytesRead, 0, 64);
        }
        finally
        {
            Settings.DetectionReadBudgetBytes = originalBudget;
        }
    }

    [Fact]
    public void FreeFormatMp3FrameRetainsMediumIdentity()
    {
        byte[] bytes = TestHelpers.CreateMinimalMp3();
        bytes[12] &= 0x0F;

        ContentTypeDetectionResult result = AssertParity(bytes, "mp3", "Medium");
        Assert.Contains("free-format-frame", result.Reason);
        Assert.Contains("frame-length-not-declared", result.Reason);

        bytes[12] = (byte)(bytes[12] | 0xF0);
        Assert.NotEqual("mp3", FileInspector.Detect(bytes)?.Extension);
    }

    [Fact]
    public void OriginalThirtyTwoByteDosExecutableIsDetected()
    {
        var bytes = new byte[32];
        Encoding.ASCII.GetBytes("MZ").CopyTo(bytes, 0);
        TestHelpers.WriteUInt16LittleEndian(bytes, 2, 32);
        TestHelpers.WriteUInt16LittleEndian(bytes, 4, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 8, 2);
        TestHelpers.WriteUInt16LittleEndian(bytes, 0x18, 0x1C);

        ContentTypeDetectionResult result = AssertParity(bytes, "exe", "Medium");
        Assert.Contains("mz:dos-executable", result.Reason);
    }

    private static byte[] JavaClassWithLargeUnusedUtf8()
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
        WriteJavaUtf8(stream, new string('A', 4096));
        WriteUInt16BigEndian(stream, 0x21);
        WriteUInt16BigEndian(stream, 2);
        WriteUInt16BigEndian(stream, 4);
        WriteUInt16BigEndian(stream, 0);
        WriteUInt16BigEndian(stream, 0);
        WriteUInt16BigEndian(stream, 0);
        WriteUInt16BigEndian(stream, 0);
        return stream.ToArray();
    }

    private static void WriteJavaUtf8(Stream stream, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        stream.WriteByte(1);
        WriteUInt16BigEndian(stream, checked((ushort)bytes.Length));
        stream.Write(bytes, 0, bytes.Length);
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

    private static ContentTypeDetectionResult AssertParity(byte[] bytes, string extension, string confidence)
    {
        ContentTypeDetectionResult? fromBytes = FileInspector.Detect(bytes);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(3, bytes.Length) };
        ContentTypeDetectionResult? fromStream = FileInspector.Detect(stream);
        Assert.Equal(extension, fromBytes?.Extension);
        Assert.Equal(extension, fromStream?.Extension);
        Assert.Equal(confidence, fromBytes?.Confidence);
        Assert.Equal(confidence, fromStream?.Confidence);
        Assert.Equal(Math.Min(3, bytes.Length), stream.Position);
        return fromStream!;
    }

    private sealed class SingleReadNonSeekableStream : Stream
    {
        private readonly byte[] _bytes;
        private bool _read;

        internal SingleReadNonSeekableStream(byte[] bytes) => _bytes = bytes;
        internal int ReadCalls { get; private set; }
        internal int BytesRead { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count)
        {
            ReadCalls++;
            if (_read) throw new InvalidOperationException("The detector attempted to probe beyond its sample budget.");
            _read = true;
            int read = Math.Min(count, _bytes.Length);
            Array.Copy(_bytes, 0, buffer, offset, read);
            BytesRead += read;
            return read;
        }
    }

    private sealed class CountingMemoryStream : MemoryStream
    {
        internal CountingMemoryStream(byte[] bytes) : base(bytes, writable: false) { }
        internal long BytesRead { get; private set; }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int read = base.Read(buffer, offset, count);
            BytesRead += read;
            return read;
        }

        public override int ReadByte()
        {
            int value = base.ReadByte();
            if (value >= 0) BytesRead++;
            return value;
        }
    }
}
