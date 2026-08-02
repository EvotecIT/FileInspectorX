using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

[Collection(nameof(DetectionSettingsCollection))]
public sealed class TwelfthReviewRegressionTests
{
    [Fact]
    public void Woff2RejectsReservedTransformsAndRequiresHmtxDependencies()
    {
        AssertNotDetectedAs("woff2", Woff2((0x40, 1, 1))); // Reserved transform version on head.
        AssertNotDetectedAs("woff2", Woff2((0x43, 4, 4))); // Transformed hmtx without dependencies.

        var valid = Woff2(
            (0x02, 4, null), // hhea
            (0x43, 4, 4),   // hmtx transform version 1
            (0x04, 4, null), // maxp
            (0x0A, 4, 4),   // transformed glyf
            (0x0B, 4, 0));  // transformed loca has no separate stream
        Assert.Equal("woff2", FileInspector.Detect(valid)?.Extension);
        using var stream = new MemoryStream(valid, writable: false);
        Assert.Equal("woff2", FileInspector.Detect(stream)?.Extension);
    }

    [Fact]
    public void RpmRequiresAlignedMainHeader()
    {
        var valid = Rpm();
        Assert.Equal("rpm", FileInspector.Detect(valid)?.Extension);

        var truncated = valid.Take(128).ToArray();
        AssertNotDetectedAs("rpm", truncated);

        var badMainMagic = (byte[])valid.Clone();
        badMainMagic[136] = 0;
        AssertNotDetectedAs("rpm", badMainMagic);
    }

    [Fact]
    public void NonSeekableNetCdfRetainsLargeHeaderIdentityAtMediumConfidence()
    {
        var bytes = NetCdfWithLargeGlobalAttribute();
        Assert.Equal("High", FileInspector.Detect(bytes)?.Confidence);
        using var stream = new NonSeekableReadStream(bytes);

        var sampled = FileInspector.Detect(stream);

        Assert.Equal("nc", sampled?.Extension);
        Assert.Equal("Medium", sampled?.Confidence);
        Assert.Contains("sampled-header", sampled?.Reason);
    }

    [Fact]
    public void SeekableNetCdfNameValidationHonorsReadBudget()
    {
        int originalBudget = Settings.DetectionReadBudgetBytes;
        try
        {
            Settings.DetectionReadBudgetBytes = 256;
            using var stream = new MemoryStream(NetCdfWithLongDimensionName(), writable: false) { Position = 7 };

            var result = FileInspector.Detect(stream);

            Assert.Equal("nc", result?.Extension);
            Assert.Equal("Medium", result?.Confidence);
            Assert.Contains("validation-budget-exceeded", result?.Reason);
            Assert.Equal(7, stream.Position);
        }
        finally
        {
            Settings.DetectionReadBudgetBytes = originalBudget;
        }
    }

    [Fact]
    public void OpenExrRequiresMandatoryTerminatedAttributeHeader()
    {
        AssertNotDetectedAs("exr", new byte[] { 0x76, 0x2F, 0x31, 0x01, 2, 0, 0, 0 });

        var valid = TestHelpers.CreateMinimalOpenExr();
        Assert.Equal("exr", FileInspector.Detect(valid)?.Extension);
        var missingTerminator = valid.Take(valid.Length - 1).ToArray();
        AssertNotDetectedAs("exr", missingTerminator);
    }

    [Fact]
    public void DdsDx10RequiresDefinedExtensionFields()
    {
        var valid = DdsDx10();
        Assert.Equal("dds", FileInspector.Detect(valid)?.Extension);

        var unknownFormat = (byte[])valid.Clone();
        WriteUInt32LittleEndian(unknownFormat, 128, 0);
        AssertNotDetectedAs("dds", unknownFormat);

        var unknownDimension = (byte[])valid.Clone();
        WriteUInt32LittleEndian(unknownDimension, 132, 0);
        AssertNotDetectedAs("dds", unknownDimension);

        var emptyArray = (byte[])valid.Clone();
        WriteUInt32LittleEndian(emptyArray, 140, 0);
        AssertNotDetectedAs("dds", emptyArray);
    }

    [Fact]
    public void SeekableMidiEventValidationHonorsReadBudget()
    {
        var bytes = LargeMidi();
        Assert.Equal("High", FileInspector.Detect(bytes)?.Confidence);
        int originalBudget = Settings.DetectionReadBudgetBytes;
        try
        {
            Settings.DetectionReadBudgetBytes = 256;
            using var stream = new MemoryStream(bytes, writable: false) { Position = 5 };

            var result = FileInspector.Detect(stream);

            Assert.Equal("mid", result?.Extension);
            Assert.Equal("Medium", result?.Confidence);
            Assert.Contains("validation-budget-exceeded", result?.Reason);
            Assert.Equal(5, stream.Position);
        }
        finally
        {
            Settings.DetectionReadBudgetBytes = originalBudget;
        }
    }

    private static void AssertNotDetectedAs(string extension, byte[] bytes)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }

    private static byte[] Woff2(params (byte Flags, byte OriginalLength, byte? TransformedLength)[] tables)
    {
        int directoryLength = tables.Sum(table => 2 + (table.TransformedLength.HasValue ? 1 : 0));
        var bytes = new byte[48 + directoryLength + 1];
        Encoding.ASCII.GetBytes("wOF2OTTO").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 8, (uint)bytes.Length);
        WriteUInt16BigEndian(bytes, 12, checked((ushort)tables.Length));
        WriteUInt32BigEndian(bytes, 16, checked((uint)(12 + tables.Length * 16)));
        WriteUInt32BigEndian(bytes, 20, 1);
        int cursor = 48;
        foreach (var table in tables)
        {
            bytes[cursor++] = table.Flags;
            bytes[cursor++] = table.OriginalLength;
            if (table.TransformedLength.HasValue) bytes[cursor++] = table.TransformedLength.Value;
        }
        bytes[cursor] = 0;
        return bytes;
    }

    private static byte[] Rpm()
    {
        var bytes = new byte[174];
        new byte[] { 0xED, 0xAB, 0xEE, 0xDB, 3, 0 }.CopyTo(bytes, 0);
        WriteUInt16BigEndian(bytes, 78, 5);
        new byte[] { 0x8E, 0xAD, 0xE8, 1 }.CopyTo(bytes, 96);
        WriteUInt32BigEndian(bytes, 104, 1);
        WriteUInt32BigEndian(bytes, 108, 1);
        WriteUInt32BigEndian(bytes, 112, 1000);
        WriteUInt32BigEndian(bytes, 116, 7);
        WriteUInt32BigEndian(bytes, 124, 1);
        new byte[] { 0x8E, 0xAD, 0xE8, 1 }.CopyTo(bytes, 136);
        WriteUInt32BigEndian(bytes, 144, 1);
        WriteUInt32BigEndian(bytes, 148, 1);
        WriteUInt32BigEndian(bytes, 152, 1000);
        WriteUInt32BigEndian(bytes, 156, 7);
        WriteUInt32BigEndian(bytes, 164, 1);
        new byte[] { 0x1F, 0x8B, 8, 0, 0 }.CopyTo(bytes, 169);
        return bytes;
    }

    private static byte[] NetCdfWithLargeGlobalAttribute()
    {
        const int valueLength = 5000;
        var bytes = new byte[48 + valueLength];
        Encoding.ASCII.GetBytes("CDF").CopyTo(bytes, 0);
        bytes[3] = 1;
        WriteUInt32BigEndian(bytes, 16, 12);
        WriteUInt32BigEndian(bytes, 20, 1);
        WriteUInt32BigEndian(bytes, 24, 1);
        bytes[28] = (byte)'a';
        WriteUInt32BigEndian(bytes, 32, 1);
        WriteUInt32BigEndian(bytes, 36, valueLength);
        WriteUInt32BigEndian(bytes, 40 + valueLength, 0);
        WriteUInt32BigEndian(bytes, 44 + valueLength, 0);
        return bytes;
    }

    private static byte[] NetCdfWithLongDimensionName()
    {
        const int nameLength = 2048;
        var bytes = new byte[40 + nameLength];
        Encoding.ASCII.GetBytes("CDF").CopyTo(bytes, 0);
        bytes[3] = 1;
        WriteUInt32BigEndian(bytes, 8, 10);
        WriteUInt32BigEndian(bytes, 12, 1);
        WriteUInt32BigEndian(bytes, 16, nameLength);
        for (int i = 0; i < nameLength; i++) bytes[20 + i] = (byte)'a';
        WriteUInt32BigEndian(bytes, 20 + nameLength, 1);
        return bytes;
    }

    private static byte[] DdsDx10()
    {
        var bytes = new byte[152];
        Encoding.ASCII.GetBytes("DDS ").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 124);
        WriteUInt32LittleEndian(bytes, 8, 0x1007);
        WriteUInt32LittleEndian(bytes, 12, 1);
        WriteUInt32LittleEndian(bytes, 16, 1);
        WriteUInt32LittleEndian(bytes, 76, 32);
        WriteUInt32LittleEndian(bytes, 80, 4);
        Encoding.ASCII.GetBytes("DX10").CopyTo(bytes, 84);
        WriteUInt32LittleEndian(bytes, 108, 0x1000);
        WriteUInt32LittleEndian(bytes, 128, 28);
        WriteUInt32LittleEndian(bytes, 132, 3);
        WriteUInt32LittleEndian(bytes, 140, 1);
        return bytes;
    }

    private static byte[] LargeMidi()
    {
        const int events = 1000;
        var bytes = new byte[22 + events * 4 + 4];
        Encoding.ASCII.GetBytes("MThd").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 6);
        WriteUInt16BigEndian(bytes, 8, 0);
        WriteUInt16BigEndian(bytes, 10, 1);
        WriteUInt16BigEndian(bytes, 12, 96);
        Encoding.ASCII.GetBytes("MTrk").CopyTo(bytes, 14);
        WriteUInt32BigEndian(bytes, 18, checked((uint)(events * 4 + 4)));
        int cursor = 22;
        for (int i = 0; i < events; i++)
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

    private static void WriteUInt32LittleEndian(byte[] bytes, int offset, uint value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
        bytes[offset + 2] = (byte)(value >> 16);
        bytes[offset + 3] = (byte)(value >> 24);
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
        protected override void Dispose(bool disposing) { if (disposing) _inner.Dispose(); base.Dispose(disposing); }
    }
}
