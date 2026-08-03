using System.Diagnostics;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class VhdBatPerformanceRegressionTests
{
    [Fact]
    public void LargeAllocatedBatIsValidatedWithoutQuadraticRangeComparisons()
    {
        using var stream = new SparseDynamicVhdStream(entries: 40_000);
        var stopwatch = Stopwatch.StartNew();

        ContentTypeDetectionResult? result = FileInspector.Detect(stream);

        stopwatch.Stop();
        Assert.Equal("vhd", result?.Extension);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(5),
            $"Large VHD BAT validation took {stopwatch.Elapsed}.");
    }

    [Fact]
    public void SortedBatValidationStillRejectsOverlappingAllocatedBlocks()
    {
        using var stream = new SparseDynamicVhdStream(entries: 2, overlapLastEntry: true);

        Assert.NotEqual("vhd", FileInspector.Detect(stream)?.Extension);
    }

    private sealed class SparseDynamicVhdStream : Stream
    {
        private const uint BlockSize = 512 * 1024;
        private const uint BlockSectors = BlockSize / 512 + 1;
        private readonly (long Offset, byte[] Bytes)[] _regions;
        private readonly long _length;
        private long _position;

        internal SparseDynamicVhdStream(uint entries, bool overlapLastEntry = false)
        {
            int tableLength = checked((int)(((ulong)entries * 4 + 511) & ~511UL));
            const long tableOffset = 1536;
            ulong firstSector = checked((ulong)(tableOffset + tableLength) / 512);
            var table = new byte[tableLength];
            for (uint index = 0; index < entries; index++)
                TestHelpers.WriteUInt32BigEndian(table, checked((int)index * 4),
                    checked((uint)(firstSector + (overlapLastEntry && index == entries - 1 ? 0 : index) * BlockSectors)));

            ulong dataEnd = checked((firstSector + entries * (ulong)BlockSectors) * 512);
            _length = checked((long)dataEnd + 512);
            ulong currentSize = checked(entries * (ulong)BlockSize);
            byte[] footer = CreateFooter(currentSize);
            byte[] header = CreateDynamicHeader(entries, tableOffset);
            _regions = new[]
            {
                (0L, footer),
                (512L, header),
                (tableOffset, table),
                (_length - 512, footer)
            };
        }

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => _length;
        public override long Position { get => _position; set => _position = value; }
        public override void Flush() { }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_position < 0 || _position > _length) throw new IOException();
            int read = (int)Math.Min(count, _length - _position);
            Array.Clear(buffer, offset, read);
            long readEnd = _position + read;
            foreach ((long regionOffset, byte[] bytes) in _regions)
            {
                long regionEnd = regionOffset + bytes.Length;
                long overlapStart = Math.Max(_position, regionOffset);
                long overlapEnd = Math.Min(readEnd, regionEnd);
                if (overlapStart >= overlapEnd) continue;
                Array.Copy(bytes, checked((int)(overlapStart - regionOffset)), buffer,
                    offset + checked((int)(overlapStart - _position)), checked((int)(overlapEnd - overlapStart)));
            }
            _position += read;
            return read;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            long position = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => checked(_position + offset),
                SeekOrigin.End => checked(_length + offset),
                _ => throw new ArgumentOutOfRangeException(nameof(origin))
            };
            if (position < 0) throw new IOException();
            _position = position;
            return position;
        }

        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        private static byte[] CreateDynamicHeader(uint entries, long tableOffset)
        {
            var header = new byte[1024];
            Encoding.ASCII.GetBytes("cxsparse").CopyTo(header, 0);
            TestHelpers.WriteUInt64BigEndian(header, 8, ulong.MaxValue);
            TestHelpers.WriteUInt64BigEndian(header, 16, checked((ulong)tableOffset));
            TestHelpers.WriteUInt32BigEndian(header, 24, 0x00010000);
            TestHelpers.WriteUInt32BigEndian(header, 28, entries);
            TestHelpers.WriteUInt32BigEndian(header, 32, BlockSize);
            FinalizeChecksum(header, 36);
            return header;
        }

        private static byte[] CreateFooter(ulong currentSize)
        {
            var footer = new byte[512];
            Encoding.ASCII.GetBytes("conectix").CopyTo(footer, 0);
            TestHelpers.WriteUInt32BigEndian(footer, 8, 2);
            TestHelpers.WriteUInt32BigEndian(footer, 12, 0x00010000);
            TestHelpers.WriteUInt64BigEndian(footer, 16, 512);
            TestHelpers.WriteUInt64BigEndian(footer, 40, currentSize);
            TestHelpers.WriteUInt64BigEndian(footer, 48, currentSize);
            TestHelpers.WriteUInt32BigEndian(footer, 56, 0x00010101);
            TestHelpers.WriteUInt32BigEndian(footer, 60, 3);
            footer[68] = 1;
            FinalizeChecksum(footer, 64);
            return footer;
        }

        private static void FinalizeChecksum(byte[] bytes, int checksumOffset)
        {
            uint sum = 0;
            for (int index = 0; index < bytes.Length; index++)
                if (index < checksumOffset || index >= checksumOffset + 4) sum += bytes[index];
            TestHelpers.WriteUInt32BigEndian(bytes, checksumOffset, ~sum);
        }
    }
}
