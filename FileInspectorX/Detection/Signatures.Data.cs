namespace FileInspectorX;

/// <summary>
/// Scientific and structured-data container detection.
/// </summary>
internal static partial class Signatures {
    private static readonly byte[] Hdf5Signature = { 0x89, (byte)'H', (byte)'D', (byte)'F', 0x0D, 0x0A, 0x1A, 0x0A };

    private readonly struct NetCdfVariableRange
    {
        internal NetCdfVariableRange(ulong begin, ulong size, ulong dataSize, bool record)
        {
            Begin = begin;
            Size = size;
            DataSize = dataSize;
            Record = record;
        }

        internal ulong Begin { get; }
        internal ulong Size { get; }
        internal ulong DataSize { get; }
        internal bool Record { get; }
    }

    internal static bool TryMatchHdf5(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchHdf5(src, src.Length, out result);

    internal static bool TryMatchHdf5(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result) {
        result = null;
        for (long offset = 0; offset <= src.Length - Hdf5Signature.Length; offset = NextHdf5Offset(offset)) {
            if (MatchesHdf5Signature(src, (int)offset) &&
                TryValidateHdf5Superblock(src.Slice((int)offset), offset, completeLength)) {
                result = Hdf5Result(offset, completeLength.HasValue);
                return true;
            }
            if (offset > int.MaxValue / 2) break;
        }
        return false;
    }

    internal static bool TryMatchHdf5(Stream stream, long minimumOffset, out ContentTypeDetectionResult? result) {
        result = null;
        if (!stream.CanSeek || !stream.CanRead) return false;
        long originalPosition;
        long length;
        try {
            originalPosition = stream.Position;
            length = stream.Length;
        } catch {
            return false;
        }

        // Version 1 with 16-byte offsets needs 148 bytes through the root symbol-table entry.
        var superblock = new byte[160];
        try {
            for (long offset = 0; offset <= length - Hdf5Signature.Length; offset = NextHdf5Offset(offset)) {
                if (offset < minimumOffset) {
                    if (offset > long.MaxValue / 2) break;
                    continue;
                }
                stream.Seek(offset, SeekOrigin.Begin);
                int read = 0;
                int requested = (int)Math.Min(superblock.Length, length - offset);
                while (read < requested) {
                    int current = stream.Read(superblock, read, requested - read);
                    if (current <= 0) break;
                    read += current;
                }
                var candidate = new ReadOnlySpan<byte>(superblock, 0, read);
                if (read >= Hdf5Signature.Length && MatchesHdf5Signature(candidate, 0) &&
                    TryValidateHdf5Superblock(candidate, offset, length)) {
                    result = Hdf5Result(offset);
                    return true;
                }
                if (offset > long.MaxValue / 2) break;
            }
            return false;
        } catch {
            result = null;
            return false;
        } finally {
            try { stream.Seek(originalPosition, SeekOrigin.Begin); } catch { }
        }
    }

    internal static bool TryMatchNetCdf(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchNetCdf(src, src.Length, out result);

    internal static bool TryMatchNetCdf(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 4 || src[0] != (byte)'C' || src[1] != (byte)'D' || src[2] != (byte)'F' ||
            (src[3] != 1 && src[3] != 2 && src[3] != 5))
            return false;

        bool isCdf5 = src[3] == 5;
        int cursor = 4;
        bool rangesFullyValidated = false;
        bool completeHeader = TryReadNetCdfNonNegative(src, ref cursor, isCdf5, out ulong recordCount) &&
            TrySkipNetCdfDimensions(src, ref cursor, isCdf5, out ulong[] dimensionLengths) &&
            TrySkipNetCdfAttributes(src, ref cursor, isCdf5) &&
            TrySkipNetCdfVariables(src, ref cursor, isCdf5, src[3] == 1, dimensionLengths, recordCount,
                completeLength, out rangesFullyValidated);
        if (!completeHeader)
        {
            if (completeLength.HasValue || !TryMatchSampledNetCdf(src, out result)) return false;
            return true;
        }

        bool complete = completeLength.HasValue && rangesFullyValidated;
        result = NetCdfResult(src[3], complete,
            sampledReason: !completeLength.HasValue ? "sampled-length-unknown" : complete ? null : "streaming-record-count");
        return true;
    }

    private static bool TryMatchSampledNetCdf(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        using var sample = new MemoryStream(src.ToArray(), writable: false);
        var reader = new NetCdfStreamReader(sample, sample.Length, sampleMayContinue: true, int.MaxValue);
        if (!reader.TryReadByte(out byte c) || c != (byte)'C' ||
            !reader.TryReadByte(out byte d) || d != (byte)'D' ||
            !reader.TryReadByte(out byte f) || f != (byte)'F' ||
            !reader.TryReadByte(out byte version) || version is not (1 or 2 or 5)) return false;
        bool isCdf5 = version == 5;
        bool parsed = reader.TryReadNonNegative(isCdf5, out ulong recordCount) &&
                      reader.TrySkipDimensions(isCdf5, out ulong[] dimensionLengths) &&
                      reader.TrySkipAttributes(isCdf5) &&
                      reader.TrySkipVariables(isCdf5, version == 1, dimensionLengths, recordCount, out _);
        if (!parsed && (!reader.Incomplete || reader.StructuralEvidence < 2)) return false;
        result = NetCdfResult(version, complete: false, sampledReason: "sampled-header");
        return true;
    }

    internal static bool TryMatchNetCdf(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try
        {
            stream.Seek(0, SeekOrigin.Begin);
            var reader = new NetCdfStreamReader(stream, stream.Length, sampleMayContinue: false,
                Math.Max(256, Settings.DetectionReadBudgetBytes));
            if (!reader.TryReadByte(out byte c) || c != (byte)'C' ||
                !reader.TryReadByte(out byte d) || d != (byte)'D' ||
                !reader.TryReadByte(out byte f) || f != (byte)'F' ||
                !reader.TryReadByte(out byte version) || version is not (1 or 2 or 5)) return false;
            bool isCdf5 = version == 5;
            bool rangesFullyValidated = false;
            if (!reader.TryReadNonNegative(isCdf5, out ulong recordCount) ||
                !reader.TrySkipDimensions(isCdf5, out ulong[] dimensionLengths) ||
                !reader.TrySkipAttributes(isCdf5) ||
                !reader.TrySkipVariables(isCdf5, version == 1, dimensionLengths, recordCount, out rangesFullyValidated))
            {
                if (!reader.BudgetExceeded || reader.StructuralEvidence < 1) return false;
                result = NetCdfResult(version, complete: false, sampledReason: "validation-budget-exceeded");
                return true;
            }
            result = NetCdfResult(version, complete: rangesFullyValidated,
                sampledReason: rangesFullyValidated ? null : "streaming-record-count");
            return true;
        }
        catch
        {
            result = null;
            return false;
        }
        finally
        {
            try { stream.Seek(originalPosition, SeekOrigin.Begin); } catch { }
        }
    }

    private sealed class NetCdfStreamReader {
        private readonly Stream _stream;
        private readonly long _length;
        private readonly bool _sampleMayContinue;
        private long _remainingBudget;

        internal NetCdfStreamReader(Stream stream, long length, bool sampleMayContinue, long readBudget) {
            _stream = stream;
            _length = length;
            _sampleMayContinue = sampleMayContinue;
            _remainingBudget = readBudget;
        }

        internal bool Incomplete { get; private set; }
        internal bool BudgetExceeded { get; private set; }
        internal int StructuralEvidence { get; private set; }

        internal bool TryReadByte(out byte value) {
            value = 0;
            if (_remainingBudget <= 0) { BudgetExceeded = true; return false; }
            if (_stream.Position >= _length) { Incomplete = _sampleMayContinue; return false; }
            int current = _stream.ReadByte();
            if (current < 0) return false;
            _remainingBudget--;
            value = (byte)current;
            return true;
        }

        private bool TryReadUInt32(out uint value) {
            value = 0;
            for (int i = 0; i < 4; i++) {
                if (!TryReadByte(out byte current)) return false;
                value = (value << 8) | current;
            }
            return true;
        }

        private bool TryReadUInt64(out ulong value) {
            value = 0;
            for (int i = 0; i < 8; i++) {
                if (!TryReadByte(out byte current)) return false;
                value = (value << 8) | current;
            }
            return true;
        }

        internal bool TryReadNonNegative(bool isCdf5, out ulong value) {
            value = 0;
            if (isCdf5) {
                if (!TryReadUInt64(out value)) return false;
                return value <= long.MaxValue || value == ulong.MaxValue;
            }
            if (!TryReadUInt32(out uint narrow)) return false;
            value = narrow;
            return narrow <= int.MaxValue || narrow == uint.MaxValue;
        }

        private bool TryReadListHeader(bool isCdf5, uint expectedTag, out ulong count) {
            count = 0;
            if (!TryReadUInt32(out uint tag) || !TryReadNonNegative(isCdf5, out count)) return false;
            if (tag == 0) return count == 0;
            if (tag != expectedTag || count is not (> 0 and <= 1000000)) return false;
            StructuralEvidence++;
            return true;
        }

        private bool TrySkipName(bool isCdf5) {
            if (!TryReadNonNegative(isCdf5, out ulong length) || length == 0 ||
                !TryScanName(length, out byte last)) return false;
            if (last == (byte)' ') return false;
            int padding = (int)((4 - (length & 3)) & 3);
            for (int i = 0; i < padding; i++)
                if (!TryReadByte(out byte current) || current != 0) return false;
            return true;
        }

        private bool TryScanName(ulong length, out byte last)
        {
            last = 0;
            long available = Math.Max(0, _length - _stream.Position);
            ulong scanLength = Math.Min(length, (ulong)available);
            if ((ulong)Math.Max(0, _remainingBudget) < scanLength) scanLength = (ulong)Math.Max(0, _remainingBudget);
            var buffer = new byte[4096];
            ulong scanned = 0;
            while (scanned < scanLength)
            {
                int wanted = (int)Math.Min((ulong)buffer.Length, scanLength - scanned);
                int read = _stream.Read(buffer, 0, wanted);
                if (read <= 0) { Incomplete = _sampleMayContinue; return false; }
                _remainingBudget -= read;
                for (int i = 0; i < read; i++)
                {
                    byte current = buffer[i];
                    if (current < 0x20 || current == (byte)'/' || current == 0x7F) return false;
                    last = current;
                }
                scanned += (uint)read;
            }
            if (scanned < length)
            {
                if (_remainingBudget <= 0) BudgetExceeded = true;
                else Incomplete = _sampleMayContinue;
                return false;
            }
            StructuralEvidence++;
            return true;
        }

        internal bool TrySkipDimensions(bool isCdf5, out ulong[] lengths) {
            lengths = Array.Empty<ulong>();
            if (!TryReadListHeader(isCdf5, 10, out ulong count) || count > int.MaxValue) return false;
            lengths = new ulong[(int)count];
            bool unlimited = false;
            for (int i = 0; i < lengths.Length; i++)
            {
                if (!TrySkipName(isCdf5) || !TryReadNonNegative(isCdf5, out ulong dimensionLength) ||
                    dimensionLength == (isCdf5 ? ulong.MaxValue : uint.MaxValue) || (dimensionLength == 0 && unlimited)) return false;
                unlimited |= dimensionLength == 0;
                lengths[i] = dimensionLength;
            }
            return true;
        }

        internal bool TrySkipAttributes(bool isCdf5) {
            if (!TryReadListHeader(isCdf5, 12, out ulong count)) return false;
            for (ulong i = 0; i < count; i++) {
                if (!TrySkipName(isCdf5) || !TryReadUInt32(out uint type) ||
                    !TryGetNetCdfTypeSize(type, isCdf5, out int typeSize) ||
                    !TryReadNonNegative(isCdf5, out ulong valueCount) || valueCount > ulong.MaxValue / (uint)typeSize)
                    return false;
                ulong byteCount = valueCount * (uint)typeSize;
                ulong padded = (byteCount + 3) & ~3UL;
                if (padded < byteCount) return false;
                if (padded > (ulong)Math.Max(0, _length - _stream.Position))
                {
                    Incomplete = _sampleMayContinue;
                    return false;
                }
                if (byteCount > long.MaxValue || _stream.Seek((long)byteCount, SeekOrigin.Current) > _length)
                {
                    Incomplete = _sampleMayContinue;
                    return false;
                }
                for (ulong padding = byteCount; padding < padded; padding++)
                    if (!TryReadByte(out byte current) || current != 0) return false;
            }
            return true;
        }

        internal bool TrySkipVariables(bool isCdf5, bool cdf1, ulong[] dimensionLengths, ulong recordCount,
            out bool rangesFullyValidated) {
            rangesFullyValidated = false;
            if (!TryReadListHeader(isCdf5, 11, out ulong count)) return false;
            var ranges = new System.Collections.Generic.List<NetCdfVariableRange>();
            for (ulong i = 0; i < count; i++) {
                if (!TrySkipName(isCdf5) || !TryReadNonNegative(isCdf5, out ulong dimensions) || dimensions > 4095) return false;
                var dimensionIds = new ulong[(int)dimensions];
                for (int dimension = 0; dimension < dimensionIds.Length; dimension++)
                    if (!TryReadNonNegative(isCdf5, out dimensionIds[dimension]) || dimensionIds[dimension] >= (ulong)dimensionLengths.Length) return false;
                if (!TrySkipAttributes(isCdf5) || !TryReadUInt32(out uint type) ||
                    !TryGetNetCdfTypeSize(type, isCdf5, out int typeSize) || !TryReadNonNegative(isCdf5, out ulong declaredSize)) return false;
                ulong begin;
                if (cdf1)
                {
                    if (!TryReadUInt32(out uint narrowBegin)) return false;
                    begin = narrowBegin;
                }
                else if (!TryReadUInt64(out begin)) return false;
                if (!TryCreateNetCdfVariableRange(dimensionLengths, dimensionIds, typeSize, declaredSize, begin, out var range)) return false;
                ranges.Add(range);
            }
            return TryValidateNetCdfVariableRanges(ranges, (ulong)_stream.Position, _sampleMayContinue ? null : _length,
                recordCount, isCdf5, out rangesFullyValidated);
        }
    }

    private static ContentTypeDetectionResult NetCdfResult(byte version, bool complete, string? sampledReason)
        => new() {
            Extension = "nc",
            MimeType = "application/x-netcdf",
            Confidence = complete ? "High" : "Medium",
            Reason = (version == 1 ? "netcdf:classic" : version == 2 ? "netcdf:64-bit-offset" : "netcdf:64-bit-data") +
                     (sampledReason == null ? string.Empty : ";" + sampledReason)
        };

    private static bool TrySkipNetCdfDimensions(ReadOnlySpan<byte> src, ref int cursor, bool isCdf5, out ulong[] lengths)
    {
        lengths = Array.Empty<ulong>();
        if (!TryReadNetCdfListHeader(src, ref cursor, isCdf5, 10, out ulong count) || count > int.MaxValue) return false;
        lengths = new ulong[(int)count];
        bool unlimited = false;
        for (int i = 0; i < lengths.Length; i++)
        {
            if (!TrySkipNetCdfName(src, ref cursor, isCdf5) ||
                !TryReadNetCdfNonNegative(src, ref cursor, isCdf5, out ulong dimensionLength) ||
                dimensionLength == (isCdf5 ? ulong.MaxValue : uint.MaxValue) || (dimensionLength == 0 && unlimited)) return false;
            unlimited |= dimensionLength == 0;
            lengths[i] = dimensionLength;
        }
        return true;
    }

    private static bool TrySkipNetCdfAttributes(ReadOnlySpan<byte> src, ref int cursor, bool isCdf5)
    {
        if (!TryReadNetCdfListHeader(src, ref cursor, isCdf5, 12, out ulong count)) return false;
        for (ulong i = 0; i < count; i++)
        {
            if (!TrySkipNetCdfName(src, ref cursor, isCdf5) || cursor + 4 > src.Length) return false;
            uint type = ReadUInt32BigEndian(src, cursor);
            cursor += 4;
            if (!TryGetNetCdfTypeSize(type, isCdf5, out int typeSize) ||
                !TryReadNetCdfNonNegative(src, ref cursor, isCdf5, out ulong valueCount) ||
                valueCount > (ulong)int.MaxValue / (uint)typeSize) return false;
            ulong byteCount = valueCount * (uint)typeSize;
            ulong padded = (byteCount + 3) & ~3UL;
            if (padded > (ulong)(src.Length - cursor)) return false;
            for (ulong padding = byteCount; padding < padded; padding++)
                if (src[cursor + (int)padding] != 0) return false;
            cursor += (int)padded;
        }
        return true;
    }

    private static bool TrySkipNetCdfVariables(ReadOnlySpan<byte> src, ref int cursor, bool isCdf5, bool cdf1,
        ulong[] dimensionLengths, ulong recordCount, long? completeLength, out bool rangesFullyValidated)
    {
        rangesFullyValidated = false;
        if (!TryReadNetCdfListHeader(src, ref cursor, isCdf5, 11, out ulong count)) return false;
        var ranges = new System.Collections.Generic.List<NetCdfVariableRange>();
        for (ulong i = 0; i < count; i++)
        {
            if (!TrySkipNetCdfName(src, ref cursor, isCdf5) ||
                !TryReadNetCdfNonNegative(src, ref cursor, isCdf5, out ulong dimensions) || dimensions > 4095) return false;
            var dimensionIds = new ulong[(int)dimensions];
            for (int dimension = 0; dimension < dimensionIds.Length; dimension++)
                if (!TryReadNetCdfNonNegative(src, ref cursor, isCdf5, out dimensionIds[dimension]) ||
                    dimensionIds[dimension] >= (ulong)dimensionLengths.Length) return false;
            if (!TrySkipNetCdfAttributes(src, ref cursor, isCdf5) || cursor + 4 > src.Length) return false;
            uint type = ReadUInt32BigEndian(src, cursor);
            cursor += 4;
            if (!TryGetNetCdfTypeSize(type, isCdf5, out int typeSize) ||
                !TryReadNetCdfNonNegative(src, ref cursor, isCdf5, out ulong declaredSize) ||
                !TryReadNetCdfOffset(src, ref cursor, cdf1, out ulong begin) ||
                !TryCreateNetCdfVariableRange(dimensionLengths, dimensionIds, typeSize, declaredSize, begin, out var range)) return false;
            ranges.Add(range);
        }
        return TryValidateNetCdfVariableRanges(ranges, (ulong)cursor, completeLength, recordCount, isCdf5,
            out rangesFullyValidated);
    }

    private static bool TryCreateNetCdfVariableRange(ulong[] dimensionLengths, ulong[] dimensionIds, int typeSize,
        ulong declaredSize, ulong begin, out NetCdfVariableRange range)
    {
        range = default;
        bool record = dimensionIds.Length > 0 && dimensionLengths[(int)dimensionIds[0]] == 0;
        ulong elements = 1;
        for (int index = 0; index < dimensionIds.Length; index++)
        {
            ulong dimensionLength = dimensionLengths[(int)dimensionIds[index]];
            if (dimensionLength == 0)
            {
                if (!record || index != 0) return false;
                continue;
            }
            if (elements > ulong.MaxValue / dimensionLength) return false;
            elements *= dimensionLength;
        }
        if (elements > ulong.MaxValue / (uint)typeSize) return false;
        ulong rawSize = elements * (uint)typeSize;
        if (rawSize > ulong.MaxValue - 3) return false;
        ulong expectedSize = (rawSize + 3) & ~3UL;
        if (declaredSize != expectedSize || begin > long.MaxValue) return false;
        range = new NetCdfVariableRange(begin, declaredSize, rawSize, record);
        return true;
    }

    private static bool TryValidateNetCdfVariableRanges(System.Collections.Generic.List<NetCdfVariableRange> ranges,
        ulong headerEnd, long? completeLength, ulong recordCount, bool isCdf5, out bool fullyValidated)
    {
        fullyValidated = false;
        if (!completeLength.HasValue) return true;
        if (completeLength.Value < 0) return false;
        ulong fileLength = (ulong)completeLength.Value;
        var records = new System.Collections.Generic.List<NetCdfVariableRange>();
        foreach (var range in ranges)
        {
            if (range.Begin < headerEnd || range.Begin > fileLength) return false;
            if (range.Record) records.Add(range);
            else if (range.Size > fileLength - range.Begin) return false;
        }
        if (records.Count == 0)
        {
            fullyValidated = true;
            return true;
        }

        records.Sort((left, right) => left.Begin.CompareTo(right.Begin));
        ulong recordStride = 0;
        if (records.Count == 1)
        {
            // Classic netCDF omits inter-record padding when there is exactly one record variable.
            recordStride = records[0].DataSize;
        }
        else
        {
            foreach (var range in records)
            {
                if (recordStride > ulong.MaxValue - range.Size) return false;
                recordStride += range.Size;
            }
        }
        ulong recordBase = records[0].Begin;
        ulong expectedBegin = recordBase;
        foreach (var range in records)
        {
            if (range.Begin != expectedBegin || expectedBegin > ulong.MaxValue - range.Size) return false;
            expectedBegin += range.Size;
        }
        ulong streamingSentinel = isCdf5 ? ulong.MaxValue : uint.MaxValue;
        if (recordCount == streamingSentinel)
        {
            foreach (var range in records)
                if (range.Begin < fileLength && range.Size > fileLength - range.Begin) return false;
            return true;
        }
        if (recordCount == 0)
        {
            fullyValidated = true;
            return true;
        }
        ulong recordAdvance = recordCount - 1;
        if (recordStride != 0 && recordAdvance > ulong.MaxValue / recordStride) return false;
        ulong lastRecordOffset = recordAdvance * recordStride;
        foreach (var range in records)
        {
            if (range.Begin > ulong.MaxValue - lastRecordOffset) return false;
            ulong lastBegin = range.Begin + lastRecordOffset;
            if (lastBegin > fileLength || range.DataSize > fileLength - lastBegin) return false;
        }
        fullyValidated = true;
        return true;
    }

    private static bool TryReadNetCdfListHeader(ReadOnlySpan<byte> src, ref int cursor, bool isCdf5, uint expectedTag, out ulong count)
    {
        count = 0;
        if (cursor + 4 > src.Length) return false;
        uint tag = ReadUInt32BigEndian(src, cursor);
        cursor += 4;
        if (!TryReadNetCdfNonNegative(src, ref cursor, isCdf5, out count)) return false;
        if (tag == 0) return count == 0;
        return tag == expectedTag && count is > 0 and <= 1000000;
    }

    private static bool TrySkipNetCdfName(ReadOnlySpan<byte> src, ref int cursor, bool isCdf5)
    {
        if (!TryReadNetCdfNonNegative(src, ref cursor, isCdf5, out ulong length) ||
            length == 0 || length > (ulong)(src.Length - cursor)) return false;
        ulong padded = (length + 3) & ~3UL;
        if (padded > (ulong)(src.Length - cursor) || src[cursor] <= 0x20 || src[cursor] == (byte)'/' || src[cursor] == 0x7F) return false;
        for (ulong character = 0; character < length; character++)
            if (src[cursor + (int)character] < 0x20 || src[cursor + (int)character] == (byte)'/' ||
                src[cursor + (int)character] == 0x7F) return false;
        if (src[cursor + (int)length - 1] == (byte)' ') return false;
        for (ulong padding = length; padding < padded; padding++)
            if (src[cursor + (int)padding] != 0) return false;
        cursor += (int)padded;
        return true;
    }

    private static bool TryReadNetCdfNonNegative(ReadOnlySpan<byte> src, ref int cursor, bool isCdf5, out ulong value)
    {
        value = 0;
        int size = isCdf5 ? 8 : 4;
        if (cursor + size > src.Length) return false;
        value = isCdf5 ? ReadUInt64(src, cursor, littleEndian: false) : ReadUInt32BigEndian(src, cursor);
        cursor += size;
        return isCdf5 ? value <= long.MaxValue || value == ulong.MaxValue : value <= int.MaxValue || value == uint.MaxValue;
    }

    private static bool TryReadNetCdfOffset(ReadOnlySpan<byte> src, ref int cursor, bool cdf1, out ulong value)
    {
        value = 0;
        int size = cdf1 ? 4 : 8;
        if (cursor + size > src.Length) return false;
        value = cdf1 ? ReadUInt32BigEndian(src, cursor) : ReadUInt64(src, cursor, littleEndian: false);
        cursor += size;
        return value <= (ulong)(cdf1 ? int.MaxValue : long.MaxValue);
    }

    private static bool TryGetNetCdfTypeSize(uint type, bool isCdf5, out int size)
    {
        size = type switch { 1 or 2 or 7 => 1, 3 or 8 => 2, 4 or 5 or 9 => 4, 6 or 10 or 11 => 8, _ => 0 };
        return size != 0 && (isCdf5 || type <= 6);
    }

    private static long NextHdf5Offset(long offset) => offset == 0 ? 512 : offset * 2;

    private static bool MatchesHdf5Signature(ReadOnlySpan<byte> src, int offset) {
        for (int i = 0; i < Hdf5Signature.Length; i++)
            if (src[offset + i] != Hdf5Signature[i]) return false;
        return true;
    }

    private static bool TryValidateHdf5Superblock(ReadOnlySpan<byte> src, long signatureOffset, long? fileLength) {
        if (src.Length < 12) return false;
        byte version = src[8];
        if (version is 0 or 1) {
            if (src.Length < 24 || src[9] != 0 || src[10] != 0 || src[11] != 0 || src[12] != 0 || src[15] != 0) return false;
            byte offsetSize = src[13];
            byte lengthSize = src[14];
            if (!IsValidHdfIntegerSize(offsetSize) || !IsValidHdfIntegerSize(lengthSize) ||
                ReadUInt16LittleEndian(src, 16) == 0 || ReadUInt16LittleEndian(src, 18) == 0 ||
                (ReadUInt32LittleEndian(src, 20) & ~3u) != 0) return false;
            int cursor = 24;
            if (version == 1) {
                if (src.Length < 28 || ReadUInt16LittleEndian(src, 24) == 0 || src[26] != 0 || src[27] != 0) return false;
                cursor = 28;
            }
            if (!TryReadHdfAddress(src, ref cursor, offsetSize, out ulong baseAddress, out bool baseUndefined) ||
                !TryReadHdfAddress(src, ref cursor, offsetSize, out ulong freeAddress, out bool freeUndefined) ||
                !TryReadHdfAddress(src, ref cursor, offsetSize, out ulong eofAddress, out bool eofUndefined) ||
                !TryReadHdfAddress(src, ref cursor, offsetSize, out ulong driverAddress, out bool driverUndefined)) return false;
            if (baseUndefined || eofUndefined || baseAddress != (ulong)signatureOffset ||
                !TryAddHdfRelativeAddress(baseAddress, eofAddress, out ulong absoluteEof) ||
                absoluteEof <= (ulong)(signatureOffset + cursor) ||
                (fileLength.HasValue && absoluteEof > (ulong)fileLength.Value) ||
                (!freeUndefined && (!TryAddHdfRelativeAddress(baseAddress, freeAddress, out ulong absoluteFree) || absoluteFree >= absoluteEof)) ||
                (!driverUndefined && (!TryAddHdfRelativeAddress(baseAddress, driverAddress, out ulong absoluteDriver) || absoluteDriver >= absoluteEof))) return false;
            if (!TryReadHdfAddress(src, ref cursor, offsetSize, out _, out bool linkNameUndefined) ||
                !TryReadHdfAddress(src, ref cursor, offsetSize, out ulong objectHeaderAddress, out bool objectHeaderUndefined) ||
                cursor + 24 > src.Length || linkNameUndefined || objectHeaderUndefined ||
                !TryAddHdfRelativeAddress(baseAddress, objectHeaderAddress, out ulong absoluteObjectHeader) ||
                absoluteObjectHeader < (ulong)(signatureOffset + cursor + 24) || absoluteObjectHeader >= absoluteEof) return false;
            uint cacheType = ReadUInt32LittleEndian(src, cursor);
            if (cacheType > 1 || ReadUInt32LittleEndian(src, cursor + 4) != 0) return false;
            return true;
        }

        if (version is not (2 or 3)) return false;
        byte modernOffsetSize = src[9];
        byte modernLengthSize = src[10];
        byte allowedFlags = version == 3 ? (byte)0x07 : (byte)0x03;
        if (!IsValidHdfIntegerSize(modernOffsetSize) || !IsValidHdfIntegerSize(modernLengthSize) ||
            (src[11] & ~allowedFlags) != 0) return false;
        int modernCursor = 12;
        if (!TryReadHdfAddress(src, ref modernCursor, modernOffsetSize, out ulong modernBase, out bool modernBaseUndefined) ||
            !TryReadHdfAddress(src, ref modernCursor, modernOffsetSize, out ulong extensionAddress, out bool extensionUndefined) ||
            !TryReadHdfAddress(src, ref modernCursor, modernOffsetSize, out ulong modernEof, out bool modernEofUndefined) ||
            !TryReadHdfAddress(src, ref modernCursor, modernOffsetSize, out ulong rootAddress, out bool rootUndefined) ||
            modernCursor + 4 > src.Length) return false;
        uint expectedChecksum = ReadUInt32LittleEndian(src, modernCursor);
        if (expectedChecksum != ComputeHdf5SuperblockChecksum(src.Slice(0, modernCursor)) ||
            modernBaseUndefined || modernEofUndefined || rootUndefined || modernBase != (ulong)signatureOffset ||
            !TryAddHdfRelativeAddress(modernBase, modernEof, out ulong absoluteModernEof) ||
            absoluteModernEof <= (ulong)(signatureOffset + modernCursor + 4) ||
            (fileLength.HasValue && absoluteModernEof > (ulong)fileLength.Value) ||
            !TryAddHdfRelativeAddress(modernBase, rootAddress, out ulong absoluteRoot) ||
            absoluteRoot < (ulong)(signatureOffset + modernCursor + 4) || absoluteRoot >= absoluteModernEof ||
            (!extensionUndefined && (!TryAddHdfRelativeAddress(modernBase, extensionAddress, out ulong absoluteExtension) ||
                                     absoluteExtension < (ulong)(signatureOffset + modernCursor + 4) || absoluteExtension >= absoluteModernEof))) return false;
        return true;
    }

    private static bool TryAddHdfRelativeAddress(ulong baseAddress, ulong relativeAddress, out ulong absoluteAddress) {
        if (ulong.MaxValue - baseAddress < relativeAddress) {
            absoluteAddress = 0;
            return false;
        }
        absoluteAddress = baseAddress + relativeAddress;
        return true;
    }

    // HDF5 superblock versions 2 and 3 use Bob Jenkins' lookup3/hashlittle checksum.
    private static uint ComputeHdf5SuperblockChecksum(ReadOnlySpan<byte> src) {
        unchecked {
            uint a = 0xDEADBEEF + (uint)src.Length;
            uint b = a;
            uint c = a;
            int cursor = 0;
            int remaining = src.Length;
            while (remaining > 12) {
                a += ReadUInt32LittleEndian(src, cursor);
                b += ReadUInt32LittleEndian(src, cursor + 4);
                c += ReadUInt32LittleEndian(src, cursor + 8);
                MixHdf5Checksum(ref a, ref b, ref c);
                cursor += 12;
                remaining -= 12;
            }

            switch (remaining) {
                case 12: c += (uint)src[cursor + 11] << 24; goto case 11;
                case 11: c += (uint)src[cursor + 10] << 16; goto case 10;
                case 10: c += (uint)src[cursor + 9] << 8; goto case 9;
                case 9: c += src[cursor + 8]; goto case 8;
                case 8: b += (uint)src[cursor + 7] << 24; goto case 7;
                case 7: b += (uint)src[cursor + 6] << 16; goto case 6;
                case 6: b += (uint)src[cursor + 5] << 8; goto case 5;
                case 5: b += src[cursor + 4]; goto case 4;
                case 4: a += (uint)src[cursor + 3] << 24; goto case 3;
                case 3: a += (uint)src[cursor + 2] << 16; goto case 2;
                case 2: a += (uint)src[cursor + 1] << 8; goto case 1;
                case 1: a += src[cursor]; break;
                case 0: return c;
            }

            FinalizeHdf5Checksum(ref a, ref b, ref c);
            return c;
        }
    }

    private static void MixHdf5Checksum(ref uint a, ref uint b, ref uint c) {
        unchecked {
            a -= c; a ^= RotateLeft(c, 4); c += b;
            b -= a; b ^= RotateLeft(a, 6); a += c;
            c -= b; c ^= RotateLeft(b, 8); b += a;
            a -= c; a ^= RotateLeft(c, 16); c += b;
            b -= a; b ^= RotateLeft(a, 19); a += c;
            c -= b; c ^= RotateLeft(b, 4); b += a;
        }
    }

    private static void FinalizeHdf5Checksum(ref uint a, ref uint b, ref uint c) {
        unchecked {
            c ^= b; c -= RotateLeft(b, 14);
            a ^= c; a -= RotateLeft(c, 11);
            b ^= a; b -= RotateLeft(a, 25);
            c ^= b; c -= RotateLeft(b, 16);
            a ^= c; a -= RotateLeft(c, 4);
            b ^= a; b -= RotateLeft(a, 14);
            c ^= b; c -= RotateLeft(b, 24);
        }
    }

    private static uint RotateLeft(uint value, int count) => (value << count) | (value >> (32 - count));

    private static bool TryReadHdfAddress(ReadOnlySpan<byte> src, ref int cursor, int size, out ulong value, out bool undefined) {
        value = 0;
        undefined = false;
        if (cursor < 0 || cursor + size > src.Length) return false;
        undefined = true;
        int valueBytes = Math.Min(size, 8);
        for (int i = 0; i < size; i++) {
            byte current = src[cursor + i];
            if (current != 0xFF) undefined = false;
            if (i < valueBytes) value |= (ulong)current << (i * 8);
        }
        if (size == 16 && !undefined)
            for (int i = 8; i < 16; i++) if (src[cursor + i] != 0) return false;
        cursor += size;
        return true;
    }

    private static bool IsValidHdfIntegerSize(byte size) => size is 2 or 4 or 8 or 16;

    private static ContentTypeDetectionResult Hdf5Result(long offset, bool completeLength = true) => new() {
        Extension = "h5",
        MimeType = "application/x-hdf5",
        Confidence = completeLength ? "High" : "Medium",
        Reason = "hdf5:signature@" + offset + (completeLength ? string.Empty : ";sampled-length-unknown")
    };
}
