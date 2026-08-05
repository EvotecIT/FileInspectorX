namespace FileInspectorX;

/// <summary>
/// Archive and disk image signatures (CAB/TAR/ISO/UDF).
/// </summary>
internal static partial class Signatures {
    private readonly struct CabDataRange
    {
        internal CabDataRange(long start, long end) { Start = start; End = end; }
        internal long Start { get; }
        internal long End { get; }
    }

    internal static bool TryMatch7z(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        // 7z signature: 37 7A BC AF 27 1C
        if (src.Length >= 6 && src[0] == 0x37 && src[1] == 0x7A && src[2] == 0xBC && src[3] == 0xAF && src[4] == 0x27 && src[5] == 0x1C) {
            result = new ContentTypeDetectionResult { Extension = "7z", MimeType = "application/x-7z-compressed", Confidence = "High", Reason = "7z" };
            return true;
        }
        return false;
    }

    internal static bool TryMatchRar(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        // RAR 4.x: 52 61 72 21 1A 07 00
        if (src.Length >= 7 && src[0] == 0x52 && src[1] == 0x61 && src[2] == 0x72 && src[3] == 0x21 && src[4] == 0x1A && src[5] == 0x07 && src[6] == 0x00) {
            result = new ContentTypeDetectionResult { Extension = "rar", MimeType = "application/vnd.rar", Confidence = "High", Reason = "rar4" };
            return true;
        }
        // RAR 5.x: 52 61 72 21 1A 07 01 00
        if (src.Length >= 8 && src[0] == 0x52 && src[1] == 0x61 && src[2] == 0x72 && src[3] == 0x21 && src[4] == 0x1A && src[5] == 0x07 && src[6] == 0x01 && src[7] == 0x00) {
            result = new ContentTypeDetectionResult { Extension = "rar", MimeType = "application/vnd.rar", Confidence = "High", Reason = "rar5" };
            return true;
        }
        return false;
    }
    internal static bool TryMatchCab(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchCab(src, src.Length, out result);

    internal static bool TryMatchCab(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 36 || !src.Slice(0, 4).SequenceEqual("MSCF"u8)) return false;
        uint cabinetSize = ReadUInt32LittleEndian(src, 8);
        uint filesOffset = ReadUInt32LittleEndian(src, 16);
        byte minorVersion = src[24];
        byte majorVersion = src[25];
        ushort folderCount = ReadUInt16LittleEndian(src, 26);
        ushort fileCount = ReadUInt16LittleEndian(src, 28);
        ushort flags = ReadUInt16LittleEndian(src, 30);
        if (cabinetSize < 36 || filesOffset < 36 || filesOffset > cabinetSize || completeLength < 0 ||
            (completeLength.HasValue && cabinetSize > completeLength.Value) ||
            majorVersion != 1 || minorVersion != 3 || folderCount == 0 || fileCount == 0 || (flags & 0xFFF8) != 0)
            return false;

        int cursor = 36;
        byte folderReserve = 0;
        byte dataReserve = 0;
        if ((flags & 0x0004) != 0) {
            if (cursor + 4 > src.Length) return TryCreateSampledCab(completeLength, src.Length, out result);
            ushort headerReserve = ReadUInt16LittleEndian(src, cursor);
            folderReserve = src[cursor + 2];
            dataReserve = src[cursor + 3];
            cursor += 4;
            if (headerReserve > cabinetSize - cursor) return false;
            if (headerReserve > src.Length - cursor) return TryCreateSampledCab(completeLength, src.Length, out result);
            cursor += headerReserve;
        }
        if ((flags & 0x0001) != 0) {
            if (!TrySkipCabString(src, ref cursor, cabinetSize, completeLength, out bool sampled) ||
                !TrySkipCabString(src, ref cursor, cabinetSize, completeLength, out bool sampledDisk)) return false;
            if (sampled || sampledDisk) return TryCreateSampledCab(completeLength, src.Length, out result);
        }
        if ((flags & 0x0002) != 0) {
            if (!TrySkipCabString(src, ref cursor, cabinetSize, completeLength, out bool sampled) ||
                !TrySkipCabString(src, ref cursor, cabinetSize, completeLength, out bool sampledDisk)) return false;
            if (sampled || sampledDisk) return TryCreateSampledCab(completeLength, src.Length, out result);
        }

        long folderRecordSize = 8L + folderReserve;
        long folderTableEnd = cursor + folderCount * folderRecordSize;
        if (folderTableEnd > filesOffset || folderTableEnd > cabinetSize) return false;
        if (folderTableEnd > src.Length) return TryCreateSampledCab(completeLength, src.Length, out result);
        var dataOffsets = new uint[folderCount];
        var dataBlockCounts = new ushort[folderCount];
        var compressionTypes = new byte[folderCount];
        var uniqueDataOffsets = new System.Collections.Generic.HashSet<uint>();
        bool payloadIntegrityNotValidated = false;
        var folderDataRanges = new System.Collections.Generic.List<CabDataRange>(folderCount);
        for (int folder = 0; folder < folderCount; folder++) {
            int record = checked(cursor + (int)(folder * folderRecordSize));
            uint dataOffset = ReadUInt32LittleEndian(src, record);
            ushort dataBlockCount = ReadUInt16LittleEndian(src, record + 4);
            ushort compressionType = ReadUInt16LittleEndian(src, record + 6);
            if (dataOffset > cabinetSize) return false;
            if (dataBlockCount != 0 && !uniqueDataOffsets.Add(dataOffset)) return false;
            if (!IsValidCabCompressionType(compressionType)) return false;
            dataOffsets[folder] = dataOffset;
            dataBlockCounts[folder] = dataBlockCount;
            compressionTypes[folder] = (byte)(compressionType & 0x000F);
        }

        if (filesOffset > int.MaxValue) return TryCreateSampledCab(completeLength, src.Length, out result);
        cursor = (int)filesOffset;
        var requiredFolderLengths = new ulong[folderCount];
        for (int file = 0; file < fileCount; file++) {
            if (cursor + 16L > cabinetSize) return false;
            if (cursor + 16 > src.Length) return TryCreateSampledCab(completeLength, src.Length, out result);
            uint fileLength = ReadUInt32LittleEndian(src, cursor);
            uint folderOffset = ReadUInt32LittleEndian(src, cursor + 4);
            ushort folderIndex = ReadUInt16LittleEndian(src, cursor + 8);
            if (folderIndex >= folderCount && folderIndex is not (0xFFFD or 0xFFFE or 0xFFFF)) return false;
            if (folderIndex == 0xFFFD && (flags & 0x0001) == 0 ||
                folderIndex == 0xFFFE && (flags & 0x0002) == 0 ||
                folderIndex == 0xFFFF && (flags & 0x0003) != 0x0003) return false;
            if (folderIndex < folderCount) {
                ulong fileEnd = (ulong)folderOffset + fileLength;
                if (fileEnd > requiredFolderLengths[folderIndex]) requiredFolderLengths[folderIndex] = fileEnd;
            }
            cursor += 16;
            int nameStart = cursor;
            while (cursor < src.Length && cursor < cabinetSize && src[cursor] != 0) cursor++;
            if (cursor >= cabinetSize) return false;
            if (cursor >= src.Length) return TryCreateSampledCab(completeLength, src.Length, out result);
            if (cursor == nameStart) return false;
            cursor++;
        }

        for (int folder = 0; folder < folderCount; folder++) {
            ushort dataBlockCount = dataBlockCounts[folder];
            if (dataBlockCount == 0) {
                if (requiredFolderLengths[folder] != 0) return false;
                continue;
            }
            long dataCursor = dataOffsets[folder];
            if (dataCursor < cursor || dataCursor >= cabinetSize) return false;
            ulong uncompressedLength = 0;
            for (int block = 0; block < dataBlockCount; block++) {
                long blockHeaderLength = 8L + dataReserve;
                if (dataCursor > cabinetSize - blockHeaderLength) return false;
                if (dataCursor + blockHeaderLength > src.Length)
                    return TryCreateSampledCab(completeLength, src.Length, out result);
                int blockOffset = checked((int)dataCursor);
                ushort compressedLength = ReadUInt16LittleEndian(src, blockOffset + 4);
                ushort expandedLength = ReadUInt16LittleEndian(src, blockOffset + 6);
                if (compressedLength == 0 || expandedLength > 32768 ||
                    compressionTypes[folder] == 0 && expandedLength != 0 && compressedLength != expandedLength) return false;
                payloadIntegrityNotValidated |= compressionTypes[folder] != 0 || ReadUInt32LittleEndian(src, blockOffset) != 0;
                long blockEnd = dataCursor + blockHeaderLength + compressedLength;
                if (blockEnd > cabinetSize) return false;
                if (blockEnd > src.Length) return TryCreateSampledCab(completeLength, src.Length, out result);
                uncompressedLength += expandedLength;
                dataCursor = blockEnd;
            }
            if (uncompressedLength < requiredFolderLengths[folder]) return false;
            folderDataRanges.Add(new CabDataRange(dataOffsets[folder], dataCursor));
        }
        folderDataRanges.Sort((left, right) => left.Start.CompareTo(right.Start));
        for (int index = 1; index < folderDataRanges.Count; index++)
        {
            if (folderDataRanges[index].Start < folderDataRanges[index - 1].End) return false;
        }

        bool trailingDataNotValidated = completeLength.HasValue && completeLength.Value > cabinetSize;
        result = CabResult(complete: true, payloadIntegrityNotValidated: payloadIntegrityNotValidated,
            trailingDataNotValidated: trailingDataNotValidated);
        return true;
    }

    private static bool IsValidCabCompressionType(ushort value) {
        int type = value & 0x000F;
        if (type > 3 || (value & 0xE000) != 0) return false;
        if (type is 0 or 1) return (value & 0xFFF0) == 0;
        int level = (value >> 4) & 0x0F;
        int memory = (value >> 8) & 0x1F;
        return type == 2 ? level is >= 1 and <= 7 && memory is >= 10 and <= 21
                         : level == 0 && memory is >= 15 and <= 21;
    }

    private static bool TrySkipCabString(ReadOnlySpan<byte> src, ref int cursor, uint cabinetSize, long? completeLength, out bool sampled) {
        sampled = false;
        int start = cursor;
        while (cursor < src.Length && cursor < cabinetSize && src[cursor] != 0) cursor++;
        if (cursor >= cabinetSize) return false;
        if (cursor >= src.Length) {
            sampled = !completeLength.HasValue || src.Length < completeLength.Value;
            return sampled;
        }
        if (cursor == start) return false;
        cursor++;
        return true;
    }

    private static bool TryCreateSampledCab(long? completeLength, int sampledLength, out ContentTypeDetectionResult? result) {
        result = null;
        if (completeLength.HasValue && completeLength.Value <= sampledLength) return false;
        result = CabResult(complete: false);
        return true;
    }

    private static ContentTypeDetectionResult CabResult(bool complete, bool payloadIntegrityNotValidated = false,
        bool trailingDataNotValidated = false) => new() {
        Extension = "cab",
        MimeType = "application/vnd.ms-cab-compressed",
        Confidence = complete && !payloadIntegrityNotValidated && !trailingDataNotValidated ? "High" : "Medium",
        Reason = "cab:cfheader" + (complete ? ";folders+files" : ";sampled-structures") +
                 (payloadIntegrityNotValidated ? ";payload-integrity-not-validated" : string.Empty) +
                 (trailingDataNotValidated ? ";trailing-data-not-validated" : string.Empty)
    };

    internal static bool TryMatchTar(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 265) return false;
        if (src.Slice(257, 5).SequenceEqual("ustar"u8)) { result = new ContentTypeDetectionResult { Extension = "tar", MimeType = "application/x-tar", Confidence = "High", Reason = "ustar" }; return true; }
        return false;
    }

    internal static bool TryMatchIso(Stream fs, out ContentTypeDetectionResult? result) {
        result = null;
        try {
            static bool checkAt(Stream s, long offset) {
                if (s.Length < offset + 5) return false;
                var arr = new byte[5];
                s.Seek(offset, SeekOrigin.Begin);
                var r = s.Read(arr, 0, arr.Length);
                return r == 5 && new ReadOnlySpan<byte>(arr).SequenceEqual("CD001"u8);
            }
            // Only accept ISO when CD001 appears at standard Primary/Backup Volume Descriptor offsets.
            if (checkAt(fs, 0x8001) || checkAt(fs, 0x8801) || checkAt(fs, 0x9001)) {
                result = new ContentTypeDetectionResult { Extension = "iso", MimeType = "application/x-iso9660-image", Confidence = "High", Reason = "iso:cd001" };
                return true;
            }
        } catch { }
        return false;
    }

    internal static bool TryMatchUdf(Stream fs, out ContentTypeDetectionResult? result) {
        result = null;
        try {
            const int sector = 2048;
            long start = 16L * sector + 1; // byte index for 5-char id
            var ids = new[] {
                System.Text.Encoding.ASCII.GetBytes("NSR02"),
                System.Text.Encoding.ASCII.GetBytes("NSR03"),
                System.Text.Encoding.ASCII.GetBytes("BEA01"),
                System.Text.Encoding.ASCII.GetBytes("TEA01")
            };
            var buf = new byte[5];
            int bea = -1; int nsr = -1; string nsrVer = ""; int tea = -1;
            for (int i = 0; i < 32; i++) {
                long off = start + i * sector;
                if (fs.Length < off + 5) break;
                fs.Seek(off, SeekOrigin.Begin);
                if (fs.Read(buf, 0, 5) != 5) break;
                var span = new ReadOnlySpan<byte>(buf);
                if (span.SequenceEqual(ids[2])) bea = i; // BEA01
                else if (span.SequenceEqual(ids[0]) || span.SequenceEqual(ids[1])) { nsr = i; nsrVer = span.SequenceEqual(ids[0]) ? "nsr02" : "nsr03"; }
                else if (span.SequenceEqual(ids[3])) tea = i; // TEA01
            }
            if (nsr >= 0) {
                var confidence = (bea >= 0 && bea < nsr && tea > nsr) ? "High" : "Medium";
                result = new ContentTypeDetectionResult { Extension = "udf", MimeType = "application/udf", Confidence = confidence, Reason = $"udf:{nsrVer}{(confidence == "High" ? ":bea+tea" : "")}" };
                return true;
            }
        } catch { }
        return false;
    }

    internal static bool TryMatchDmg(Stream fs, out ContentTypeDetectionResult? result) {
        // Apple UDIF (DMG) has 512-byte trailer at EOF starting with 'koly'
        result = null;
        try {
            if (fs.Length < 512) return false;
            fs.Seek(-512, SeekOrigin.End);
            var buf = new byte[4];
            int n = fs.Read(buf, 0, 4);
            if (n == 4 && buf[0] == (byte)'k' && buf[1] == (byte)'o' && buf[2] == (byte)'l' && buf[3] == (byte)'y') {
                result = new ContentTypeDetectionResult { Extension = "dmg", MimeType = "application/x-apple-diskimage", Confidence = "Medium", Reason = "udif:koly" };
                return true;
            }
        } catch { }
        return false;
    }
}
