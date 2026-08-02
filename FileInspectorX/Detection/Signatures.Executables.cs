namespace FileInspectorX;

/// <summary>
/// Executable formats (ELF, Java class, DEX, Mach-O) detection.
/// </summary>
internal static partial class Signatures {
    internal static bool TryMatchElf(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchElf(src, src.Length, out result);

    internal static bool TryMatchElf(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
        => TryMatchElf(src, completeLength, default, out result);

    internal static bool TryMatchElf(Stream stream, out ContentTypeDetectionResult? result) {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try {
            if (stream.Length < 16 || !TryReadAt(stream, 0, (int)Math.Min(64, stream.Length), out var headerBytes)) return false;
            var header = new ReadOnlySpan<byte>(headerBytes);
            if (header.Length < 16 || header[4] is not (1 or 2)) return false;
            bool littleEndian = header[5] == 1;
            if (!littleEndian && header[5] != 2) return false;
            int sectionOffsetField = header[4] == 1 ? 32 : 40;
            int sectionEntrySizeField = header[4] == 1 ? 46 : 58;
            ulong sectionOffset = header[4] == 1 ? ReadUInt32(header, sectionOffsetField, littleEndian) : ReadUInt64(header, sectionOffsetField, littleEndian);
            ushort sectionEntrySize = ReadUInt16(header, sectionEntrySizeField, littleEndian);
            ReadOnlySpan<byte> sectionZero = default;
            byte[]? sectionZeroBytes = null;
            if (sectionOffset != 0 && sectionEntrySize != 0 && sectionOffset <= long.MaxValue && sectionEntrySize <= stream.Length - (long)sectionOffset &&
                TryReadAt(stream, (long)sectionOffset, sectionEntrySize, out sectionZeroBytes))
                sectionZero = new ReadOnlySpan<byte>(sectionZeroBytes);
            return TryMatchElf(header, stream.Length, sectionZero, out result);
        } catch {
            result = null;
            return false;
        } finally {
            try { stream.Seek(originalPosition, SeekOrigin.Begin); } catch { }
        }
    }

    private static bool TryMatchElf(ReadOnlySpan<byte> src, long? completeLength, ReadOnlySpan<byte> sectionZero, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 16) return false;
        if (!(src[0] == 0x7F && src[1] == (byte)'E' && src[2] == (byte)'L' && src[3] == (byte)'F')) return false;
        var clazz = src[4];
        var endian = src[5];
        if (clazz is not (1 or 2) || endian is not (1 or 2) || src[6] != 1) return false;
        for (int i = 9; i < 16; i++) if (src[i] != 0) return false;
        int headerSize = clazz == 1 ? 52 : 64;
        if (src.Length < headerSize) return false;
        bool littleEndian = endian == 1;
        ushort etype = ReadUInt16(src, 16, littleEndian);
        ushort emach = ReadUInt16(src, 18, littleEndian);
        uint version = ReadUInt32(src, 20, littleEndian);
        int headerSizeOffset = clazz == 1 ? 40 : 52;
        int programEntrySizeOffset = clazz == 1 ? 42 : 54;
        int programCountOffset = clazz == 1 ? 44 : 56;
        int sectionEntrySizeOffset = clazz == 1 ? 46 : 58;
        int sectionCountOffset = clazz == 1 ? 48 : 60;
        int sectionNameIndexOffset = clazz == 1 ? 50 : 62;
        ushort declaredHeaderSize = ReadUInt16(src, headerSizeOffset, littleEndian);
        ushort programEntrySize = ReadUInt16(src, programEntrySizeOffset, littleEndian);
        ushort declaredProgramCount = ReadUInt16(src, programCountOffset, littleEndian);
        ushort sectionEntrySize = ReadUInt16(src, sectionEntrySizeOffset, littleEndian);
        ushort declaredSectionCount = ReadUInt16(src, sectionCountOffset, littleEndian);
        ushort declaredSectionNameIndex = ReadUInt16(src, sectionNameIndexOffset, littleEndian);
        bool knownType = etype <= 4 || etype is >= 0xFE00 and <= 0xFEFF || etype >= 0xFF00;
        if (!knownType || version != 1 || declaredHeaderSize != headerSize) return false;
        if (declaredProgramCount > 0 && declaredProgramCount != 0xFFFF && programEntrySize != (clazz == 1 ? 32 : 56)) return false;
        ulong programOffset = clazz == 1 ? ReadUInt32(src, 28, littleEndian) : ReadUInt64(src, 32, littleEndian);
        ulong sectionOffset = clazz == 1 ? ReadUInt32(src, 32, littleEndian) : ReadUInt64(src, 40, littleEndian);
        bool needsSectionZero = sectionOffset != 0 && (declaredSectionCount == 0 || declaredProgramCount == 0xFFFF || declaredSectionNameIndex == 0xFFFF);
        int expectedSectionEntrySize = clazz == 1 ? 40 : 64;
        if (sectionOffset != 0 && sectionEntrySize != expectedSectionEntrySize) return false;
        if (sectionOffset == 0 && (declaredSectionCount != 0 || declaredProgramCount == 0xFFFF || declaredSectionNameIndex == 0xFFFF)) return false;
        if (needsSectionZero && sectionZero.IsEmpty && sectionOffset <= int.MaxValue &&
            (ulong)src.Length >= sectionOffset + sectionEntrySize)
            sectionZero = src.Slice((int)sectionOffset, sectionEntrySize);
        if (needsSectionZero && sectionZero.Length < expectedSectionEntrySize) return false;

        ulong sectionCount = declaredSectionCount;
        if (declaredSectionCount == 0 && sectionOffset != 0)
            sectionCount = clazz == 1 ? ReadUInt32(sectionZero, 20, littleEndian) : ReadUInt64(sectionZero, 32, littleEndian);
        ulong programCount = declaredProgramCount == 0xFFFF ? ReadUInt32(sectionZero, clazz == 1 ? 28 : 44, littleEndian) : declaredProgramCount;
        ulong sectionNameIndex = declaredSectionNameIndex == 0xFFFF ? ReadUInt32(sectionZero, clazz == 1 ? 24 : 40, littleEndian) : declaredSectionNameIndex;
        if (sectionOffset != 0 && sectionCount == 0 || sectionNameIndex != 0 && sectionNameIndex >= sectionCount) return false;
        if (programCount > 0 && programEntrySize != (clazz == 1 ? 32 : 56)) return false;
        if (completeLength < 0 ||
            !IsElfTableRangeValid(programOffset, programEntrySize, programCount, headerSize, completeLength) ||
            !IsElfTableRangeValid(sectionOffset, sectionEntrySize, sectionCount, headerSize, completeLength)) return false;

        string c = clazz == 2 ? "64" : "32";
        string e = littleEndian ? "le" : "be";
        string et = etype == 0 ? "none" : etype == 1 ? "rel" : etype == 2 ? "exec" : etype == 3 ? "dyn" :
            etype == 4 ? "core" : etype <= 0xFEFF ? "os-specific" : "processor-specific";
        string mach = emach switch {
            0 => "unspecified", 3 => "x86", 62 => "x86_64", 40 => "arm", 183 => "aarch64", 8 => "mips", 50 => "ia64", 243 => "riscv", _ => emach.ToString(System.Globalization.CultureInfo.InvariantCulture)
        };
        var r = $"elf:{c}-{e}" + (et == "" ? "" : $":{et}") + (mach == "" ? "" : $":{mach}");
        result = new ContentTypeDetectionResult { Extension = "elf", MimeType = "application/x-elf", Confidence = "High", Reason = r };
        return true;
    }

    private static bool IsElfTableRangeValid(ulong offset, ushort entrySize, ulong count, int headerSize, long? completeLength)
    {
        if (count == 0) return offset == 0;
        if (offset < (ulong)headerSize || entrySize == 0) return false;
        if (count > ulong.MaxValue / entrySize) return false;
        ulong length = (ulong)entrySize * count;
        return !completeLength.HasValue || offset <= (ulong)completeLength.Value && length <= (ulong)completeLength.Value - offset;
    }

    internal static bool TryMatchMachO(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchMachO(src, src.Length, out result);

    internal static bool TryMatchMachO(ReadOnlySpan<byte> src, long? totalLength, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 4) return false;
        uint m = (uint)(src[0] << 24 | src[1] << 16 | src[2] << 8 | src[3]);
        if (m is 0xCAFEBABE or 0xBEBAFECA or 0xCAFEBABF or 0xBFBAFECA)
            return TryMatchFatMachO(src, littleEndian: m is 0xBEBAFECA or 0xBFBAFECA,
                is64Bit: m is 0xCAFEBABF or 0xBFBAFECA, totalLength, out result);

        bool littleEndian;
        bool is64Bit;
        string reason;
        switch (m) {
            case 0xFEEDFACE: littleEndian = false; is64Bit = false; reason = "macho:be32"; break;
            case 0xCEFAEDFE: littleEndian = true; is64Bit = false; reason = "macho:le32"; break;
            case 0xFEEDFACF: littleEndian = false; is64Bit = true; reason = "macho:be64"; break;
            case 0xCFFAEDFE: littleEndian = true; is64Bit = true; reason = "macho:le64"; break;
            default: return false;
        }

        int headerSize = is64Bit ? 32 : 28;
        if (src.Length < headerSize) return false;
        uint cpuType = ReadUInt32(src, 4, littleEndian);
        uint fileType = ReadUInt32(src, 12, littleEndian);
        uint commandCount = ReadUInt32(src, 16, littleEndian);
        uint commandBytes = ReadUInt32(src, 20, littleEndian);
        uint commandAlignment = is64Bit ? 8u : 4u;

        if (!IsKnownMachCpuType(cpuType) || fileType < 1 || fileType > 14) return false;
        if ((commandBytes % commandAlignment) != 0) return false;
        if (commandCount == 0) {
            if (commandBytes != 0) return false;
        } else if (commandBytes / 8 < commandCount) {
            return false;
        }
        ulong commandEnd = (ulong)headerSize + commandBytes;
        if (totalLength.HasValue && commandEnd > (ulong)totalLength.Value) return false;
        bool commandsSampled = commandEnd <= (ulong)src.Length;
        if (commandsSampled && !TryValidateMachLoadCommands(src.Slice(headerSize, (int)commandBytes), commandCount, commandAlignment, littleEndian)) return false;
        if (!commandsSampled && (!totalLength.HasValue || commandEnd <= (ulong)src.Length)) return false;

        result = new ContentTypeDetectionResult {
            Extension = "macho",
            MimeType = "application/x-mach-binary",
            Confidence = commandsSampled ? "High" : "Medium",
            Reason = reason + (commandsSampled ? string.Empty : ";sampled-load-commands")
        };
        return true;
    }

    private static bool TryValidateMachLoadCommands(ReadOnlySpan<byte> commands, uint commandCount, uint alignment, bool littleEndian)
    {
        int cursor = 0;
        for (uint index = 0; index < commandCount; index++)
        {
            if (cursor + 8 > commands.Length) return false;
            uint command = ReadUInt32(commands, cursor, littleEndian);
            uint size = ReadUInt32(commands, cursor + 4, littleEndian);
            if (command == 0 || size < 8 || (size % alignment) != 0 || size > (uint)(commands.Length - cursor)) return false;
            cursor += (int)size;
        }
        return cursor == commands.Length;
    }

    internal static bool TryMatchJavaClass(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (InspectJavaClass(src, out ushort major, out ushort minor) != JavaSampleStatus.Complete) return false;
        result = JavaClassResult(major, minor);
        return true;
    }

    internal static bool TryMatchJavaClass(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result) {
        if (completeLength.HasValue) return TryMatchJavaClass(src, out result);
        result = null;
        JavaSampleStatus status = InspectJavaClass(src, out ushort major, out ushort minor);
        if (status == JavaSampleStatus.Invalid) return false;
        result = JavaClassResult(major, minor);
        result.Confidence = "Medium";
        result.Reason += ";sampled-length-unknown";
        return true;
    }

    /// <summary>
    /// Validates a complete JVM ClassFile without limiting seekable inputs to the detector's prefix sample.
    /// Attribute payloads are skipped in place so large classes do not require whole-file allocation.
    /// </summary>
    internal static bool TryMatchJavaClass(Stream stream, out ContentTypeDetectionResult? result) {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try {
            if (stream.Length < 10) return false;
            stream.Seek(0, SeekOrigin.Begin);
            if (!TryReadJavaU4(stream, out uint magic) || magic != 0xCAFEBABE ||
                !TryReadJavaU2(stream, out ushort minor) ||
                !TryReadJavaU2(stream, out ushort major) ||
                !TryReadJavaU2(stream, out ushort constantPoolCount) ||
                !IsDefinedJavaClassVersion(major, minor) || constantPoolCount < 2) return false;

            var constantPoolTags = new byte[constantPoolCount];
            var constantPoolReference1 = new ushort[constantPoolCount];
            var constantPoolReference2 = new ushort[constantPoolCount];
            var constantPoolReferenceKinds = new byte[constantPoolCount];
            for (int index = 1; index < constantPoolCount; index++) {
                int tagValue = stream.ReadByte();
                if (tagValue < 0 || !IsJavaConstantPoolTag((byte)tagValue)) return false;
                byte tag = (byte)tagValue;
                constantPoolTags[index] = tag;
                switch (tag) {
                    case 1:
                        if (!TryReadJavaU2(stream, out ushort utf8Length) || !TrySkipJavaBytes(stream, utf8Length)) return false;
                        break;
                    case 3:
                    case 4:
                        if (!TrySkipJavaBytes(stream, 4)) return false;
                        break;
                    case 5:
                    case 6:
                        if (!TrySkipJavaBytes(stream, 8)) return false;
                        break;
                    case 7:
                    case 8:
                    case 16:
                    case 19:
                    case 20:
                        if (!TryReadJavaU2(stream, out constantPoolReference1[index])) return false;
                        break;
                    case 9:
                    case 10:
                    case 11:
                    case 12:
                        if (!TryReadJavaU2(stream, out constantPoolReference1[index]) ||
                            !TryReadJavaU2(stream, out constantPoolReference2[index])) return false;
                        break;
                    case 15:
                        int referenceKind = stream.ReadByte();
                        if (referenceKind < 0 || !TryReadJavaU2(stream, out constantPoolReference1[index])) return false;
                        constantPoolReferenceKinds[index] = (byte)referenceKind;
                        break;
                    case 17:
                    case 18:
                        if (!TryReadJavaU2(stream, out _) || !TryReadJavaU2(stream, out constantPoolReference1[index])) return false;
                        break;
                    default:
                        return false;
                }
                if (tag is 5 or 6 && ++index >= constantPoolCount) return false;
            }
            if (!AreJavaConstantPoolReferencesValid(constantPoolTags, constantPoolReference1,
                    constantPoolReference2, constantPoolReferenceKinds, major)) return false;

            if (!TryReadJavaU2(stream, out _) ||
                !TryReadJavaU2(stream, out ushort thisClass) ||
                !TryReadJavaU2(stream, out ushort superClass) ||
                !TryReadJavaU2(stream, out ushort interfaceCount) ||
                !IsJavaConstantPoolReference(constantPoolTags, thisClass, 7) ||
                (superClass != 0 && !IsJavaConstantPoolReference(constantPoolTags, superClass, 7))) return false;
            for (int index = 0; index < interfaceCount; index++) {
                if (!TryReadJavaU2(stream, out ushort interfaceClass) ||
                    !IsJavaConstantPoolReference(constantPoolTags, interfaceClass, 7)) return false;
            }
            if (!TrySkipJavaMembers(stream, constantPoolTags) ||
                !TrySkipJavaMembers(stream, constantPoolTags) ||
                !TrySkipJavaAttributes(stream, constantPoolTags) ||
                stream.Position != stream.Length) return false;

            result = JavaClassResult(major, minor);
            return true;
        } catch {
            result = null;
            return false;
        } finally {
            try { stream.Seek(originalPosition, SeekOrigin.Begin); } catch { }
        }
    }

    internal static bool TryMatchDex(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchDex(src, src.Length, out result);

    internal static bool TryMatchDex(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!stream.CanRead || !stream.CanSeek || stream.Length < 0x70) return false;
        long originalPosition = stream.Position;
        try
        {
            if (stream.Length <= Math.Max(0x78, Settings.DetectionReadBudgetBytes) && stream.Length <= int.MaxValue &&
                TryReadAt(stream, 0, (int)stream.Length, out var complete))
                return TryMatchDex(new ReadOnlySpan<byte>(complete), stream.Length, out result);
            if (!TryReadAt(stream, 0, 0x78, out var header) || !TryMatchDex(new ReadOnlySpan<byte>(header), null, out result)) return false;
            result!.Confidence = "Medium";
            result.Reason += ";integrity-budget-exceeded";
            return true;
        }
        finally
        {
            try { stream.Seek(originalPosition, SeekOrigin.Begin); } catch { }
        }
    }

    internal static bool TryMatchDex(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 0x70 || src[0] != (byte)'d' || src[1] != (byte)'e' || src[2] != (byte)'x' ||
            src[3] != (byte)'\n' || src[7] != 0 ||
            src[4] < (byte)'0' || src[4] > (byte)'9' ||
            src[5] < (byte)'0' || src[5] > (byte)'9' ||
            src[6] < (byte)'0' || src[6] > (byte)'9')
            return false;

        int version = (src[4] - (byte)'0') * 100 + (src[5] - (byte)'0') * 10 + src[6] - (byte)'0';
        if (version is not (35 or 37 or 38 or 39 or 40 or 41)) return false;

        uint endianTagAsLittleEndian = ReadUInt32(src, 40, littleEndian: true);
        bool fieldsAreLittleEndian;
        if (endianTagAsLittleEndian == 0x12345678) fieldsAreLittleEndian = true;
        else if (endianTagAsLittleEndian == 0x78563412) fieldsAreLittleEndian = false;
        else return false;

        uint fileSize = ReadUInt32(src, 32, fieldsAreLittleEndian);
        uint headerSize = ReadUInt32(src, 36, fieldsAreLittleEndian);
        uint expectedHeaderSize = version >= 41 ? 0x78u : 0x70u;
        if (headerSize != expectedHeaderSize || fileSize < headerSize || src.Length < headerSize) return false;
        if (version == 41) {
            uint containerSize = ReadUInt32(src, 112, fieldsAreLittleEndian);
            uint headerOffset = ReadUInt32(src, 116, fieldsAreLittleEndian);
            if (headerOffset != 0 || containerSize < headerSize || fileSize > containerSize ||
                (fileSize < containerSize && (fileSize & 3) != 0) ||
                (completeLength.HasValue && containerSize != completeLength.Value)) return false;
        }
        else if (completeLength.HasValue && fileSize != completeLength.Value) return false;

        if (completeLength.HasValue && fileSize <= src.Length &&
            !TryValidateDexSectionsAndMap(src.Slice(0, (int)fileSize), fieldsAreLittleEndian, headerSize)) return false;

        bool integrityValidated = false;
        if (completeLength.HasValue && fileSize <= int.MaxValue && fileSize <= src.Length)
        {
            int dexLength = (int)fileSize;
            using var sha1 = System.Security.Cryptography.SHA1.Create();
            byte[] calculatedSignature = sha1.ComputeHash(src.Slice(32, dexLength - 32).ToArray());
            if (!src.Slice(12, 20).SequenceEqual(calculatedSignature)) return false;
            uint storedChecksum = ReadUInt32(src, 8, fieldsAreLittleEndian);
            if (storedChecksum != ComputeAdler32(src.Slice(12, dexLength - 12))) return false;
            integrityValidated = true;
        }

        result = new ContentTypeDetectionResult {
            Extension = "dex",
            MimeType = "application/vnd.android.dex",
            Confidence = integrityValidated ? "High" : "Medium",
            Reason = $"dex:{version:000}" + (fieldsAreLittleEndian ? string.Empty : ":reverse-endian") +
                     (integrityValidated ? string.Empty : ";integrity-not-sampled")
        };
        return true;
    }

    private static bool TryValidateDexSectionsAndMap(ReadOnlySpan<byte> dex, bool littleEndian, uint headerSize)
    {
        uint mapOffset = ReadUInt32(dex, 52, littleEndian);
        uint dataSize = ReadUInt32(dex, 104, littleEndian);
        uint dataOffset = ReadUInt32(dex, 108, littleEndian);
        if (mapOffset == 0 || (mapOffset & 3) != 0 || mapOffset < headerSize || mapOffset > dex.Length - 4 ||
            dataOffset < headerSize || dataOffset > dex.Length || dataSize != dex.Length - dataOffset ||
            mapOffset < dataOffset) return false;

        var expected = new (ushort Type, int HeaderOffset, uint Width)[] {
            (0x0001, 56, 4), (0x0002, 64, 4), (0x0003, 72, 12),
            (0x0004, 80, 8), (0x0005, 88, 8), (0x0006, 96, 32)
        };
        for (int index = 0; index < expected.Length; index++)
        {
            uint count = ReadUInt32(dex, expected[index].HeaderOffset, littleEndian);
            uint offset = ReadUInt32(dex, expected[index].HeaderOffset + 4, littleEndian);
            if ((count == 0) != (offset == 0) || count != 0 &&
                ((offset & 3) != 0 || offset < headerSize || (ulong)offset + (ulong)count * expected[index].Width > (ulong)dex.Length))
                return false;
        }

        uint mapCount = ReadUInt32(dex, (int)mapOffset, littleEndian);
        if (mapCount is < 2 or > 65535 || (ulong)mapOffset + 4UL + (ulong)mapCount * 12UL > (ulong)dex.Length) return false;
        var seenTypes = new System.Collections.Generic.HashSet<ushort>();
        uint previousOffset = 0;
        bool sawHeader = false, sawMap = false;
        for (uint index = 0; index < mapCount; index++)
        {
            int item = checked((int)mapOffset + 4 + (int)index * 12);
            ushort type = ReadUInt16(dex, item, littleEndian);
            ushort unused = ReadUInt16(dex, item + 2, littleEndian);
            uint count = ReadUInt32(dex, item + 4, littleEndian);
            uint offset = ReadUInt32(dex, item + 8, littleEndian);
            if (unused != 0 || count == 0 || offset >= dex.Length || !seenTypes.Add(type) || index != 0 && offset < previousOffset) return false;
            previousOffset = offset;
            if (type == 0x0000) sawHeader = count == 1 && offset == 0;
            else if (type == 0x1000) sawMap = count == 1 && offset == mapOffset;
            for (int expectedIndex = 0; expectedIndex < expected.Length; expectedIndex++)
            {
                if (type != expected[expectedIndex].Type) continue;
                if (count != ReadUInt32(dex, expected[expectedIndex].HeaderOffset, littleEndian) ||
                    offset != ReadUInt32(dex, expected[expectedIndex].HeaderOffset + 4, littleEndian)) return false;
            }
        }
        return sawHeader && sawMap;
    }

    private static uint ComputeAdler32(ReadOnlySpan<byte> data)
    {
        const uint Modulus = 65521;
        uint a = 1;
        uint b = 0;
        for (int i = 0; i < data.Length; i++)
        {
            a = (a + data[i]) % Modulus;
            b = (b + a) % Modulus;
        }
        return (b << 16) | a;
    }

    private static bool TryMatchFatMachO(ReadOnlySpan<byte> src, bool littleEndian, bool is64Bit, long? totalLength, out ContentTypeDetectionResult? result) {
        result = null;
        int entrySize = is64Bit ? 32 : 20;
        if (src.Length < 8 + entrySize) return false;

        uint architectureCount = ReadUInt32(src, 4, littleEndian);
        if (architectureCount < 1 || architectureCount > 64) return false;
        long directoryEnd = 8L + architectureCount * entrySize;
        if (directoryEnd > src.Length) return false;

        bool allSlicesSampled = true;
        var sliceOffsets = new ulong[(int)architectureCount];
        var sliceEnds = new ulong[(int)architectureCount];
        for (uint i = 0; i < architectureCount; i++) {
            int entryOffset = checked(8 + (int)i * entrySize);
            uint cpuType = ReadUInt32(src, entryOffset, littleEndian);
            uint cpuSubtype = ReadUInt32(src, entryOffset + 4, littleEndian);
            ulong offset = is64Bit ? ReadUInt64(src, entryOffset + 8, littleEndian) : ReadUInt32(src, entryOffset + 8, littleEndian);
            ulong size = is64Bit ? ReadUInt64(src, entryOffset + 16, littleEndian) : ReadUInt32(src, entryOffset + 12, littleEndian);
            uint alignmentPower = ReadUInt32(src, entryOffset + (is64Bit ? 24 : 16), littleEndian);
            if (!IsKnownMachCpuType(cpuType) || offset < (ulong)directoryEnd || size == 0 || alignmentPower > 31 ||
                size > ulong.MaxValue - offset ||
                (is64Bit && ReadUInt32(src, entryOffset + 28, littleEndian) != 0) ||
                (totalLength.HasValue && (offset > (ulong)totalLength.Value || size > (ulong)totalLength.Value - offset))) return false;
            ulong sliceEnd = offset + size;
            for (uint previous = 0; previous < i; previous++)
                if (offset < sliceEnds[(int)previous] && sliceOffsets[(int)previous] < sliceEnd) return false;
            sliceOffsets[(int)i] = offset;
            sliceEnds[(int)i] = sliceEnd;
            ulong alignment = 1UL << (int)alignmentPower;
            if ((offset & (alignment - 1)) != 0) return false;
            if (offset + 12 <= (ulong)src.Length)
            {
                int available = (int)Math.Min(size, (ulong)src.Length - offset);
                if (!TryValidateMachSlice(src.Slice((int)offset, available), size, cpuType, cpuSubtype,
                        out bool sliceFullyValidated)) return false;
                allSlicesSampled &= sliceFullyValidated;
            }
            else allSlicesSampled = false;
        }

        result = new ContentTypeDetectionResult {
            Extension = "macho",
            MimeType = "application/x-mach-binary",
            Confidence = allSlicesSampled ? "High" : "Medium",
            Reason = "macho:fat" + (is64Bit ? "64" : string.Empty) + (littleEndian ? "-le" : string.Empty) +
                     (allSlicesSampled ? string.Empty : ";sampled-slices")
        };
        return true;
    }

    internal static bool TryMatchMachO(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try
        {
            int prefixLength = (int)Math.Min(stream.Length, Math.Max(32, Settings.HeaderReadBytes));
            if (prefixLength < 4 || !TryReadAt(stream, 0, prefixLength, out var prefix) ||
                !TryMatchMachO(new ReadOnlySpan<byte>(prefix), stream.Length, out result)) return false;
            uint magic = ReadUInt32BigEndian(new ReadOnlySpan<byte>(prefix), 0);
            bool fat = magic is 0xCAFEBABE or 0xBEBAFECA or 0xCAFEBABF or 0xBFBAFECA;
            if (!fat)
            {
                if (result?.Confidence != "Medium" || !result.Reason.Contains("sampled-load-commands")) return true;
                bool thinLittleEndian = magic is 0xCEFAEDFE or 0xCFFAEDFE;
                bool thin64Bit = magic is 0xFEEDFACF or 0xCFFAEDFE;
                int headerSize = thin64Bit ? 32 : 28;
                uint commandCount = ReadUInt32(new ReadOnlySpan<byte>(prefix), 16, thinLittleEndian);
                uint commandBytes = ReadUInt32(new ReadOnlySpan<byte>(prefix), 20, thinLittleEndian);
                uint alignment = thin64Bit ? 8u : 4u;
                if (!TryValidateMachLoadCommands(stream, 0, (ulong)stream.Length, headerSize, commandCount, commandBytes,
                        alignment, thinLittleEndian,
                        out bool budgetExceeded)) return false;
                if (budgetExceeded)
                {
                    result.Reason = result.Reason.Replace(";sampled-load-commands", ";validation-budget-exceeded");
                    return true;
                }
                result.Confidence = "High";
                result.Reason = result.Reason.Replace(";sampled-load-commands", string.Empty);
                return true;
            }
            bool littleEndian = magic is 0xBEBAFECA or 0xBFBAFECA;
            bool is64Bit = magic is 0xCAFEBABF or 0xBFBAFECA;
            uint count = ReadUInt32(new ReadOnlySpan<byte>(prefix), 4, littleEndian);
            int entrySize = is64Bit ? 32 : 20;
            int directoryLength = checked(8 + (int)count * entrySize);
            if (!TryReadAt(stream, 0, directoryLength, out var directory)) return false;
            var entries = new ReadOnlySpan<byte>(directory);
            for (int index = 0; index < count; index++)
            {
                int entry = 8 + index * entrySize;
                uint cpuType = ReadUInt32(entries, entry, littleEndian);
                uint cpuSubtype = ReadUInt32(entries, entry + 4, littleEndian);
                ulong offset = is64Bit ? ReadUInt64(entries, entry + 8, littleEndian) : ReadUInt32(entries, entry + 8, littleEndian);
                ulong size = is64Bit ? ReadUInt64(entries, entry + 16, littleEndian) : ReadUInt32(entries, entry + 12, littleEndian);
                if (offset > long.MaxValue ||
                    !TryReadAt(stream, (long)offset, (int)Math.Min(size, 32UL), out var sliceHeader) ||
                    !TryValidateMachSlice(new ReadOnlySpan<byte>(sliceHeader), size, cpuType, cpuSubtype,
                        out bool sliceFullyValidated)) return false;
                if (!sliceFullyValidated)
                {
                    var slice = new ReadOnlySpan<byte>(sliceHeader);
                    uint sliceMagic = ReadUInt32BigEndian(slice, 0);
                    bool sliceLittleEndian = sliceMagic is 0xCEFAEDFE or 0xCFFAEDFE;
                    bool slice64Bit = sliceMagic is 0xFEEDFACF or 0xCFFAEDFE;
                    int headerSize = slice64Bit ? 32 : 28;
                    uint commandCount = ReadUInt32(slice, 16, sliceLittleEndian);
                    uint commandBytes = ReadUInt32(slice, 20, sliceLittleEndian);
                    if (!TryValidateMachLoadCommands(stream, (long)offset, size, headerSize, commandCount, commandBytes,
                            slice64Bit ? 8u : 4u, sliceLittleEndian, out bool budgetExceeded)) return false;
                    if (budgetExceeded)
                    {
                        result!.Confidence = "Medium";
                        result.Reason = result.Reason.Replace(";sampled-slices", string.Empty) + ";slice-validation-budget-exceeded";
                        return true;
                    }
                }
            }
            result!.Confidence = "High";
            result.Reason = result.Reason.Replace(";sampled-slices", string.Empty);
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

    private static bool TryValidateMachSlice(ReadOnlySpan<byte> src, ulong declaredSize, uint expectedCpuType,
        uint expectedCpuSubtype, out bool fullyValidated)
    {
        fullyValidated = false;
        if (src.Length < 12) return false;
        uint magic = ReadUInt32BigEndian(src, 0);
        bool littleEndian = magic is 0xCEFAEDFE or 0xCFFAEDFE;
        if (magic is not (0xFEEDFACE or 0xCEFAEDFE or 0xFEEDFACF or 0xCFFAEDFE)) return false;
        bool is64Bit = magic is 0xFEEDFACF or 0xCFFAEDFE;
        int headerSize = is64Bit ? 32 : 28;
        if (ReadUInt32(src, 4, littleEndian) != expectedCpuType ||
            ReadUInt32(src, 8, littleEndian) != expectedCpuSubtype || declaredSize < (ulong)headerSize) return false;
        if (src.Length < headerSize) return true;
        uint fileType = ReadUInt32(src, 12, littleEndian);
        uint commandCount = ReadUInt32(src, 16, littleEndian);
        uint commandBytes = ReadUInt32(src, 20, littleEndian);
        uint alignment = is64Bit ? 8u : 4u;
        if (fileType < 1 || fileType > 14 || commandBytes % alignment != 0 ||
            (commandCount == 0 ? commandBytes != 0 : commandBytes / 8 < commandCount) ||
            (ulong)headerSize + commandBytes > declaredSize) return false;
        if ((ulong)headerSize + commandBytes > (ulong)src.Length) return true;
        if (!TryValidateMachLoadCommands(src.Slice(headerSize, (int)commandBytes), commandCount, alignment, littleEndian)) return false;
        fullyValidated = true;
        return true;
    }

    private static bool TryValidateMachLoadCommands(Stream stream, long baseOffset, ulong declaredSize, int headerSize, uint commandCount,
        uint commandBytes, uint alignment, bool littleEndian, out bool budgetExceeded)
    {
        budgetExceeded = false;
        long cursor = headerSize;
        long commandEnd = headerSize + (long)commandBytes;
        if ((ulong)commandEnd > declaredSize || baseOffset < 0 || baseOffset > stream.Length - commandEnd) return false;
        int commandBudget = Math.Max(32, Math.Min(4096, Math.Max(256, Settings.DetectionReadBudgetBytes) / 8));
        for (uint index = 0; index < commandCount; index++)
        {
            if (index >= commandBudget)
            {
                budgetExceeded = true;
                return true;
            }
            if (cursor > commandEnd - 8 || !TryReadAt(stream, baseOffset + cursor, 8, out var commandHeader)) return false;
            var header = new ReadOnlySpan<byte>(commandHeader);
            uint command = ReadUInt32(header, 0, littleEndian);
            uint size = ReadUInt32(header, 4, littleEndian);
            if (command == 0 || size < 8 || size % alignment != 0 || size > commandEnd - cursor) return false;
            cursor += size;
        }
        return cursor == commandEnd;
    }

    private static bool IsKnownMachCpuType(uint cpuType) {
        uint baseType = cpuType & 0x00FFFFFFu;
        uint abiFlags = cpuType & 0xFF000000u;
        if (abiFlags != 0 && abiFlags != 0x01000000u && abiFlags != 0x02000000u) return false;
        return baseType is 1 or 6 or 7 or 8 or 10 or 11 or 12 or 13 or 14 or 15 or 16 or 18;
    }

    private static bool IsJavaConstantPoolTag(byte tag)
        => tag is 1 or 3 or 4 or 5 or 6 or 7 or 8 or 9 or 10 or 11 or 12 or 15 or 16 or 17 or 18 or 19 or 20;

    private static bool IsJavaConstantPoolReference(byte[] tags, ushort index, byte expectedTag)
        => index > 0 && index < tags.Length && tags[index] == expectedTag;

    private enum JavaSampleStatus { Invalid, NeedMore, Complete }

    private static JavaSampleStatus InspectJavaClass(ReadOnlySpan<byte> src, out ushort major, out ushort minor) {
        major = 0;
        minor = 0;
        if (src.Length < 10 || src[0] != 0xCA || src[1] != 0xFE || src[2] != 0xBA || src[3] != 0xBE)
            return JavaSampleStatus.Invalid;
        minor = ReadUInt16BigEndian(src, 4);
        major = ReadUInt16BigEndian(src, 6);
        ushort constantPoolCount = ReadUInt16BigEndian(src, 8);
        if (!IsDefinedJavaClassVersion(major, minor) || constantPoolCount < 2) return JavaSampleStatus.Invalid;

        var constantPoolTags = new byte[constantPoolCount];
        var constantPoolReference1 = new ushort[constantPoolCount];
        var constantPoolReference2 = new ushort[constantPoolCount];
        var constantPoolReferenceKinds = new byte[constantPoolCount];
        int cursor = 10;
        for (int index = 1; index < constantPoolCount; index++) {
            if (cursor >= src.Length) return JavaSampleStatus.NeedMore;
            byte tag = src[cursor++];
            if (!IsJavaConstantPoolTag(tag)) return JavaSampleStatus.Invalid;
            constantPoolTags[index] = tag;
            int payloadLength;
            if (tag == 1) {
                if (cursor + 2 > src.Length) return JavaSampleStatus.NeedMore;
                payloadLength = 2 + ReadUInt16BigEndian(src, cursor);
            } else {
                payloadLength = tag switch {
                    3 or 4 or 9 or 10 or 11 or 12 or 17 or 18 => 4,
                    5 or 6 => 8,
                    7 or 8 or 16 or 19 or 20 => 2,
                    15 => 3,
                    _ => 0
                };
            }
            if (payloadLength == 0) return JavaSampleStatus.Invalid;
            if (payloadLength > src.Length - cursor) return JavaSampleStatus.NeedMore;
            switch (tag) {
                case 7:
                case 8:
                case 16:
                case 19:
                case 20:
                    constantPoolReference1[index] = ReadUInt16BigEndian(src, cursor);
                    break;
                case 9:
                case 10:
                case 11:
                case 12:
                    constantPoolReference1[index] = ReadUInt16BigEndian(src, cursor);
                    constantPoolReference2[index] = ReadUInt16BigEndian(src, cursor + 2);
                    break;
                case 15:
                    constantPoolReferenceKinds[index] = src[cursor];
                    constantPoolReference1[index] = ReadUInt16BigEndian(src, cursor + 1);
                    break;
                case 17:
                case 18:
                    constantPoolReference1[index] = ReadUInt16BigEndian(src, cursor + 2);
                    break;
            }
            cursor += payloadLength;
            if (tag is 5 or 6 && ++index >= constantPoolCount) return JavaSampleStatus.Invalid;
        }
        if (!AreJavaConstantPoolReferencesValid(constantPoolTags, constantPoolReference1,
                constantPoolReference2, constantPoolReferenceKinds, major)) return JavaSampleStatus.Invalid;

        if (cursor + 8 > src.Length) return JavaSampleStatus.NeedMore;
        ushort thisClass = ReadUInt16BigEndian(src, cursor + 2);
        ushort superClass = ReadUInt16BigEndian(src, cursor + 4);
        ushort interfaceCount = ReadUInt16BigEndian(src, cursor + 6);
        cursor += 8;
        if (!IsJavaConstantPoolReference(constantPoolTags, thisClass, 7) ||
            (superClass != 0 && !IsJavaConstantPoolReference(constantPoolTags, superClass, 7))) return JavaSampleStatus.Invalid;
        for (int index = 0; index < interfaceCount; index++) {
            if (cursor + 2 > src.Length) return JavaSampleStatus.NeedMore;
            ushort interfaceClass = ReadUInt16BigEndian(src, cursor);
            cursor += 2;
            if (!IsJavaConstantPoolReference(constantPoolTags, interfaceClass, 7)) return JavaSampleStatus.Invalid;
        }

        JavaSampleStatus status = InspectJavaMembers(src, ref cursor, constantPoolTags);
        if (status != JavaSampleStatus.Complete) return status;
        status = InspectJavaMembers(src, ref cursor, constantPoolTags);
        if (status != JavaSampleStatus.Complete) return status;
        status = InspectJavaAttributes(src, ref cursor, constantPoolTags);
        if (status != JavaSampleStatus.Complete) return status;
        return cursor == src.Length ? JavaSampleStatus.Complete : JavaSampleStatus.Invalid;
    }

    private static JavaSampleStatus InspectJavaMembers(ReadOnlySpan<byte> src, ref int cursor, byte[] constantPoolTags) {
        if (cursor + 2 > src.Length) return JavaSampleStatus.NeedMore;
        ushort count = ReadUInt16BigEndian(src, cursor);
        cursor += 2;
        for (int index = 0; index < count; index++) {
            if (cursor + 8 > src.Length) return JavaSampleStatus.NeedMore;
            ushort nameIndex = ReadUInt16BigEndian(src, cursor + 2);
            ushort descriptorIndex = ReadUInt16BigEndian(src, cursor + 4);
            ushort attributes = ReadUInt16BigEndian(src, cursor + 6);
            cursor += 8;
            if (!IsJavaConstantPoolReference(constantPoolTags, nameIndex, 1) ||
                !IsJavaConstantPoolReference(constantPoolTags, descriptorIndex, 1)) return JavaSampleStatus.Invalid;
            JavaSampleStatus status = InspectJavaAttributes(src, ref cursor, constantPoolTags, attributes);
            if (status != JavaSampleStatus.Complete) return status;
        }
        return JavaSampleStatus.Complete;
    }

    private static JavaSampleStatus InspectJavaAttributes(ReadOnlySpan<byte> src, ref int cursor, byte[] constantPoolTags) {
        if (cursor + 2 > src.Length) return JavaSampleStatus.NeedMore;
        ushort count = ReadUInt16BigEndian(src, cursor);
        cursor += 2;
        return InspectJavaAttributes(src, ref cursor, constantPoolTags, count);
    }

    private static JavaSampleStatus InspectJavaAttributes(ReadOnlySpan<byte> src, ref int cursor, byte[] constantPoolTags, ushort count) {
        for (int index = 0; index < count; index++) {
            if (cursor + 6 > src.Length) return JavaSampleStatus.NeedMore;
            ushort nameIndex = ReadUInt16BigEndian(src, cursor);
            uint length = ReadUInt32(src, cursor + 2, littleEndian: false);
            cursor += 6;
            if (!IsJavaConstantPoolReference(constantPoolTags, nameIndex, 1)) return JavaSampleStatus.Invalid;
            if (length > src.Length - cursor) return JavaSampleStatus.NeedMore;
            cursor += (int)length;
        }
        return JavaSampleStatus.Complete;
    }

    private static ContentTypeDetectionResult JavaClassResult(ushort major, ushort minor) => new() {
        Extension = "class",
        MimeType = "application/java-vm",
        Confidence = "High",
        Reason = $"java-class:{major}.{minor}"
    };

    private static bool IsDefinedJavaClassVersion(ushort major, ushort minor)
        => major == 45 ? minor <= 3 :
           major is >= 46 and <= 55 ? minor == 0 :
           major is >= 56 and <= 100 && minor is 0 or ushort.MaxValue;

    private static bool AreJavaConstantPoolReferencesValid(byte[] tags, ushort[] reference1,
        ushort[] reference2, byte[] referenceKinds, ushort major) {
        for (int index = 1; index < tags.Length; index++) {
            byte tag = tags[index];
            if ((tag is 15 or 16 or 18) && major < 51 || tag == 17 && major < 55 ||
                (tag is 19 or 20) && major < 53) return false;
            switch (tag) {
                case 7:
                case 8:
                case 16:
                case 19:
                case 20:
                    if (!IsJavaConstantPoolReference(tags, reference1[index], 1)) return false;
                    break;
                case 9:
                case 10:
                case 11:
                    if (!IsJavaConstantPoolReference(tags, reference1[index], 7) ||
                        !IsJavaConstantPoolReference(tags, reference2[index], 12)) return false;
                    break;
                case 12:
                    if (!IsJavaConstantPoolReference(tags, reference1[index], 1) ||
                        !IsJavaConstantPoolReference(tags, reference2[index], 1)) return false;
                    break;
                case 15:
                    if (!IsJavaMethodHandleReferenceValid(tags, reference1[index], referenceKinds[index], major)) return false;
                    break;
                case 17:
                case 18:
                    if (!IsJavaConstantPoolReference(tags, reference1[index], 12)) return false;
                    break;
            }
        }
        return true;
    }

    private static bool IsJavaMethodHandleReferenceValid(byte[] tags, ushort referenceIndex, byte referenceKind, ushort major) {
        if (referenceIndex == 0 || referenceIndex >= tags.Length) return false;
        byte referenceTag = tags[referenceIndex];
        return referenceKind switch {
            >= 1 and <= 4 => referenceTag == 9,
            5 or 8 => referenceTag == 10,
            6 or 7 => referenceTag == 10 || major >= 52 && referenceTag == 11,
            9 => referenceTag == 11,
            _ => false
        };
    }

    private static bool TrySkipJavaMembers(Stream stream, byte[] constantPoolTags) {
        if (!TryReadJavaU2(stream, out ushort count)) return false;
        for (int index = 0; index < count; index++) {
            if (!TryReadJavaU2(stream, out _) ||
                !TryReadJavaU2(stream, out ushort nameIndex) ||
                !TryReadJavaU2(stream, out ushort descriptorIndex) ||
                !TryReadJavaU2(stream, out ushort attributes) ||
                !IsJavaConstantPoolReference(constantPoolTags, nameIndex, 1) ||
                !IsJavaConstantPoolReference(constantPoolTags, descriptorIndex, 1) ||
                !TrySkipJavaAttributes(stream, constantPoolTags, attributes)) return false;
        }
        return true;
    }

    private static bool TrySkipJavaAttributes(Stream stream, byte[] constantPoolTags) {
        if (!TryReadJavaU2(stream, out ushort count)) return false;
        return TrySkipJavaAttributes(stream, constantPoolTags, count);
    }

    private static bool TrySkipJavaAttributes(Stream stream, byte[] constantPoolTags, ushort count) {
        for (int index = 0; index < count; index++) {
            if (!TryReadJavaU2(stream, out ushort nameIndex) ||
                !TryReadJavaU4(stream, out uint length) ||
                !IsJavaConstantPoolReference(constantPoolTags, nameIndex, 1) ||
                !TrySkipJavaBytes(stream, length)) return false;
        }
        return true;
    }

    private static bool TryReadJavaU2(Stream stream, out ushort value) {
        value = 0;
        int high = stream.ReadByte();
        int low = stream.ReadByte();
        if (high < 0 || low < 0) return false;
        value = (ushort)((high << 8) | low);
        return true;
    }

    private static bool TryReadJavaU4(Stream stream, out uint value) {
        value = 0;
        int b0 = stream.ReadByte();
        int b1 = stream.ReadByte();
        int b2 = stream.ReadByte();
        int b3 = stream.ReadByte();
        if (b0 < 0 || b1 < 0 || b2 < 0 || b3 < 0) return false;
        value = ((uint)b0 << 24) | ((uint)b1 << 16) | ((uint)b2 << 8) | (uint)b3;
        return true;
    }

    private static bool TrySkipJavaBytes(Stream stream, ulong count) {
        if (count > (ulong)(stream.Length - stream.Position)) return false;
        stream.Seek((long)count, SeekOrigin.Current);
        return true;
    }

    private static ushort ReadUInt16BigEndian(ReadOnlySpan<byte> src, int offset)
        => (ushort)((src[offset] << 8) | src[offset + 1]);

    private static uint ReadUInt32(ReadOnlySpan<byte> src, int offset, bool littleEndian) {
        if (littleEndian)
            return (uint)(src[offset] | src[offset + 1] << 8 | src[offset + 2] << 16 | src[offset + 3] << 24);
        return (uint)(src[offset] << 24 | src[offset + 1] << 16 | src[offset + 2] << 8 | src[offset + 3]);
    }
}
