namespace FileInspectorX;

/// <summary>
/// Executable formats (ELF, Java class, DEX, Mach-O) detection.
/// </summary>
internal static partial class Signatures {
    internal static bool TryMatchElf(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
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
        ushort declaredHeaderSize = ReadUInt16(src, headerSizeOffset, littleEndian);
        ushort programEntrySize = ReadUInt16(src, programEntrySizeOffset, littleEndian);
        ushort programCount = ReadUInt16(src, programCountOffset, littleEndian);
        ushort sectionEntrySize = ReadUInt16(src, sectionEntrySizeOffset, littleEndian);
        ushort sectionCount = ReadUInt16(src, sectionCountOffset, littleEndian);
        bool knownType = etype <= 4 || etype is >= 0xFE00 and <= 0xFEFF || etype >= 0xFF00;
        if (!knownType || version != 1 || declaredHeaderSize != headerSize) return false;
        if (programCount > 0 && programEntrySize != (clazz == 1 ? 32 : 56)) return false;
        if (sectionCount > 0 && sectionEntrySize != (clazz == 1 ? 40 : 64)) return false;

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

    internal static bool TryMatchMachO(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchMachO(src, src.Length, out result);

    internal static bool TryMatchMachO(ReadOnlySpan<byte> src, long? totalLength, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 4) return false;
        uint m = (uint)(src[0] << 24 | src[1] << 16 | src[2] << 8 | src[3]);
        if (m == 0xCAFEBABE || m == 0xBEBAFECA)
            return TryMatchFatMachO(src, littleEndian: m == 0xBEBAFECA, totalLength, out result);

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

        if (!IsKnownMachCpuType(cpuType) || fileType < 1 || fileType > 12) return false;
        if ((commandBytes % commandAlignment) != 0) return false;
        if (commandCount == 0) {
            if (commandBytes != 0) return false;
        } else if (commandBytes / 8 < commandCount) {
            return false;
        }
        if (totalLength.HasValue && (ulong)headerSize + commandBytes > (ulong)totalLength.Value) return false;

        result = new ContentTypeDetectionResult {
            Extension = "macho",
            MimeType = "application/x-mach-binary",
            Confidence = "High",
            Reason = reason
        };
        return true;
    }

    internal static bool TryMatchJavaClass(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 10 || src[0] != 0xCA || src[1] != 0xFE || src[2] != 0xBA || src[3] != 0xBE)
            return false;

        ushort minor = ReadUInt16BigEndian(src, 4);
        ushort major = ReadUInt16BigEndian(src, 6);
        ushort constantPoolCount = ReadUInt16BigEndian(src, 8);
        if (major < 45 || major > 100 || constantPoolCount < 2) return false;

        var constantPoolTags = new byte[constantPoolCount];
        int cursor = 10;
        for (int index = 1; index < constantPoolCount; index++)
        {
            if (cursor >= src.Length) return false;
            byte tag = src[cursor++];
            if (!IsJavaConstantPoolTag(tag)) return false;
            constantPoolTags[index] = tag;
            int payloadLength;
            if (tag == 1)
            {
                if (cursor + 2 > src.Length) return false;
                payloadLength = 2 + ReadUInt16BigEndian(src, cursor);
            }
            else
            {
                payloadLength = tag switch {
                    3 or 4 or 9 or 10 or 11 or 12 or 17 or 18 => 4,
                    5 or 6 => 8,
                    7 or 8 or 16 or 19 or 20 => 2,
                    15 => 3,
                    _ => 0
                };
            }
            if (payloadLength == 0 || payloadLength > src.Length - cursor) return false;
            cursor += payloadLength;
            if (tag is 5 or 6)
            {
                if (++index >= constantPoolCount) return false;
            }
        }

        if (cursor + 8 > src.Length) return false;
        ushort thisClass = ReadUInt16BigEndian(src, cursor + 2);
        ushort superClass = ReadUInt16BigEndian(src, cursor + 4);
        ushort interfaceCount = ReadUInt16BigEndian(src, cursor + 6);
        cursor += 8;
        if (!IsJavaConstantPoolReference(constantPoolTags, thisClass, 7) ||
            (superClass != 0 && !IsJavaConstantPoolReference(constantPoolTags, superClass, 7)) ||
            interfaceCount > (src.Length - cursor) / 2) return false;
        for (int index = 0; index < interfaceCount; index++)
        {
            ushort interfaceClass = ReadUInt16BigEndian(src, cursor);
            cursor += 2;
            if (!IsJavaConstantPoolReference(constantPoolTags, interfaceClass, 7)) return false;
        }
        if (!TrySkipJavaMembers(src, ref cursor, constantPoolTags) ||
            !TrySkipJavaMembers(src, ref cursor, constantPoolTags) ||
            !TrySkipJavaAttributes(src, ref cursor, constantPoolTags) || cursor != src.Length) return false;

        result = new ContentTypeDetectionResult {
            Extension = "class",
            MimeType = "application/java-vm",
            Confidence = "High",
            Reason = $"java-class:{major}.{minor}"
        };
        return true;
    }

    internal static bool TryMatchDex(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchDex(src, src.Length, out result);

    internal static bool TryMatchDex(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 0x70 || src[0] != (byte)'d' || src[1] != (byte)'e' || src[2] != (byte)'x' ||
            src[3] != (byte)'\n' || src[7] != 0 ||
            src[4] < (byte)'0' || src[4] > (byte)'9' ||
            src[5] < (byte)'0' || src[5] > (byte)'9' ||
            src[6] < (byte)'0' || src[6] > (byte)'9')
            return false;

        int version = (src[4] - (byte)'0') * 100 + (src[5] - (byte)'0') * 10 + src[6] - (byte)'0';
        if (version < 35 || version > 41) return false;

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

        result = new ContentTypeDetectionResult {
            Extension = "dex",
            MimeType = "application/vnd.android.dex",
            Confidence = "High",
            Reason = $"dex:{version:000}" + (fieldsAreLittleEndian ? string.Empty : ":reverse-endian")
        };
        return true;
    }

    private static bool TryMatchFatMachO(ReadOnlySpan<byte> src, bool littleEndian, long? totalLength, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 28) return false;

        uint architectureCount = ReadUInt32(src, 4, littleEndian);
        if (architectureCount < 1 || architectureCount > 64) return false;
        long directoryEnd = 8L + architectureCount * 20L;
        if (directoryEnd > src.Length) return false;

        for (uint i = 0; i < architectureCount; i++) {
            int entryOffset = checked(8 + (int)i * 20);
            uint cpuType = ReadUInt32(src, entryOffset, littleEndian);
            uint offset = ReadUInt32(src, entryOffset + 8, littleEndian);
            uint size = ReadUInt32(src, entryOffset + 12, littleEndian);
            uint alignmentPower = ReadUInt32(src, entryOffset + 16, littleEndian);
            if (!IsKnownMachCpuType(cpuType) || offset < directoryEnd || size == 0 || alignmentPower > 31 ||
                (totalLength.HasValue && (ulong)offset + size > (ulong)totalLength.Value)) return false;
            uint alignment = 1u << (int)alignmentPower;
            if ((offset & (alignment - 1)) != 0) return false;
        }

        result = new ContentTypeDetectionResult {
            Extension = "macho",
            MimeType = "application/x-mach-binary",
            Confidence = "High",
            Reason = littleEndian ? "macho:fat-le" : "macho:fat"
        };
        return true;
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

    private static bool TrySkipJavaMembers(ReadOnlySpan<byte> src, ref int cursor, byte[] constantPoolTags)
    {
        if (cursor + 2 > src.Length) return false;
        ushort count = ReadUInt16BigEndian(src, cursor);
        cursor += 2;
        for (int index = 0; index < count; index++)
        {
            if (cursor + 8 > src.Length) return false;
            ushort nameIndex = ReadUInt16BigEndian(src, cursor + 2);
            ushort descriptorIndex = ReadUInt16BigEndian(src, cursor + 4);
            ushort attributes = ReadUInt16BigEndian(src, cursor + 6);
            cursor += 8;
            if (!IsJavaConstantPoolReference(constantPoolTags, nameIndex, 1) ||
                !IsJavaConstantPoolReference(constantPoolTags, descriptorIndex, 1) ||
                !TrySkipJavaAttributes(src, ref cursor, constantPoolTags, attributes)) return false;
        }
        return true;
    }

    private static bool TrySkipJavaAttributes(ReadOnlySpan<byte> src, ref int cursor, byte[] constantPoolTags)
    {
        if (cursor + 2 > src.Length) return false;
        ushort count = ReadUInt16BigEndian(src, cursor);
        cursor += 2;
        return TrySkipJavaAttributes(src, ref cursor, constantPoolTags, count);
    }

    private static bool TrySkipJavaAttributes(ReadOnlySpan<byte> src, ref int cursor, byte[] constantPoolTags, ushort count)
    {
        for (int index = 0; index < count; index++)
        {
            if (cursor + 6 > src.Length) return false;
            ushort nameIndex = ReadUInt16BigEndian(src, cursor);
            uint length = ReadUInt32(src, cursor + 2, littleEndian: false);
            cursor += 6;
            if (!IsJavaConstantPoolReference(constantPoolTags, nameIndex, 1) || length > src.Length - cursor) return false;
            cursor += (int)length;
        }
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
