namespace FileInspectorX;

/// <summary>
/// Executable formats (ELF, Java class, DEX, Mach-O) detection.
/// </summary>
internal static partial class Signatures {
    internal static bool TryMatchElf(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 6) return false;
        if (!(src[0] == 0x7F && src[1] == (byte)'E' && src[2] == (byte)'L' && src[3] == (byte)'F')) return false;
        var clazz = src[4];
        var endian = src[5];
        string c = clazz == 2 ? "64" : clazz == 1 ? "32" : "?";
        string e = endian == 2 ? "be" : endian == 1 ? "le" : "?";
        string et = ""; string mach = "";
        if (src.Length >= 18) {
            int eTypeOff = 16; ushort etype;
            if (endian == 2 && eTypeOff + 1 < src.Length)
                etype = (ushort)((src[eTypeOff] << 8) | src[eTypeOff + 1]);
            else if (eTypeOff + 1 < src.Length)
                etype = (ushort)(src[eTypeOff] | (src[eTypeOff + 1] << 8));
            else etype = 0;
            et = etype == 1 ? "rel" : etype == 2 ? "exec" : etype == 3 ? "dyn" : etype == 4 ? "core" : "?";
        }
        if (src.Length >= 20) {
            int eMachOff = 18; ushort emach;
            if (endian == 2 && eMachOff + 1 < src.Length)
                emach = (ushort)((src[eMachOff] << 8) | src[eMachOff + 1]);
            else if (eMachOff + 1 < src.Length)
                emach = (ushort)(src[eMachOff] | (src[eMachOff + 1] << 8));
            else emach = 0;
            mach = emach switch {
                3 => "x86", 62 => "x86_64", 40 => "arm", 183 => "aarch64", 8 => "mips", 50 => "ia64", 243 => "riscv", _ => "?"
            };
        }
        var r = $"elf:{c}-{e}" + (et == "" ? "" : $":{et}") + (mach == "" ? "" : $":{mach}");
        result = new ContentTypeDetectionResult { Extension = "elf", MimeType = "application/x-elf", Confidence = "High", Reason = r };
        return true;
    }

    internal static bool TryMatchMachO(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 4) return false;
        uint m = (uint)(src[0] << 24 | src[1] << 16 | src[2] << 8 | src[3]);
        if (m == 0xCAFEBABE || m == 0xBEBAFECA)
            return TryMatchFatMachO(src, littleEndian: m == 0xBEBAFECA, out result);

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
        if (src.Length < 11 || src[0] != 0xCA || src[1] != 0xFE || src[2] != 0xBA || src[3] != 0xBE)
            return false;

        ushort minor = ReadUInt16BigEndian(src, 4);
        ushort major = ReadUInt16BigEndian(src, 6);
        ushort constantPoolCount = ReadUInt16BigEndian(src, 8);
        byte firstTag = src[10];
        if (major < 45 || major > 100 || constantPoolCount < 2 || !IsJavaConstantPoolTag(firstTag))
            return false;

        result = new ContentTypeDetectionResult {
            Extension = "class",
            MimeType = "application/java-vm",
            Confidence = "High",
            Reason = $"java-class:{major}.{minor}"
        };
        return true;
    }

    internal static bool TryMatchDex(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
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

        result = new ContentTypeDetectionResult {
            Extension = "dex",
            MimeType = "application/vnd.android.dex",
            Confidence = "High",
            Reason = $"dex:{version:000}" + (fieldsAreLittleEndian ? string.Empty : ":reverse-endian")
        };
        return true;
    }

    private static bool TryMatchFatMachO(ReadOnlySpan<byte> src, bool littleEndian, out ContentTypeDetectionResult? result) {
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
            if (!IsKnownMachCpuType(cpuType) || offset < directoryEnd || size == 0 || alignmentPower > 31) return false;
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

    private static ushort ReadUInt16BigEndian(ReadOnlySpan<byte> src, int offset)
        => (ushort)((src[offset] << 8) | src[offset + 1]);

    private static uint ReadUInt32(ReadOnlySpan<byte> src, int offset, bool littleEndian) {
        if (littleEndian)
            return (uint)(src[offset] | src[offset + 1] << 8 | src[offset + 2] << 16 | src[offset + 3] << 24);
        return (uint)(src[offset] << 24 | src[offset + 1] << 16 | src[offset + 2] << 8 | src[offset + 3]);
    }
}
