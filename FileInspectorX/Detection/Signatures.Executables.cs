namespace FileInspectorX;

/// <summary>
/// Executable formats (ELF, Mach-O) detection.
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
        switch (m) {
            case 0xFEEDFACE: result = new ContentTypeDetectionResult { Extension = "macho", MimeType = "application/x-mach-binary", Confidence = "High", Reason = "macho:be32" }; return true;
            case 0xCEFAEDFE: result = new ContentTypeDetectionResult { Extension = "macho", MimeType = "application/x-mach-binary", Confidence = "High", Reason = "macho:le32" }; return true;
            case 0xFEEDFACF: result = new ContentTypeDetectionResult { Extension = "macho", MimeType = "application/x-mach-binary", Confidence = "High", Reason = "macho:be64" }; return true;
            case 0xCFFAEDFE: result = new ContentTypeDetectionResult { Extension = "macho", MimeType = "application/x-mach-binary", Confidence = "High", Reason = "macho:le64" }; return true;
            case 0xCAFEBABE: result = new ContentTypeDetectionResult { Extension = "macho", MimeType = "application/x-mach-binary", Confidence = "High", Reason = "macho:fat" }; return true;
            case 0xBEBAFECA: result = new ContentTypeDetectionResult { Extension = "macho", MimeType = "application/x-mach-binary", Confidence = "High", Reason = "macho:fat-le" }; return true;
        }
        return false;
    }
}

