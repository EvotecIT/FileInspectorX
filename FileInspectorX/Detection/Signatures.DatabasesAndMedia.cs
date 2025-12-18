namespace FileInspectorX;

/// <summary>
/// Database/media container signatures (SQLite, MP4/HEIF ftyp box family).
/// </summary>
internal static partial class Signatures {
    /// <summary>
    /// Recognizes Windows registry hive files.
    /// </summary>
    internal static bool TryMatchRegistryHive(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        // Windows registry hive files begin with ASCII 'regf'
        if (src.Length >= 4 && src[0] == (byte)'r' && src[1] == (byte)'e' && src[2] == (byte)'g' && src[3] == (byte)'f')
        {
            result = new ContentTypeDetectionResult { Extension = "hive", MimeType = "application/x-windows-registry-hive", Confidence = "High", Reason = "regf" };
            return true;
        }
        return false;
    }

    /// <summary>
    /// Recognizes Group Policy Registry.pol files by header ("PReg" + version).
    /// Format: 4-byte ASCII signature "PReg" followed by a little-endian DWORD version (commonly 1).
    /// </summary>
    internal static bool TryMatchRegistryPol(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        const int POL_SIGNATURE_LEN = 4;
        const int POL_VERSION_OFFSET = 4;
        const uint POL_VERSION_SUPPORTED = 1;

        // Registry.pol begins with ASCII "PReg" followed by a 32-bit LE version.
        if (src.Length < POL_VERSION_OFFSET + sizeof(uint)) return false;
        if (!src.Slice(0, POL_SIGNATURE_LEN).SequenceEqual("PReg"u8)) return false;

        // Version is little-endian DWORD at offset 4
        uint version = (uint)(src[POL_VERSION_OFFSET] | (src[POL_VERSION_OFFSET + 1] << 8) | (src[POL_VERSION_OFFSET + 2] << 16) | (src[POL_VERSION_OFFSET + 3] << 24));
        if (version != POL_VERSION_SUPPORTED) return false;

        result = new ContentTypeDetectionResult
        {
            Extension = "pol",
            MimeType = "application/x-group-policy-registry-pol",
            Confidence = "High",
            Reason = "gpo:registry-pol",
            ReasonDetails = $"pol:version={version}"
        };
        return true;
    }

    /// <summary>
    /// Recognizes Microsoft Extensible Storage Engine (ESE/JET Blue) databases (e.g., .edb, .dit).
    /// </summary>
    internal static bool TryMatchEse(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        // Extensible Storage Engine (JET Blue) database files (edb/dit) typically start with 0xEF 0xCD 0xAB 0x89
        if (src.Length >= 4 && src[0] == 0xEF && src[1] == 0xCD && src[2] == 0xAB && src[3] == 0x89)
        {
            result = new ContentTypeDetectionResult { Extension = "edb", MimeType = "application/x-ese-database", Confidence = "High", Reason = "ese:header" };
            return true;
        }
        return false;
    }
    /// <summary>
    /// Recognizes Windows Event Log (EVTX) files by header.
    /// </summary>
    /// <param name="src"></param>
    /// <param name="result"></param>
    /// <returns></returns>
    internal static bool TryMatchEvtx(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        // Windows Event Log (EVTX) header starts with "ElfFile\0"
        if (src.Length >= 8 && src[0] == (byte)'E' && src[1] == (byte)'l' && src[2] == (byte)'f' && src[3] == (byte)'F' && src[4] == (byte)'i' && src[5] == (byte)'l' && src[6] == (byte)'e') {
            result = new ContentTypeDetectionResult { Extension = "evtx", MimeType = "application/vnd.ms-windows.evtx", Confidence = "High", Reason = "evtx:ElfFile" };
            return true;
        }
        return false;
    }
    /// <summary>
    /// Recognizes SQLite database files by header.
    /// </summary>
    internal static bool TryMatchSqlite(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        var sig = System.Text.Encoding.ASCII.GetBytes("SQLite format 3\x00");
        if (src.Length >= sig.Length && src.Slice(0, sig.Length).SequenceEqual(sig)) {
            result = new ContentTypeDetectionResult { Extension = "sqlite", MimeType = "application/vnd.sqlite3", Confidence = "High", Reason = "sqlite" };
            return true;
        }
        return false;
    }

    /// <summary>
    /// Recognizes KeePass KDBX 3/4 databases via 16-byte magic sequence.
    /// </summary>
    internal static bool TryMatchKeePassKdbx(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        // KDBX signature consists of two 32-bit words followed by a format/version pair.
        // KDBX 3.x: 0x9AA2D903, 0xB54BFB67; KDBX 4.x: 0x9AA2D903, 0xB54BFB67 (same first two words),
        // next two 32-bit values differ but are not required for coarse detection.
        if (src.Length >= 8)
        {
            uint w0 = (uint)(src[0] | (src[1] << 8) | (src[2] << 16) | (src[3] << 24));
            uint w1 = (uint)(src[4] | (src[5] << 8) | (src[6] << 16) | (src[7] << 24));
            if (w0 == 0x9AA2D903 && w1 == 0xB54BFB67)
            {
                result = new ContentTypeDetectionResult { Extension = "kdbx", MimeType = "application/x-keepass-kdbx", Confidence = "High", Reason = "kdbx:magic" };
                return true;
            }
        }
        return false;
    }
    /// <summary>
    /// Recognizes MP4/HEIF family files by 'ftyp' box and brand identifiers.
    /// </summary>
    /// <param name="src"></param>
    /// <param name="result"></param>
    /// <returns></returns>
    internal static bool TryMatchFtyp(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 12) return false;
        if (!src.Slice(4, 4).SequenceEqual("ftyp"u8)) return false;
        var brand = src.Slice(8, 4);
        ReadOnlySpan<byte> comp = src.Length >= 20 ? src.Slice(16, Math.Min(8, src.Length - 16)) : ReadOnlySpan<byte>.Empty;
        static bool HasBrand(ReadOnlySpan<byte> major, ReadOnlySpan<byte> compat, ReadOnlySpan<byte> sought) {
            if (major.SequenceEqual(sought)) return true;
            for (int i = 0; i + 4 <= compat.Length; i += 4)
                if (compat.Slice(i, 4).SequenceEqual(sought)) return true;
            return false;
        }
        if (brand.SequenceEqual("heic"u8) || brand.SequenceEqual("heif"u8) || HasBrand(brand, comp, "mif1"u8) || brand.SequenceEqual("hevc"u8)) {
            result = new ContentTypeDetectionResult { Extension = "heic", MimeType = "image/heic", Confidence = "High", Reason = "ftyp:heif" };
            return true;
        }
        if (HasBrand(brand, comp, "isom"u8) || HasBrand(brand, comp, "iso2"u8) || HasBrand(brand, comp, "mp41"u8) || HasBrand(brand, comp, "mp42"u8) || HasBrand(brand, comp, "MSNV"u8)) {
            result = new ContentTypeDetectionResult { Extension = "mp4", MimeType = "video/mp4", Confidence = "High", Reason = "ftyp:mp4" };
            return true;
        }
        if (HasBrand(brand, comp, "M4A "u8) || HasBrand(brand, comp, "M4B "u8)) {
            result = new ContentTypeDetectionResult { Extension = "m4a", MimeType = "audio/mp4", Confidence = "High", Reason = "ftyp:m4a" };
            return true;
        }
        if (HasBrand(brand, comp, "3gp4"u8) || HasBrand(brand, comp, "3g2a"u8)) {
            result = new ContentTypeDetectionResult { Extension = "3gp", MimeType = "video/3gpp", Confidence = "High", Reason = "ftyp:3gp" };
            return true;
        }
        result = new ContentTypeDetectionResult { Extension = "mp4", MimeType = "video/mp4", Confidence = "High", Reason = "ftyp:mp4" };
        return true;
    }
}
