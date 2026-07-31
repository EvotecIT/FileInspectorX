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
        if (src.Length < 4096 || !src.Slice(0, 4).SequenceEqual("regf"u8)) return false;
        uint primarySequence = ReadUInt32LittleEndian(src, 4);
        uint secondarySequence = ReadUInt32LittleEndian(src, 8);
        uint major = ReadUInt32LittleEndian(src, 20);
        uint minor = ReadUInt32LittleEndian(src, 24);
        uint fileType = ReadUInt32LittleEndian(src, 28);
        uint fileFormat = ReadUInt32LittleEndian(src, 32);
        uint rootCellOffset = ReadUInt32LittleEndian(src, 36);
        uint hiveBinsSize = ReadUInt32LittleEndian(src, 40);
        uint clustering = ReadUInt32LittleEndian(src, 44);
        if (primarySequence != secondarySequence || primarySequence == 0 || major != 1 || minor is < 3 or > 6 ||
            fileType != 0 || fileFormat != 1 || rootCellOffset < 0x20 || hiveBinsSize == 0 || (hiveBinsSize & 0xFFF) != 0 || clustering != 1)
            return false;
        uint checksum = 0;
        for (int offset = 0; offset < 0x1FC; offset += 4) checksum ^= ReadUInt32LittleEndian(src, offset);
        if (checksum != ReadUInt32LittleEndian(src, 0x1FC)) return false;
        result = new ContentTypeDetectionResult { Extension = "hive", MimeType = "application/x-windows-registry-hive", Confidence = "High", Reason = "registry-hive:base-block" };
        return true;
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
            result = new ContentTypeDetectionResult { Extension = "edb", MimeType = "application/x-ese-database", Confidence = "Medium", Reason = "ese:magic-only" };
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
        if (src.Length < 128 || !src.Slice(0, 8).SequenceEqual(new byte[] { (byte)'E', (byte)'l', (byte)'f', (byte)'F', (byte)'i', (byte)'l', (byte)'e', 0 })) return false;
        uint headerSize = ReadUInt32LittleEndian(src, 0x20);
        ushort minor = ReadUInt16LittleEndian(src, 0x24);
        ushort major = ReadUInt16LittleEndian(src, 0x26);
        ushort blockSize = ReadUInt16LittleEndian(src, 0x28);
        ushort chunkCount = ReadUInt16LittleEndian(src, 0x2A);
        if (headerSize != 128 || major != 3 || minor != 1 || blockSize != 4096 || chunkCount == 0) return false;
        result = new ContentTypeDetectionResult { Extension = "evtx", MimeType = "application/vnd.ms-windows.evtx", Confidence = "High", Reason = "evtx:file-header" };
        return true;
    }

    /// <summary>
    /// Recognizes Windows minidump files by the standard "MDMP" signature.
    /// </summary>
    internal static bool TryMatchMinidump(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 32 || !src.Slice(0, 4).SequenceEqual("MDMP"u8)) return false;
        uint version = ReadUInt32LittleEndian(src, 4);
        uint streams = ReadUInt32LittleEndian(src, 8);
        uint directoryRva = ReadUInt32LittleEndian(src, 12);
        if ((version & 0xFFFF) != 0xA793 || streams is < 1 or > 65535 || directoryRva < 32 || directoryRva + streams * 12L > src.Length) return false;
        result = new ContentTypeDetectionResult
        {
            Extension = "dmp",
            MimeType = "application/x-ms-minidump",
            Confidence = "High",
            Reason = "dmp:minidump-header"
        };
        return true;
    }

    /// <summary>
    /// Recognizes protected Windows crash dumps generated by WER for protected processes.
    /// These files do not start with "MDMP" but have a stable 64-byte binary header in real samples.
    /// </summary>
    internal static bool TryMatchProtectedDump(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        ReadOnlySpan<byte> signature = stackalloc byte[]
        {
            0xF3, 0x0E, 0x3E, 0xA1, 0x71, 0xD5, 0xAF, 0x4E,
            0x9F, 0xBB, 0xF8, 0x0D, 0x0B, 0x19, 0xA3, 0xC0,
            0x6A, 0x1C, 0x50, 0x10, 0xE1, 0x7A, 0xD4, 0x4B,
            0x8D, 0x2F, 0x12, 0x78, 0x3C, 0x02, 0x74, 0x82
        };

        if (src.Length < 0x40) return false;
        if (!src.Slice(0, signature.Length).SequenceEqual(signature)) return false;

        static bool MatchesLe32(ReadOnlySpan<byte> data, int offset, uint value)
            => data[offset] == (byte)(value & 0xFF)
            && data[offset + 1] == (byte)((value >> 8) & 0xFF)
            && data[offset + 2] == (byte)((value >> 16) & 0xFF)
            && data[offset + 3] == (byte)((value >> 24) & 0xFF);

        if (!MatchesLe32(src, 0x20, 2)) return false;
        if (!MatchesLe32(src, 0x24, 0x40)) return false;
        if (!MatchesLe32(src, 0x30, 0x21B)) return false;
        if (!MatchesLe32(src, 0x34, 0x200)) return false;
        if (!MatchesLe32(src, 0x38, 0x20)) return false;

        result = new ContentTypeDetectionResult
        {
            Extension = "dmp",
            MimeType = "application/x-ms-protected-dump",
            Confidence = "High",
            Reason = "dmp:protected"
        };
        return true;
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
        if (src.Length < 16) return false;
        if (!src.Slice(4, 4).SequenceEqual("ftyp"u8)) return false;
        uint boxLength = ReadUInt32BigEndian(src, 0);
        if (boxLength < 16 || (boxLength & 3) != 0 || boxLength > src.Length) return false;
        var brand = src.Slice(8, 4);
        ReadOnlySpan<byte> comp = boxLength > 16 ? src.Slice(16, checked((int)boxLength - 16)) : ReadOnlySpan<byte>.Empty;
        static bool HasBrand(ReadOnlySpan<byte> major, ReadOnlySpan<byte> compat, ReadOnlySpan<byte> sought) {
            if (major.SequenceEqual(sought)) return true;
            for (int i = 0; i + 4 <= compat.Length; i += 4)
                if (compat.Slice(i, 4).SequenceEqual(sought)) return true;
            return false;
        }

        if (HasBrand(brand, comp, "avif"u8) || HasBrand(brand, comp, "avis"u8)) {
            result = new ContentTypeDetectionResult { Extension = "avif", MimeType = "image/avif", Confidence = "High", Reason = "ftyp:avif" };
            return true;
        }
        if (HasBrand(brand, comp, "heic"u8) || HasBrand(brand, comp, "heix"u8) ||
            HasBrand(brand, comp, "hevc"u8) || HasBrand(brand, comp, "hevx"u8) ||
            HasBrand(brand, comp, "heim"u8) || HasBrand(brand, comp, "heis"u8) ||
            HasBrand(brand, comp, "hevm"u8) || HasBrand(brand, comp, "hevs"u8)) {
            result = new ContentTypeDetectionResult { Extension = "heic", MimeType = "image/heic", Confidence = "High", Reason = "ftyp:heif" };
            return true;
        }
        if (HasBrand(brand, comp, "qt  "u8)) {
            result = new ContentTypeDetectionResult { Extension = "mov", MimeType = "video/quicktime", Confidence = "High", Reason = "ftyp:quicktime" };
            return true;
        }
        if (HasBrand(brand, comp, "M4A "u8) || HasBrand(brand, comp, "M4B "u8) || HasBrand(brand, comp, "F4A "u8)) {
            result = new ContentTypeDetectionResult { Extension = "m4a", MimeType = "audio/mp4", Confidence = "High", Reason = "ftyp:m4a" };
            return true;
        }
        if ((brand[0] == (byte)'3' && brand[1] == (byte)'g' && (brand[2] == (byte)'p' || brand[2] == (byte)'2')) ||
            HasBrand(brand, comp, "3gp4"u8) || HasBrand(brand, comp, "3g2a"u8)) {
            result = new ContentTypeDetectionResult { Extension = "3gp", MimeType = "video/3gpp", Confidence = "High", Reason = "ftyp:3gp" };
            return true;
        }
        if (HasBrand(brand, comp, "isom"u8) || HasBrand(brand, comp, "iso2"u8) ||
            HasBrand(brand, comp, "iso3"u8) || HasBrand(brand, comp, "iso4"u8) ||
            HasBrand(brand, comp, "iso5"u8) || HasBrand(brand, comp, "iso6"u8) ||
            HasBrand(brand, comp, "mp41"u8) || HasBrand(brand, comp, "mp42"u8) ||
            HasBrand(brand, comp, "MSNV"u8) || HasBrand(brand, comp, "dash"u8)) {
            result = new ContentTypeDetectionResult { Extension = "mp4", MimeType = "video/mp4", Confidence = "High", Reason = "ftyp:mp4" };
            return true;
        }

        result = new ContentTypeDetectionResult {
            Extension = "isobmff",
            MimeType = "application/octet-stream",
            Confidence = "Medium",
            Reason = "ftyp:unknown-brand",
            ReasonDetails = "major-brand=" + System.Text.Encoding.ASCII.GetString(brand.ToArray())
        };
        return true;
    }
}
