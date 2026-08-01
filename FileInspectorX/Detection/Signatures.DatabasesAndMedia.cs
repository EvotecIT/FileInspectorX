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
        if (primarySequence == 0 || secondarySequence == 0 || major != 1 || minor is < 3 or > 6 ||
            fileType != 0 || fileFormat != 1 || rootCellOffset < 0x20 || hiveBinsSize == 0 || (hiveBinsSize & 0xFFF) != 0 || clustering != 1)
            return false;
        uint checksum = 0;
        for (int offset = 0; offset < 0x1FC; offset += 4) checksum ^= ReadUInt32LittleEndian(src, offset);
        if (checksum == 0) checksum = 1;
        else if (checksum == uint.MaxValue) checksum = 0xFFFFFFFE;
        if (checksum != ReadUInt32LittleEndian(src, 0x1FC)) return false;
        bool dirty = primarySequence != secondarySequence;
        result = new ContentTypeDetectionResult {
            Extension = "hive",
            MimeType = "application/x-windows-registry-hive",
            Confidence = dirty ? "Medium" : "High",
            Reason = dirty ? "registry-hive:base-block:dirty" : "registry-hive:base-block",
            ReasonDetails = dirty ? $"registry-hive:sequence-mismatch={primarySequence}/{secondarySequence};recovery-may-be-required" : null
        };
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
        => TryMatchMinidump(src, src.Length, out result);

    internal static bool TryMatchMinidump(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 32 || !src.Slice(0, 4).SequenceEqual("MDMP"u8)) return false;
        uint version = ReadUInt32LittleEndian(src, 4);
        uint streams = ReadUInt32LittleEndian(src, 8);
        uint directoryRva = ReadUInt32LittleEndian(src, 12);
        if ((version & 0xFFFF) != 0xA793 || streams > 65535 ||
            (streams == 0 ? directoryRva != 0 : directoryRva < 32) ||
            (streams != 0 && completeLength.HasValue && directoryRva + streams * 12L > completeLength.Value)) return false;
        result = new ContentTypeDetectionResult
        {
            Extension = "dmp",
            MimeType = "application/x-ms-minidump",
            Confidence = "High",
            Reason = streams == 0 ? "dmp:minidump-header;empty-directory" : "dmp:minidump-header"
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
    internal static bool TryMatchFtyp(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchFtyp(src, src.Length, out result);

    internal static bool TryMatchFtyp(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 16) return false;
        if (!src.Slice(4, 4).SequenceEqual("ftyp"u8)) return false;
        uint size32 = ReadUInt32BigEndian(src, 0);
        int brandOffset;
        int compatibleOffset;
        ulong boxLength;
        if (size32 == 1)
        {
            if (src.Length < 24) return false;
            boxLength = ReadUInt64(src, 8, littleEndian: false);
            brandOffset = 16;
            compatibleOffset = 24;
            if (boxLength < 24) return false;
        }
        else
        {
            brandOffset = 8;
            compatibleOffset = 16;
            if (size32 == 0)
            {
                if (!completeLength.HasValue || completeLength.Value < 16) return false;
                boxLength = (ulong)completeLength.Value;
            }
            else boxLength = size32;
            if (boxLength < 16) return false;
        }
        if ((boxLength & 3) != 0 || (completeLength.HasValue && boxLength > (ulong)completeLength.Value)) return false;
        var brand = src.Slice(brandOffset, 4);
        ulong compatibilityLength = boxLength - (ulong)compatibleOffset;
        int compatibleBytes = (int)Math.Min(compatibilityLength, (ulong)Math.Max(0, src.Length - compatibleOffset));
        compatibleBytes -= compatibleBytes & 3;
        ReadOnlySpan<byte> comp = compatibleBytes > 0 ? src.Slice(compatibleOffset, compatibleBytes) : ReadOnlySpan<byte>.Empty;
        FtypBrandKind kinds = GetFtypBrandKind(brand);
        for (int offset = 0; offset < comp.Length; offset += 4)
            kinds |= GetFtypBrandKind(comp.Slice(offset, 4)) & ~FtypBrandKind.LegacyHeif;
        bool completeBox = boxLength <= (ulong)src.Length;
        return TryCreateFtypResult(brand, kinds, completeBox, out result);
    }

    /// <summary>
    /// Scans the complete File Type Box from a seekable stream, including compatibility lists larger than the prefix sample.
    /// </summary>
    internal static bool TryMatchFtyp(Stream stream, out ContentTypeDetectionResult? result) {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try {
            if (stream.Length < 16 || !TryReadAt(stream, 0, (int)Math.Min(24, stream.Length), out var headerBytes)) return false;
            var header = new ReadOnlySpan<byte>(headerBytes);
            if (!header.Slice(4, 4).SequenceEqual("ftyp"u8)) return false;
            uint size32 = ReadUInt32BigEndian(header, 0);
            int brandOffset;
            int compatibleOffset;
            ulong boxLength;
            if (size32 == 1) {
                if (header.Length < 24) return false;
                boxLength = ReadUInt64(header, 8, littleEndian: false);
                brandOffset = 16;
                compatibleOffset = 24;
                if (boxLength < 24) return false;
            } else {
                brandOffset = 8;
                compatibleOffset = 16;
                boxLength = size32 == 0 ? (ulong)stream.Length : size32;
                if (boxLength < 16) return false;
            }
            if ((boxLength & 3) != 0 || boxLength > (ulong)stream.Length) return false;
            var brand = header.Slice(brandOffset, 4).ToArray();
            FtypBrandKind kinds = GetFtypBrandKind(brand);
            long remaining = (long)boxLength - compatibleOffset;
            stream.Seek(compatibleOffset, SeekOrigin.Begin);
            var buffer = new byte[4096];
            while (remaining > 0) {
                int batch = (int)Math.Min(buffer.Length, remaining);
                int read = 0;
                while (read < batch) {
                    int current = stream.Read(buffer, read, batch - read);
                    if (current <= 0) return false;
                    read += current;
                }
                var brands = new ReadOnlySpan<byte>(buffer, 0, batch);
                for (int offset = 0; offset < brands.Length; offset += 4)
                    kinds |= GetFtypBrandKind(brands.Slice(offset, 4)) & ~FtypBrandKind.LegacyHeif;
                remaining -= batch;
            }
            return TryCreateFtypResult(brand, kinds, completeBox: true, out result);
        } catch {
            result = null;
            return false;
        } finally {
            try { stream.Seek(originalPosition, SeekOrigin.Begin); } catch { }
        }
    }

    [Flags]
    private enum FtypBrandKind {
        None = 0,
        Avif = 1,
        Heic = 2,
        GenericHeif = 4,
        LegacyHeif = 8,
        QuickTime = 16,
        M4A = 32,
        ThreeGpp = 64,
        Mp4 = 128
    }

    private static FtypBrandKind GetFtypBrandKind(ReadOnlySpan<byte> brand) {
        if (brand.SequenceEqual("avif"u8) || brand.SequenceEqual("avis"u8)) return FtypBrandKind.Avif;
        if (brand.SequenceEqual("heic"u8) || brand.SequenceEqual("heix"u8) ||
            brand.SequenceEqual("hevc"u8) || brand.SequenceEqual("hevx"u8) ||
            brand.SequenceEqual("heim"u8) || brand.SequenceEqual("heis"u8) ||
            brand.SequenceEqual("hevm"u8) || brand.SequenceEqual("hevs"u8)) return FtypBrandKind.Heic;
        if (brand.SequenceEqual("mif1"u8) || brand.SequenceEqual("mif2"u8) || brand.SequenceEqual("msf1"u8)) return FtypBrandKind.GenericHeif;
        if (brand.SequenceEqual("heif"u8)) return FtypBrandKind.LegacyHeif;
        if (brand.SequenceEqual("qt  "u8)) return FtypBrandKind.QuickTime;
        if (brand.SequenceEqual("M4A "u8) || brand.SequenceEqual("M4B "u8) || brand.SequenceEqual("F4A "u8)) return FtypBrandKind.M4A;
        if (brand[0] == (byte)'3' && brand[1] == (byte)'g' && (brand[2] == (byte)'p' || brand[2] == (byte)'2')) return FtypBrandKind.ThreeGpp;
        if (brand.SequenceEqual("isom"u8) || brand.SequenceEqual("iso2"u8) ||
            brand.SequenceEqual("iso3"u8) || brand.SequenceEqual("iso4"u8) ||
            brand.SequenceEqual("iso5"u8) || brand.SequenceEqual("iso6"u8) ||
            brand.SequenceEqual("mp41"u8) || brand.SequenceEqual("mp42"u8) ||
            brand.SequenceEqual("avc1"u8) || brand.SequenceEqual("av01"u8) ||
            brand.SequenceEqual("M4V "u8) || brand.SequenceEqual("MSNV"u8) || brand.SequenceEqual("dash"u8)) return FtypBrandKind.Mp4;
        return FtypBrandKind.None;
    }

    private static bool TryCreateFtypResult(ReadOnlySpan<byte> majorBrand, FtypBrandKind kinds, bool completeBox, out ContentTypeDetectionResult? result) {
        result = null;
        if (!completeBox) {
            if (IsSpecificFtypMajor(majorBrand) &&
                TryCreateFtypResult(majorBrand, GetFtypBrandKind(majorBrand), completeBox: true, out result) &&
                result != null) {
                result.Confidence = "Medium";
                result.Reason += ";sampled-compatible-brands";
                return true;
            }
            result = new ContentTypeDetectionResult {
                Extension = "isobmff",
                MimeType = "application/octet-stream",
                Confidence = "Medium",
                Reason = "ftyp:sampled-compatible-brands",
                ReasonDetails = "major-brand=" + System.Text.Encoding.ASCII.GetString(majorBrand.ToArray())
            };
            return true;
        }
        if ((kinds & FtypBrandKind.Avif) != 0)
            result = new ContentTypeDetectionResult { Extension = "avif", MimeType = "image/avif", Confidence = "High", Reason = "ftyp:avif" };
        else if ((kinds & FtypBrandKind.Heic) != 0)
            result = new ContentTypeDetectionResult { Extension = "heic", MimeType = "image/heic", Confidence = "High", Reason = "ftyp:heif" };
        else if ((kinds & FtypBrandKind.GenericHeif) != 0)
            result = new ContentTypeDetectionResult { Extension = "heif", MimeType = "image/heif", Confidence = "High", Reason = "ftyp:heif-generic" };
        else if ((kinds & FtypBrandKind.LegacyHeif) != 0)
            result = new ContentTypeDetectionResult { Extension = "heif", MimeType = "image/heif", Confidence = "Medium", Reason = "ftyp:heif-legacy-brand" };
        else if ((kinds & FtypBrandKind.QuickTime) != 0)
            result = new ContentTypeDetectionResult { Extension = "mov", MimeType = "video/quicktime", Confidence = "High", Reason = "ftyp:quicktime" };
        else if ((kinds & FtypBrandKind.M4A) != 0)
            result = new ContentTypeDetectionResult { Extension = "m4a", MimeType = "audio/mp4", Confidence = "High", Reason = "ftyp:m4a" };
        else if ((kinds & FtypBrandKind.ThreeGpp) != 0)
            result = new ContentTypeDetectionResult { Extension = "3gp", MimeType = "video/3gpp", Confidence = "High", Reason = "ftyp:3gp" };
        else if ((kinds & FtypBrandKind.Mp4) != 0)
            result = new ContentTypeDetectionResult { Extension = "mp4", MimeType = "video/mp4", Confidence = "High", Reason = "ftyp:mp4" };
        else
            result = new ContentTypeDetectionResult {
                Extension = "isobmff",
                MimeType = "application/octet-stream",
                Confidence = "Medium",
                Reason = "ftyp:unknown-brand",
                ReasonDetails = "major-brand=" + System.Text.Encoding.ASCII.GetString(majorBrand.ToArray())
            };
        return true;
    }

    private static bool IsSpecificFtypMajor(ReadOnlySpan<byte> brand)
        => brand.SequenceEqual("avif"u8) || brand.SequenceEqual("avis"u8) ||
           brand.SequenceEqual("heic"u8) || brand.SequenceEqual("heix"u8) ||
           brand.SequenceEqual("hevc"u8) || brand.SequenceEqual("hevx"u8) ||
           brand.SequenceEqual("heim"u8) || brand.SequenceEqual("heis"u8) ||
           brand.SequenceEqual("hevm"u8) || brand.SequenceEqual("hevs"u8) ||
           brand.SequenceEqual("heif"u8) || brand.SequenceEqual("qt  "u8) ||
           brand.SequenceEqual("M4A "u8) || brand.SequenceEqual("M4B "u8) || brand.SequenceEqual("F4A "u8) ||
           (brand[0] == (byte)'3' && brand[1] == (byte)'g' && (brand[2] == (byte)'p' || brand[2] == (byte)'2')) ||
           brand.SequenceEqual("mp41"u8) || brand.SequenceEqual("mp42"u8) ||
           brand.SequenceEqual("avc1"u8) || brand.SequenceEqual("M4V "u8) ||
           brand.SequenceEqual("MSNV"u8) || brand.SequenceEqual("dash"u8);
}
