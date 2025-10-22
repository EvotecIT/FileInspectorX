namespace FileInspectorX;

/// <summary>
/// Database/media container signatures (SQLite, MP4/HEIF ftyp box family).
/// </summary>
internal static partial class Signatures {
    internal static bool TryMatchEvtx(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        // Windows Event Log (EVTX) header starts with "ElfFile\0"
        if (src.Length >= 8 && src[0] == (byte)'E' && src[1] == (byte)'l' && src[2] == (byte)'f' && src[3] == (byte)'F' && src[4] == (byte)'i' && src[5] == (byte)'l' && src[6] == (byte)'e') {
            result = new ContentTypeDetectionResult { Extension = "evtx", MimeType = "application/vnd.ms-windows.evtx", Confidence = "High", Reason = "evtx:ElfFile" };
            return true;
        }
        return false;
    }
    internal static bool TryMatchSqlite(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        var sig = System.Text.Encoding.ASCII.GetBytes("SQLite format 3\x00");
        if (src.Length >= sig.Length && src.Slice(0, sig.Length).SequenceEqual(sig)) {
            result = new ContentTypeDetectionResult { Extension = "sqlite", MimeType = "application/vnd.sqlite3", Confidence = "High", Reason = "sqlite" };
            return true;
        }
        return false;
    }

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
