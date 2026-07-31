namespace FileInspectorX;

/// <summary>
/// RIFF container and common image formats (TIFF/GLB) detection.
/// </summary>
internal static partial class Signatures {
    internal static bool TryMatchRiff(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 12) return false;
        if (!src.Slice(0, 4).SequenceEqual("RIFF"u8)) return false;
        var fcc = src.Slice(8, 4);
        if (fcc.SequenceEqual("WAVE"u8)) { result = new ContentTypeDetectionResult { Extension = "wav", MimeType = "audio/wav", Confidence = "High", Reason = "riff:wav" }; return true; }
        if (fcc.SequenceEqual("AVI "u8)) { result = new ContentTypeDetectionResult { Extension = "avi", MimeType = "video/x-msvideo", Confidence = "High", Reason = "riff:avi" }; return true; }
        if (fcc.SequenceEqual("WEBP"u8)) { result = new ContentTypeDetectionResult { Extension = "webp", MimeType = "image/webp", Confidence = "High", Reason = "riff:webp" }; return true; }
        return false;
    }

    internal static bool TryMatchGlb(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 20 || !src.Slice(0, 4).SequenceEqual("glTF"u8)) return false;
        uint version = ReadUInt32LittleEndian(src, 4);
        uint totalLength = ReadUInt32LittleEndian(src, 8);
        uint firstChunkLength = ReadUInt32LittleEndian(src, 12);
        uint firstChunkType = ReadUInt32LittleEndian(src, 16);
        if (version != 2 || totalLength < 20 || (totalLength & 3) != 0 || firstChunkType != 0x4E4F534A ||
            (firstChunkLength & 3) != 0 || firstChunkLength > totalLength - 20)
            return false;
        result = new ContentTypeDetectionResult { Extension = "glb", MimeType = "model/gltf-binary", Confidence = "High", Reason = "glb:v2+json-chunk" };
        return true;
    }

    internal static bool TryMatchTiff(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 8) return false;
        bool littleEndian;
        if (src[0] == 0x49 && src[1] == 0x49) littleEndian = true;
        else if (src[0] == 0x4D && src[1] == 0x4D) littleEndian = false;
        else return false;
        ushort magic = ReadUInt16(src, 2, littleEndian);
        if (magic == 42)
        {
            uint firstIfd = ReadUInt32(src, 4, littleEndian);
            if (firstIfd < 8 || (firstIfd & 1) != 0 || firstIfd + 2L > src.Length) return false;
            result = new ContentTypeDetectionResult { Extension = "tif", MimeType = "image/tiff", Confidence = "High", Reason = littleEndian ? "tiff:le+ifd" : "tiff:be+ifd" };
            return true;
        }
        if (magic != 43 || src.Length < 16) return false;
        if (ReadUInt16(src, 4, littleEndian) != 8 || ReadUInt16(src, 6, littleEndian) != 0) return false;
        ulong firstBigIfd = ReadUInt64(src, 8, littleEndian);
        if (firstBigIfd < 16 || (firstBigIfd & 1) != 0 || firstBigIfd + 8UL > (ulong)src.Length) return false;
        result = new ContentTypeDetectionResult { Extension = "tif", MimeType = "image/tiff", Confidence = "High", Reason = littleEndian ? "bigtiff:le+ifd" : "bigtiff:be+ifd" };
        return true;
    }
}
