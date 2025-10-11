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
        if (src.Length < 4) return false;
        if (src.Slice(0, 4).SequenceEqual("glTF"u8)) { result = new ContentTypeDetectionResult { Extension = "glb", MimeType = "model/gltf-binary", Confidence = "High", Reason = "glb" }; return true; }
        return false;
    }

    internal static bool TryMatchTiff(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 4) return false;
        if (src[0] == 0x49 && src[1] == 0x49 && src[2] == 0x2A && src[3] == 0x00) { result = new ContentTypeDetectionResult { Extension = "tif", MimeType = "image/tiff", Confidence = "High", Reason = "tiff:le" }; return true; }
        if (src[0] == 0x4D && src[1] == 0x4D && src[2] == 0x00 && (src[3] == 0x2A || src[3] == 0x2B)) { result = new ContentTypeDetectionResult { Extension = "tif", MimeType = "image/tiff", Confidence = "High", Reason = src[3] == 0x2B ? "tiff:be64" : "tiff:be" }; return true; }
        return false;
    }
}

