namespace FileInspectorX;

/// <summary>
/// Convenience predicates for common content families; these are conservative and rely on detected MIME/extension.
/// </summary>
public static class InspectHelpers {
    /// <summary>
    /// Determines if the detected content type represents an image file.
    /// </summary>
    /// <param name="r"></param>
    /// <returns></returns>
    public static bool IsImage(ContentTypeDetectionResult? r) {
        if (r is null) return false;
        if (!string.IsNullOrEmpty(r.MimeType) && r.MimeType.StartsWith("image/", StringComparison.OrdinalIgnoreCase)) return true;
        var ext = (r.Extension ?? string.Empty).ToLowerInvariant();
        return ext is "png" or "jpg" or "jpeg" or "gif" or "webp" or "bmp" or "tif" or "tiff" or "heic";
    }

    /// <summary>
    /// Determines if the detected content type represents an archive file.
    /// </summary>
    /// <param name="r"></param>
    /// <returns></returns>
    public static bool IsArchive(ContentTypeDetectionResult? r) {
        if (r is null) return false;
        var mime = r.MimeType ?? string.Empty;
        if (mime.Contains("zip") || mime.Contains("tar") || mime.Contains("gzip")) return true;
        var ext = (r.Extension ?? string.Empty).ToLowerInvariant();
        return ext is "zip" or "7z" or "rar" or "tar" or "gz" or "bz2" or "xz" or "iso";
    }

    /// <summary>
    /// Determines if the detected content type represents a text file.
    /// </summary>
    /// <param name="r"></param>
    /// <returns></returns>
    public static bool IsText(ContentTypeDetectionResult? r) {
        if (r is null) return false;
        var mime = r.MimeType ?? string.Empty;
        if (mime.StartsWith("text/", StringComparison.OrdinalIgnoreCase)) return true;
        var ext = (r.Extension ?? string.Empty).ToLowerInvariant();
        return ext is "txt" or "json" or "xml" or "html" or "csv" or "tsv" or "yml" or "yaml" or "ini" or "inf" or "admx" or "adml" or "log" or "rtf" or "eml" or "ndjson" or "jsonl" or "toml" or
               "ps1" or "psm1" or "psd1" or "vbs" or "vbe" or "wsf" or "wsh" or "js" or "jse" or "mjs" or "cjs" or "sh" or "bash" or "zsh" or "bat" or "cmd" or "py" or "pyw" or "rb" or "pl" or "lua";
    }
}
