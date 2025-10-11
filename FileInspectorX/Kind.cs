namespace FileInspectorX;

/// <summary>
/// Broad content category used to quickly route files based on type.
/// </summary>
public enum ContentKind {
    Unknown,
    Text,
    Image,
    Archive,
    Executable,
    Document,
    Audio,
    Video,
    Model,
    Database,
}

/// <summary>
/// Helpers for mapping a detection result onto a <see cref="ContentKind"/>.
/// </summary>
public static class KindClassifier {
    public static ContentKind Classify(ContentTypeDetectionResult? r) {
        if (r is null) return ContentKind.Unknown;
        var mime = r.MimeType?.ToLowerInvariant() ?? string.Empty;
        var ext = (r.Extension ?? string.Empty).ToLowerInvariant();

        if (mime.StartsWith("text/") || InspectHelpers.IsText(r)) return ContentKind.Text;
        if (mime.StartsWith("image/") || InspectHelpers.IsImage(r)) return ContentKind.Image;
        if (mime.StartsWith("audio/")) return ContentKind.Audio;
        if (mime.StartsWith("video/")) return ContentKind.Video;
        if (mime.Contains("zip") || mime.Contains("tar") || mime.Contains("gzip") || InspectHelpers.IsArchive(r)) return ContentKind.Archive;
        if (ext is "elf" or "exe" or "dll" or "macho") return ContentKind.Executable;
        if (ext is "docx" or "xlsx" or "pptx" or "pdf" or "rtf" or "eml") return ContentKind.Document;
        if (ext is "gltf" or "glb") return ContentKind.Model;
        if (ext is "sqlite") return ContentKind.Database;
        return ContentKind.Unknown;
    }
}