namespace FileInspectorX;

/// <summary>
/// Broad content category used to quickly route files based on type.
/// </summary>
public enum ContentKind {
    /// <summary>Unrecognized or indeterminate.</summary>
    Unknown,
    /// <summary>Plain text or structured text (JSON, YAML, logs, Markdown, scripts, etc.).</summary>
    Text,
    /// <summary>Raster or vector image formats.</summary>
    Image,
    /// <summary>Archive or disk container formats (ZIP/TAR/DMG/ISO/7z/RAR).</summary>
    Archive,
    /// <summary>Native or managed executables/libraries (PE/ELF/Mach-O).</summary>
    Executable,
    /// <summary>Document formats (PDF, OOXML, RTF, EML, etc.).</summary>
    Document,
    /// <summary>Audio files.</summary>
    Audio,
    /// <summary>Video files.</summary>
    Video,
    /// <summary>3D model formats.</summary>
    Model,
    /// <summary>Database file formats.</summary>
    Database,
}

/// <summary>
/// Helpers for mapping a detection result onto a <see cref="ContentKind"/>.
/// </summary>
public static class KindClassifier {
    /// <summary>
    /// Maps a detection result onto a broad <see cref="ContentKind"/>.
    /// </summary>
    /// <param name="r">Detection result to classify.</param>
    /// <returns>One of the <see cref="ContentKind"/> values.</returns>
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
