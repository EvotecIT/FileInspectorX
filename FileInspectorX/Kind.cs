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
    /// <summary>Installable or runtime package formats.</summary>
    Package,
    /// <summary>Virtual, optical, or filesystem disk images.</summary>
    DiskImage,
    /// <summary>Network, event-trace, or process-dump capture formats.</summary>
    Capture,
    /// <summary>Font and font-collection formats.</summary>
    Font,
    /// <summary>Columnar, scientific, or other structured binary data.</summary>
    StructuredData,
    /// <summary>Medical imaging and interchange formats.</summary>
    Medical,
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
        var guessed = (r.GuessedExtension ?? string.Empty).ToLowerInvariant();

        if (ext == "reg") return ContentKind.Executable;
        if (mime.StartsWith("text/") || InspectHelpers.IsText(r)) return ContentKind.Text;
        if (mime.StartsWith("image/") || InspectHelpers.IsImage(r)) return ContentKind.Image;
        if (mime.StartsWith("audio/")) return ContentKind.Audio;
        if (mime.StartsWith("video/")) return ContentKind.Video;
        if (ext is "rpm" or "deb" or "crx" or "apk" or "jar" or "ipa" or "vsix" or "appx" or "msix" or "msi" or "xap" or "nupkg" ||
            guessed is "apk" or "jar" or "ipa" or "vsix" or "appx" or "msix" or "msi" or "xap" or "nupkg") return ContentKind.Package;
        if (ext is "qcow2" or "vhd" or "vhdx" or "dmg" or "iso" or "udf") return ContentKind.DiskImage;
        if (ext is "pcap" or "pcapng" or "etl" or "evtx" or "dmp" or "mdmp") return ContentKind.Capture;
        if (ext is "ttf" or "otf" or "woff" or "woff2" or "ttc" or "otc") return ContentKind.Font;
        if (ext is "parquet" or "arrow" or "h5" or "hdf5" or "nc") return ContentKind.StructuredData;
        if (ext == "dcm") return ContentKind.Medical;
        if (mime.Contains("zip") || mime.Contains("tar") || mime.Contains("gzip") || InspectHelpers.IsArchive(r)) return ContentKind.Archive;
        if (ext is "elf" or "exe" or "dll" or "sys" or "ocx" or "cpl" or "scr" or "com" or "pif" or "macho" or "class" or "dex" or "lnk" or "chm" or "swf" or "wasm") return ContentKind.Executable;
        if (ext is "docx" or "xlsx" or "pptx" or "pdf" or "rtf" or "eml") return ContentKind.Document;
        if (ext is "gltf" or "glb") return ContentKind.Model;
        if (ext is "sqlite" or "edb" or "accdb" or "mdb" or "pst" or "ost" or "ndb" or "hive") return ContentKind.Database;
        return ContentKind.Unknown;
    }
}
