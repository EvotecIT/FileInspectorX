namespace FileInspectorX;

/// <summary>
/// Built-in, dependency-free helper maps used by FileInspector and consumers.
/// Keep policy-light: these are conveniences, not enforcement.
/// </summary>
/// <summary>
/// Built-in, dependency-free mapping of common file extensions to canonical MIME types.
/// </summary>
public static class MimeMaps {
    public static readonly IReadOnlyDictionary<string, string> Default = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
        ["png"] = "image/png",
        ["jpg"] = "image/jpeg",
        ["jpeg"] = "image/jpeg",
        ["gif"] = "image/gif",
        ["bmp"] = "image/bmp",
        ["webp"] = "image/webp",
        ["tif"] = "image/tiff",
        ["tiff"] = "image/tiff",

        ["pdf"] = "application/pdf",
        ["zip"] = "application/zip",
        ["gz"] = "application/gzip",
        ["7z"] = "application/x-7z-compressed",
        ["rar"] = "application/vnd.rar",
        ["tar"] = "application/x-tar",
        ["sqlite"] = "application/vnd.sqlite3",
        ["docx"] = "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ["xlsx"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ["pptx"] = "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ["epub"] = "application/epub+zip",
        ["jar"] = "application/java-archive",
        ["apk"] = "application/vnd.android.package-archive",
        ["ipa"] = "application/zip",
        ["vsix"] = "application/zip",
        ["xap"] = "application/x-silverlight-app",
        ["kmz"] = "application/vnd.google-earth.kmz",
        ["odt"] = "application/vnd.oasis.opendocument.text",
        ["ods"] = "application/vnd.oasis.opendocument.spreadsheet",
        ["odp"] = "application/vnd.oasis.opendocument.presentation",
        ["odg"] = "application/vnd.oasis.opendocument.graphics",
        ["parquet"] = "application/vnd.apache.parquet",
        ["pcap"] = "application/vnd.tcpdump.pcap",
        ["pcapng"] = "application/x-pcapng",
        ["flac"] = "audio/flac",
        ["wasm"] = "application/wasm",
        ["bz2"] = "application/x-bzip2",
        ["xz"] = "application/x-xz",
        ["zst"] = "application/zstd",
        ["ico"] = "image/x-icon",

        ["mp4"] = "video/mp4",
        ["m4a"] = "audio/mp4",
        ["3gp"] = "video/3gpp",
        ["avi"] = "video/x-msvideo",
        ["wav"] = "audio/wav",
        ["mp3"] = "audio/mpeg",
        ["heic"] = "image/heic",

        ["json"] = "application/json",
        ["xml"] = "application/xml",
        ["html"] = "text/html",
        ["csv"] = "text/csv",
        ["tsv"] = "text/tab-separated-values",
        ["txt"] = "text/plain",
        ["log"] = "text/plain",
        ["ini"] = "text/plain"
    };

    public static bool TryGetByExtension(string? extension, out string? mime) {
        mime = null;
        if (string.IsNullOrWhiteSpace(extension)) return false;
        var key = extension!.Trim().TrimStart('.');
        return Default.TryGetValue(key, out mime);
    }
}

/// <summary>
/// Convenience set of commonly risky executable/script extensions; not a policy, used only for hints.
/// </summary>
public static class DangerousExtensions {
    public static readonly ISet<string> Default = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "exe", "dll", "sys", "msi", "msp", "cpl", "scr", "pif", "com",
        "bat", "cmd", "ps1", "psm1", "psd1", "vbs", "js", "jse", "wsf", "wsh",
        "reg", "hta", "lnk"
    };

    public static bool IsDangerous(string? extension) {
        if (string.IsNullOrWhiteSpace(extension)) return false;
        var key = extension!.Trim().TrimStart('.');
        return Default.Contains(key);
    }
}

