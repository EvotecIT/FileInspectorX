namespace FileInspectorX;

/// <summary>
/// Built-in, dependency-free helper maps used by FileInspector and consumers.
/// Keep policy-light: these are conveniences, not enforcement.
/// </summary>
public static class MimeMaps {
    /// <summary>
    /// Default map from file extension (without dot) to MIME type. Case‑insensitive keys.
    /// </summary>
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
        ["ps1"] = "text/x-powershell",
        ["vbs"] = "text/vbscript",
        ["psm1"] = "text/x-powershell",
        ["psd1"] = "text/x-powershell",
        ["py"] = "text/x-python",
        ["rb"] = "text/x-ruby",
        ["lua"] = "text/x-lua",
        ["md"] = "text/markdown",
        ["cfg"] = "text/plain",
        ["conf"] = "text/plain",
        ["sh"] = "text/x-shellscript",
        ["bash"] = "text/x-shellscript",
        ["zsh"] = "text/x-shellscript",
        ["bat"] = "text/x-batch",
        ["cmd"] = "text/x-batch",
        ["doc"] = "application/msword",
        ["xls"] = "application/vnd.ms-excel",
        ["ppt"] = "application/vnd.ms-powerpoint",
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
        ["ndjson"] = "application/x-ndjson",
        ["jsonl"] = "application/x-ndjson",
        ["xml"] = "application/xml",
        ["html"] = "text/html",
        ["toml"] = "application/toml",
        ["csv"] = "text/csv",
        ["tsv"] = "text/tab-separated-values",
        ["txt"] = "text/plain",
        ["log"] = "text/plain",
        ["ini"] = "text/plain",
        ["inf"] = "text/plain",
        ["admx"] = "application/xml",
        ["adml"] = "application/xml",
        ["pol"] = "application/x-group-policy-registry-pol",
        ["etl"] = "application/octet-stream"
    };

    /// <summary>
    /// Looks up a MIME type by file extension.
    /// </summary>
    /// <param name="extension">Extension with or without leading dot (e.g., ".pdf" or "pdf").</param>
    /// <param name="mime">The resolved MIME type when found.</param>
    /// <returns>True when the extension is mapped; otherwise false.</returns>
    public static bool TryGetByExtension(string? extension, out string? mime) {
        mime = null;
        if (string.IsNullOrWhiteSpace(extension)) return false;
        var key = extension!.Trim().TrimStart('.');
        return Default.TryGetValue(key, out mime);
    }
}

// Extend default MIME mappings for security/crypto-related files and PGP
internal static class ExtraMime
{
    static ExtraMime()
    {
        // Merge additional mappings into MimeMaps.Default via reflection if needed elsewhere
    }
    /// <summary>
    /// Returns additional MIME type defaults for common crypto files.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> Crypto = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["pem"] = "application/x-pem-file",
        ["crt"] = "application/pkix-cert",
        ["cer"] = "application/pkix-cert",
        ["csr"] = "application/pkcs10",
        ["key"] = "application/x-pem-key",
        ["pub"] = "application/x-pem-key",
        ["p7b"] = "application/pkcs7-mime",
        ["p7s"] = "application/pkcs7-signature",
        ["p12"] = "application/x-pkcs12",
        ["pfx"] = "application/x-pkcs12",
        ["asc"] = "application/pgp", // generic ASCII‑armored PGP
        ["pgp"] = "application/pgp-encrypted",
        ["gpg"] = "application/pgp-encrypted"
    };
}

/// <summary>
/// Convenience set of commonly risky executable/script extensions; not a policy, used only for hints.
/// </summary>
public static class DangerousExtensions {
    /// <summary>
    /// A convenience set of commonly risky executable/script extensions. Case‑insensitive.
    /// </summary>
    public static readonly ISet<string> Default = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "exe", "dll", "sys", "msi", "msp", "cpl", "scr", "pif", "com",
        "bat", "cmd", "ps1", "psm1", "psd1", "vbs", "js", "jse", "wsf", "wsh",
        "reg", "hta", "lnk"
    };

    /// <summary>
    /// Returns true when the provided extension belongs to the <see cref="Default"/> risky set.
    /// </summary>
    public static bool IsDangerous(string? extension) {
        if (string.IsNullOrWhiteSpace(extension)) return false;
        var key = extension!.Trim().TrimStart('.');
        var custom = Settings.DangerousExtensionsOverride;
        if (custom != null && custom.Count > 0) return custom.Contains(key);
        return Default.Contains(key);
    }
}
