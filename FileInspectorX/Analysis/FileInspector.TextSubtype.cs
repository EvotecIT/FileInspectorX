namespace FileInspectorX;

public static partial class FileInspector
{
    private static string? MapTextSubtypeFromExtension(string? ext)
    {
        var e = (ext ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(e)) return null;
        return e switch
        {
            "md" or "markdown" => "markdown",
            "ini" or "cfg" or "conf" => "ini",
            "toml" => "toml",
            "yml" or "yaml" => "yaml",
            "json" or "ndjson" or "jsonl" => "json",
            "xml" or "admx" or "adml" => "xml",
            "csv" => "csv",
            "tsv" => "tsv",
            "log" => "log",
            "ps1" or "psm1" or "psd1" => "powershell",
            "py" or "pyw" => "python",
            "rb" => "ruby",
            "lua" => "lua",
            "vbs" or "vbe" or "wsf" or "wsh" => "vbscript",
            "js" or "jse" or "mjs" or "cjs" => "javascript",
            "sh" or "bash" or "zsh" => "shell",
            "bat" or "cmd" => "batch",
            _ => null
        };
    }

    private static bool IsScriptTextSubtype(string? subtype)
    {
        var s = (subtype ?? string.Empty).Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(s)) return false;
        return s is "powershell" or "javascript" or "vbscript" or "shell" or "batch" or "python" or "ruby" or "perl" or "lua";
    }
}
