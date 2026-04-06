namespace FileInspectorX;

/// <summary>
/// Human-friendly labels for detected MIME types, extensions, and special subtypes.
/// </summary>
public static class FriendlyNames
{
    /// <summary>
    /// Returns a user-friendly type label for the provided analysis/detection.
    /// Falls back to MIME type when no mapping is available.
    /// </summary>
    public static string? GetTypeLabel(ContentTypeDetectionResult? det, FileAnalysis a)
    {
        // Citrix special cases from text subtype
        if (string.Equals(a.TextSubtype, "citrix-ica", System.StringComparison.OrdinalIgnoreCase))
            return "Citrix ICA connection file";
        if (string.Equals(a.TextSubtype, "citrix-receiver-config", System.StringComparison.OrdinalIgnoreCase))
            return "Citrix Receiver/Workspace configuration (XML)";

        var ext = det?.Extension?.ToLowerInvariant();
        var mime = det?.MimeType?.ToLowerInvariant();
        if (string.IsNullOrEmpty(ext) && string.IsNullOrEmpty(mime)) return null;

        var subtype = a.ContainerSubtype?.ToLowerInvariant();
        if (string.IsNullOrEmpty(subtype) && ext == "zip")
        {
            subtype = det?.GuessedExtension?.ToLowerInvariant();
        }

        switch (subtype)
        {
            case "jar": return "Java archive (JAR)";
            case "apk": return "Android package (APK)";
            case "ipa": return "iOS application archive (IPA)";
            case "epub": return "EPUB e-book";
            case "odt": return "OpenDocument text document";
            case "ods": return "OpenDocument spreadsheet";
            case "odp": return "OpenDocument presentation";
            case "odg": return "OpenDocument drawing";
            case "kmz": return "Google Earth KMZ archive";
            case "vsix": return "Visual Studio extension (VSIX)";
            case "nupkg": return "NuGet package (NUPKG)";
            case "xap": return "Silverlight application package (XAP)";
            case "appx":
            case "msix": return "Windows app package";
        }

        // Extension-first friendly map
        switch (ext)
        {
            case "png": return "PNG image";
            case "jpg":
            case "jpeg": return "JPEG image";
            case "gif": return "GIF image";
            case "bmp": return "Bitmap image";
            case "webp": return "WebP image";
            case "tif":
            case "tiff": return "TIFF image";
            case "ico": return "Icon image";
            case "pfx":
            case "p12": return "PKCS#12 / PFX archive";
            case "p7b": return "PKCS#7 certificate bundle";
            case "spc": return "Software publisher certificate bundle";
            case "p7s": return "PKCS#7 signature";
            case "crt":
            case "cer": return "X.509 certificate";
            case "csr": return "Certificate signing request (CSR)";
            case "pem": return "PEM file";
            case "key": return "Private key (PEM/OpenSSH)";
            case "pub": return "Public key (PEM)";
            case "asc": return "PGP ASCII‑armored data";
            case "b64": return "Base64‑encoded data";
            case "hex": return "Hex‑encoded data";
            case "b85": return "Base85/ASCII85‑encoded data";
            case "uu":  return "UUEncoded data";
            case "qp":  return "Quoted-printable encoded data";
            case "pgp":
            case "gpg": return "PGP/GPG encrypted data";
            case "docx": return "Word document";
            case "doc":  return "Word 97-2003 document";
            case "xlsx": return "Excel workbook";
            case "xls":  return "Excel 97-2003 workbook";
            case "pptx": return "PowerPoint presentation";
            case "ppt":  return "PowerPoint 97-2003 presentation";
            case "pdf":  return "PDF document";
            case "txt":  return "Text file";
            case "ini":  return "INI configuration file";
            case "inf":  return "Windows INF file";
            case "md":   return "Markdown document";
            case "json": return "JSON file";
            case "ndjson":
            case "jsonl": return "NDJSON (JSON Lines)";
            case "yml":
            case "yaml": return "YAML document";
            case "xml":  return "XML file";
            case "ps1":  return "PowerShell script";
            case "psm1": return "PowerShell module";
            case "psd1": return "PowerShell data file";
            case "ps1xml": return "PowerShell format/configuration file";
            case "bat":
            case "cmd":  return "Windows batch script";
            case "js":
            case "mjs":
            case "cjs": return "JavaScript file";
            case "vbs": return "VBScript file";
            case "vbe": return "Encoded VBScript file";
            case "wsf":
            case "wsh": return "Windows Script Host script";
            case "sh":
            case "bash":
            case "zsh": return "Shell script";
            case "py":  return "Python script";
            case "rb":  return "Ruby script";
            case "lua": return "Lua script";
            case "admx": return "Group Policy ADMX template";
            case "adml": return "Group Policy ADML resource file";
            case "toml": return "TOML document";
            case "eml":  return "Email message (.eml)";
            // 'log' handled below to allow richer labels
            case "csv":  return "CSV (comma-separated values)";
            case "tsv":  return "TSV (tab-separated values)";
            case "zip":  return "ZIP archive";
            case "7z":   return "7-Zip archive";
            case "rar":  return "RAR archive";
            case "tar":  return "TAR archive";
            case "gz":   return "GZIP compressed file";
            case "cab":  return "Windows cabinet archive";
            case "nupkg": return "NuGet package (NUPKG)";
            case "exe":  return "Windows executable (.exe)";
            case "dll":  return "Windows library (.dll)";
            case "parquet": return "Apache Parquet data file";
            case "pcap": return "Packet capture (PCAP)";
            case "pcapng": return "Packet capture (PCAPNG)";
            case "wasm": return "WebAssembly module";
            case "heic": return "HEIC image";
            case "flac": return "FLAC audio";
            case "wav": return "WAV audio";
            case "mp3": return "MP3 audio";
            case "m4a": return "AAC audio (M4A)";
            case "mp4": return "MPEG-4 video";
            case "avi": return "AVI video";
            case "3gp": return "3GPP media";
            case "bz2": return "BZip2 compressed file";
            case "xz": return "XZ compressed file";
            case "zst": return "Zstandard compressed file";
            case "dmp":
                if (string.Equals(mime, "application/x-ms-protected-dump", System.StringComparison.OrdinalIgnoreCase))
                    return "Protected Windows crash dump";
                return "Windows memory dump";
            case "msi":  return "Windows installer package (.msi)";
            case "vsix": return "Visual Studio extension (VSIX)";
            case "apk":  return "Android package (APK)";
            case "ipa":  return "iOS application archive (IPA)";
            case "evtx": return "Windows Event Log (EVTX)";
            case "sqlite": return "SQLite database";
            case "etl": return "Windows Trace Log (ETL)";
            case "pol": return "Group Policy Registry.pol file";
        }

        // Special-case text logs: use heuristic findings to return a friendlier label
        if (string.Equals(ext, "log", System.StringComparison.OrdinalIgnoreCase))
        {
            var f = a.SecurityFindings ?? Array.Empty<string>();
            if (f.Contains("ps:transcript", StringComparer.OrdinalIgnoreCase)) return "PowerShell transcript log";
            if (f.Contains("log:iis-w3c", StringComparer.OrdinalIgnoreCase)) return "IIS W3C log";
            if (f.Contains("log:dns", StringComparer.OrdinalIgnoreCase)) return "Windows DNS Server log";
            if (f.Contains("log:firewall", StringComparer.OrdinalIgnoreCase)) return "Windows Firewall log";
            if (f.Contains("log:netlogon", StringComparer.OrdinalIgnoreCase)) return "Windows Netlogon log";
            if (f.Contains("log:dhcp", StringComparer.OrdinalIgnoreCase)) return "Windows DHCP Server log";
            if (f.Contains("exchange:msgtrack", StringComparer.OrdinalIgnoreCase)) return "Exchange message tracking log";
            if (f.Contains("defender:txt", StringComparer.OrdinalIgnoreCase)) return "Windows Defender log";
            if (f.Contains("sql:errorlog", StringComparer.OrdinalIgnoreCase)) return "SQL Server ERRORLOG";
            if (f.Contains("nps:radius", StringComparer.OrdinalIgnoreCase)) return "NPS/RADIUS log";
            if (f.Contains("sql:agent", StringComparer.OrdinalIgnoreCase)) return "SQL Server Agent log";
            if (f.Contains("event-xml", StringComparer.OrdinalIgnoreCase)) return "Windows Event XML";
            if (f.Contains("event:txt", StringComparer.OrdinalIgnoreCase)) return "Windows Event text log";

            // Fallback to detection reason when findings are unavailable (e.g., detection-only contexts)
            var reason = det?.Reason?.ToLowerInvariant() ?? string.Empty;
            if (!string.IsNullOrEmpty(reason))
            {
                if (reason.Contains("text:log-powershell-transcript")) return "PowerShell transcript log";
                if (reason.Contains("text:log-syslog")) return "Syslog text log";
                if (reason.Contains("text:log-dns")) return "Windows DNS Server log";
                if (reason.Contains("text:log-firewall")) return "Windows Firewall log";
                if (reason.Contains("text:log-netlogon")) return "Windows Netlogon log";
                if (reason.Contains("text:log-dhcp")) return "Windows DHCP Server log";
                if (reason.Contains("text:log-exchange")) return "Exchange message tracking log";
                if (reason.Contains("text:log-sql-errorlog")) return "SQL Server ERRORLOG";
                if (reason.Contains("text:log-nps")) return "NPS/RADIUS log";
                if (reason.Contains("text:log-sqlagent")) return "SQL Server Agent log";
                if (reason.Contains("text:event-txt")) return "Windows Event text log";
            }
            return "Text log";
        }

        // MIME fallbacks
        switch (mime)
        {
            case "application/vnd.openxmlformats-officedocument.wordprocessingml.document": return "Word document";
            case "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":      return "Excel workbook";
            case "application/vnd.openxmlformats-officedocument.presentationml.presentation": return "PowerPoint presentation";
            case "application/pdf": return "PDF document";
            case "application/zip": return "ZIP archive";
            case "application/x-7z-compressed": return "7-Zip archive";
            case "application/vnd.rar": return "RAR archive";
            case "application/gzip": return "GZIP compressed file";
            case "application/vnd.ms-cab-compressed": return "Windows cabinet archive";
            case "text/plain": return "Text file";
            case "application/json": return "JSON file";
            case "application/xml": return "XML file";
            case "text/markdown": return "Markdown document";
            case "application/x-msdownload":
                // Distinguish by extension when possible
                if (ext == "exe") return "Windows executable (.exe)";
                if (ext == "dll") return "Windows library (.dll)";
                return "Windows binary";
        }

        // Container subtypes
        if (!string.IsNullOrEmpty(a.ContainerSubtype))
        {
            if (a.ContainerSubtype == "appx" || a.ContainerSubtype == "msix") return "Windows app package";
            if (a.ContainerSubtype == "vsix") return "Visual Studio extension (VSIX)";
            if (a.ContainerSubtype == "nupkg") return "NuGet package (NUPKG)";
            if (a.ContainerSubtype == "xap") return "Silverlight application package (XAP)";
        }

        return det?.MimeType; // fallback to MIME
    }
}
