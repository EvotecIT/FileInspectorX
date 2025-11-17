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

        // Extension-first friendly map
        switch (ext)
        {
            case "pfx":
            case "p12": return "PKCS#12 / PFX archive";
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
            case "md":   return "Markdown document";
            case "json": return "JSON file";
            case "ndjson":
            case "jsonl": return "NDJSON (JSON Lines)";
            case "yml":
            case "yaml": return "YAML document";
            case "xml":  return "XML file";
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
            case "nupkg": return "NuGet package (NUPKG)";
            case "xap":   return "Silverlight application package (XAP)";
            case "exe":  return "Windows executable (.exe)";
            case "dll":  return "Windows library (.dll)";
            case "msi":  return "Windows installer package (.msi)";
            case "vsix": return "Visual Studio extension (VSIX)";
            case "apk":  return "Android package (APK)";
            case "ipa":  return "iOS application archive (IPA)";
            case "evtx": return "Windows Event Log (EVTX)";
            case "sqlite": return "SQLite database";
            case "etl": return "Windows Trace Log (ETL)";
        }

        // Special-case text logs: use heuristic findings to return a friendlier label
        if (string.Equals(ext, "log", System.StringComparison.OrdinalIgnoreCase))
        {
            var f = a.SecurityFindings ?? Array.Empty<string>();
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
