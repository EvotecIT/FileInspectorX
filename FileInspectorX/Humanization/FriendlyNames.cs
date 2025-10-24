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
            case "xml":  return "XML file";
            case "csv":  return "CSV (comma-separated values)";
            case "tsv":  return "TSV (tab-separated values)";
            case "zip":  return "ZIP archive";
            case "7z":   return "7-Zip archive";
            case "rar":  return "RAR archive";
            case "tar":  return "TAR archive";
            case "gz":   return "GZIP compressed file";
            case "exe":  return "Windows executable (.exe)";
            case "dll":  return "Windows library (.dll)";
            case "msi":  return "Windows installer package (.msi)";
            case "vsix": return "Visual Studio extension (VSIX)";
            case "apk":  return "Android package (APK)";
            case "ipa":  return "iOS application archive (IPA)";
            case "evtx": return "Windows Event Log (EVTX)";
            case "sqlite": return "SQLite database";
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
        }

        return det?.MimeType; // fallback to MIME
    }
}
