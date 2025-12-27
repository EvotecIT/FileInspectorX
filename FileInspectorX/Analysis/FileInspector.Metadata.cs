using System.Collections.Generic;
using System.IO;

namespace FileInspectorX;

public static partial class FileInspector
{
    /// <summary>
    /// Reads basic file system metadata for a file path. Returns null when the file is missing or inaccessible.
    /// </summary>
    public static FileSystemMetadata? ReadFileMetadata(string path, FileMetadataOptions? options = null)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        options ??= new FileMetadataOptions();
        try
        {
            if (!File.Exists(path)) return new FileSystemMetadata { Exists = false, Path = options.IncludePath ? path : null };
            var fi = new FileInfo(path);
            var meta = new FileSystemMetadata { Exists = true };
            if (options.IncludePath) meta.Path = path;
            if (options.IncludeSize) meta.Size = fi.Length;
            if (options.IncludeTimestamps)
            {
                meta.CreatedUtc = fi.CreationTimeUtc;
                meta.ModifiedUtc = fi.LastWriteTimeUtc;
            }
            if (options.IncludeAccessedUtc)
                meta.AccessedUtc = fi.LastAccessTimeUtc;
            if (options.IncludeAttributes)
                meta.Attributes = fi.Attributes.ToString();
            if (options.IncludeMagicHeader && options.MagicHeaderBytes > 0)
                meta.MagicHeaderHex = MagicHeaderHex(path, options.MagicHeaderBytes);
            return meta;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Inspects a file and returns analysis, report view, file metadata, and a flattened metadata dictionary.
    /// </summary>
    public static FileInspectionSummary InspectWithMetadata(
        string path,
        DetectionOptions? options = null,
        FileMetadataOptions? metadataOptions = null)
    {
        var analysis = Inspect(path, options);
        var report = ReportView.From(analysis);
        var fileMeta = ReadFileMetadata(path, metadataOptions);
        var meta = CollectMetadata(analysis, fileMeta, report);
        return new FileInspectionSummary
        {
            Analysis = analysis,
            Report = report,
            FileMetadata = fileMeta,
            Metadata = meta
        };
    }

    /// <summary>
    /// Builds a flattened metadata dictionary from analysis and optional file metadata.
    /// </summary>
    public static IReadOnlyDictionary<string, object?> CollectMetadata(
        FileAnalysis analysis,
        FileSystemMetadata? fileMetadata = null)
    {
        return CollectMetadata(analysis, fileMetadata, null);
    }

    /// <summary>
    /// Builds a metadata dictionary from file system metadata only.
    /// </summary>
    public static IReadOnlyDictionary<string, object?> CollectMetadata(FileSystemMetadata fileMetadata)
    {
        var dict = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        AddFileMetadata(dict, fileMetadata);
        return dict;
    }

    /// <summary>
    /// Returns a lightweight signature status summary for the analysis.
    /// </summary>
    public static SignatureStatus? GetSignatureStatus(FileAnalysis analysis)
    {
        var auth = analysis.Authenticode;
        if (auth == null) return null;
        var status = new SignatureStatus
        {
            IsSigned = auth.Present,
            IsValid = auth.IsTrustedWindowsPolicy ?? auth.ChainValid,
            SignerSubject = !string.IsNullOrWhiteSpace(auth.SignerSubjectCN) ? auth.SignerSubjectCN : auth.SignerSubject,
            SignerThumbprint = auth.SignerThumbprint,
            SigningTimeUtc = auth.TimestampTime?.UtcDateTime
        };
        return status;
    }

    /// <summary>
    /// Compares the current file name against OriginalFilename metadata and returns mismatch status.
    /// </summary>
    public static bool? IsOriginalFilenameMismatch(string? currentFileName, string? originalFilename)
    {
        if (string.IsNullOrWhiteSpace(currentFileName)) return null;
        if (string.IsNullOrWhiteSpace(originalFilename)) return null;
        try
        {
            var current = Path.GetFileName(currentFileName);
            if (string.IsNullOrWhiteSpace(current)) return null;
            return !string.Equals(current, originalFilename, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return null;
        }
    }

    private static IReadOnlyDictionary<string, object?> CollectMetadata(
        FileAnalysis analysis,
        FileSystemMetadata? fileMetadata,
        ReportView? report)
    {
        var dict = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        if (fileMetadata != null)
            AddFileMetadata(dict, fileMetadata);

        var reportDict = (report ?? ReportView.From(analysis)).ToDictionary();
        foreach (var kv in reportDict) dict[kv.Key] = kv.Value;

        AddSignatureMetadata(dict, analysis);
        return dict;
    }

    private static void AddFileMetadata(IDictionary<string, object?> dict, FileSystemMetadata meta)
    {
        if (!string.IsNullOrWhiteSpace(meta.Path)) dict["Path"] = meta.Path;
        if (meta.Size.HasValue) dict["Size"] = meta.Size.Value;
        if (meta.CreatedUtc.HasValue) dict["CreatedUtc"] = meta.CreatedUtc.Value;
        if (meta.ModifiedUtc.HasValue) dict["ModifiedUtc"] = meta.ModifiedUtc.Value;
        if (meta.AccessedUtc.HasValue) dict["AccessedUtc"] = meta.AccessedUtc.Value;
        if (!string.IsNullOrWhiteSpace(meta.Attributes)) dict["Attributes"] = meta.Attributes;
        if (!string.IsNullOrWhiteSpace(meta.MagicHeaderHex)) dict["MagicHeaderHex"] = meta.MagicHeaderHex;
    }

    private static void AddSignatureMetadata(IDictionary<string, object?> dict, FileAnalysis analysis)
    {
        var status = GetSignatureStatus(analysis);
        if (status == null) return;
        if (status.IsSigned.HasValue && !dict.ContainsKey("IsSigned")) dict["IsSigned"] = status.IsSigned.Value;
        if (status.IsValid.HasValue && !dict.ContainsKey("SignatureValid")) dict["SignatureValid"] = status.IsValid.Value;
        if (!string.IsNullOrWhiteSpace(status.SignerSubject) && !dict.ContainsKey("SignerSubject")) dict["SignerSubject"] = status.SignerSubject;
        if (!string.IsNullOrWhiteSpace(status.SignerThumbprint) && !dict.ContainsKey("SignerThumbprint")) dict["SignerThumbprint"] = status.SignerThumbprint;
        if (status.SigningTimeUtc.HasValue && !dict.ContainsKey("SigningTime")) dict["SigningTime"] = status.SigningTimeUtc.Value;
    }
}
