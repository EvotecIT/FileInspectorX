using System.Security.Cryptography;

namespace FileInspectorX;

public static partial class FileInspector
{
    /// <summary>Analyzes a stable bounded snapshot and produces schema version 1. Throws on unreadable or oversized input.</summary>
    public static InspectionReport AnalyzeReport(string path, InspectionReportOptions? options = null)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return AnalyzeReport(stream, Path.GetFileName(path), options);
    }

    /// <summary>Reports complete input from offset zero for seekable streams, or remaining input for forward-only streams.
    /// Leaves the stream open and restores the original seekable position. Oversized input is rejected.</summary>
    public static InspectionReport AnalyzeReport(Stream stream, string? fileName = null, InspectionReportOptions? options = null)
    {
        if (stream == null) throw new ArgumentNullException(nameof(stream));
        if (!stream.CanRead) throw new ArgumentException("A readable stream is required.", nameof(stream));
        options ??= new InspectionReportOptions();
        if (options.MaxInputBytes <= 0 || options.MaxTextCharacters <= 0 || options.MaxArchiveEntries <= 0 || options.MaxEntryBytes <= 0 || options.MaxExpandedBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(options), "Report budgets must be positive.");
        var policy = new InspectionReportOptions
        {
            MaxInputBytes = options.MaxInputBytes, MaxTextCharacters = options.MaxTextCharacters,
            MaxArchiveEntries = options.MaxArchiveEntries, MaxEntryBytes = options.MaxEntryBytes, MaxExpandedBytes = options.MaxExpandedBytes
        };
        var detection = options.Detection?.Copy() ?? new DetectionOptions { IncludePermissions = false, IncludeInstaller = false, IncludeShellProperties = false };
        detection.Settings ??= InspectionSettings.CaptureDefaults();
        detection.OfflineCertificateValidation = true;
        detection.ComputeSha256 = true;
        detection.MagicHeaderBytes = Math.Max(16, detection.MagicHeaderBytes);
        var original = stream.CanSeek ? stream.Position : (long?)null;
        byte[] bytes;
        try
        {
            if (original.HasValue) stream.Position = 0;
            using var snapshot = new MemoryStream();
            var buffer = new byte[8192];
            while (true)
            {
                detection.CancellationToken.ThrowIfCancellationRequested();
                var read = stream.Read(buffer, 0, (int)Math.Min(buffer.Length, (long)policy.MaxInputBytes - snapshot.Length + 1));
                if (read == 0) break;
                if (snapshot.Length + read > policy.MaxInputBytes) throw new InvalidDataException("report:input-size-limit");
                snapshot.Write(buffer, 0, read);
            }
            bytes = snapshot.ToArray();
        }
        finally { if (original.HasValue) stream.Position = original.Value; }
        var name = DisplayFileName(fileName);
        var analysis = Analyze(bytes, detection, name);
        using var operation = InspectionOperation.Begin(detection);
        var content = ReportContentReader.Read(bytes, analysis, policy);
        var report = new InspectionReport
        {
            AnalyzerVersion = typeof(FileInspector).Assembly.GetName().Version?.ToString() ?? "unknown",
            CreatedUtc = DateTimeOffset.UtcNow,
            File = new ReportFileIdentity { Name = name, SizeBytes = bytes.LongLength, Sha256 = ReportHash(bytes) },
            Analysis = analysis, Content = content
        };
        report.Observations = ReportExplainer.Explain(report);
        return report;
    }

    internal static string ReportHash(byte[] bytes)
    {
        using var sha = SHA256.Create();
        return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", string.Empty).ToLowerInvariant();
    }

    internal static string DisplayFileName(string? value)
    {
        var name = (value ?? string.Empty).Replace('\\', '/');
        return name.Substring(name.LastIndexOf('/') + 1);
    }
}
