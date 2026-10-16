using System.Security.Cryptography;

namespace FileInspectorX;

public static partial class FileInspector
{
    /// <summary>Analyzes a stable bounded snapshot and produces the current report schema. Throws on unreadable or oversized input.</summary>
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
        var policy = options.Copy();
        var detection = options.Detection?.Copy() ?? new DetectionOptions { IncludePermissions = false, IncludeInstaller = false, IncludeShellProperties = false };
        detection.Settings ??= InspectionSettings.CaptureDefaults();
        detection.OfflineCertificateValidation = true;
        detection.ComputeSha256 = true;
        detection.MagicHeaderBytes = Math.Max(16, detection.MagicHeaderBytes);
        var original = stream.CanSeek ? stream.Position : (long?)null;
        ReportSnapshot? snapshot = null;
        try
        {
            if (original.HasValue) stream.Position = 0;
            snapshot = ReportSnapshot.Capture(stream, policy, detection.CancellationToken);
        }
        finally
        {
            try { if (original.HasValue) stream.Position = original.Value; }
            catch { snapshot?.Dispose(); throw; }
        }
        using (snapshot) return AnalyzeReportSnapshot(snapshot!.Stream, snapshot.Sha256, DisplayFileName(fileName), detection, policy,
            new ReportReadContext(policy, detection), 0);
    }

    internal static InspectionReport AnalyzeReportSnapshot(Stream snapshot, string hash, string name, DetectionOptions detection,
        InspectionReportOptions policy, ReportReadContext context, int depth)
    {
        snapshot.Position = 0;
        var analysis = Analyze(snapshot, detection, name);
        using var operation = InspectionOperation.Begin(detection);
        var content = ReportContentReader.Read(snapshot, hash, name, analysis, policy, context, depth, detection.CancellationToken);
        var report = new InspectionReport
        {
            AnalyzerVersion = typeof(FileInspector).Assembly.GetName().Version?.ToString() ?? "unknown",
            CreatedUtc = DateTimeOffset.UtcNow,
            File = new ReportFileIdentity { Name = name, SizeBytes = snapshot.Length, Sha256 = hash },
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
