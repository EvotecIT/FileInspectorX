using System.Diagnostics;
using System.Reflection;
using System.Text.Json;

namespace FileInspectorX.Web;

internal sealed class AnalysisQueue(Catalog catalog)
{
    internal async Task RunAsync(CancellationToken stoppingToken)
    {
        await foreach (var id in catalog.Queue.Reader.ReadAllAsync(stoppingToken))
        {
            try
            {
                catalog.Update(id, "running");
                var job = catalog.Find(id)!;
                var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true };
                if (Path.GetFileNameWithoutExtension(Environment.ProcessPath!).Equals("dotnet", StringComparison.OrdinalIgnoreCase)) start.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
                foreach (var argument in new[] { "--worker", catalog.Blob(id), job.Name }) start.ArgumentList.Add(argument);
                using var process = Process.Start(start) ?? throw new IOException("Unable to start analysis worker.");
                // Only the live catalog owner can publish. A surviving child has no report destination.
                var report = ReadReport(process.StandardOutput.BaseStream, stoppingToken);
                try
                {
                    var clock = Stopwatch.StartNew();
                    while (true)
                    {
                        stoppingToken.ThrowIfCancellationRequested();
                        process.Refresh();
                        if (process.HasExited) break;
                        if (report.IsFaulted || report.IsCanceled) await report;
                        if (clock.Elapsed > TimeSpan.FromSeconds(30) || process.WorkingSet64 > 512L * 1024 * 1024)
                            throw new TimeoutException("Worker exceeded its time or observed memory limit.");
                        await Task.Delay(100, stoppingToken);
                    }
                    if (process.ExitCode != 0) throw new InvalidDataException("Worker could not produce a report.");
                    catalog.PublishReport(id, await report);
                }
                finally
                {
                    if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(CancellationToken.None); }
                    try { await report; } catch (Exception ex) when (ex is IOException or OperationCanceledException or InvalidDataException) { }
                }
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                Console.Error.WriteLine("Analysis " + id + " did not complete (" + ex.GetType().Name + ").");
                catalog.Update(id, "failed", ex is TimeoutException ? "Worker exceeded its resource budget." : "Analysis failed or was interrupted.");
                File.Delete(catalog.ReportPath(id)); File.Delete(catalog.ReportPath(id) + ".tmp");
                if (stoppingToken.IsCancellationRequested) break;
            }
        }
    }

    private static async Task<byte[]> ReadReport(Stream output, CancellationToken token)
    {
        using var report = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var read = await output.ReadAsync(buffer, token);
            if (read == 0) return report.ToArray();
            if (report.Length + read > Catalog.MaxReportBytes) throw new InvalidDataException("Worker report exceeds 16 MiB.");
            report.Write(buffer, 0, read);
        }
    }
}

internal static class Worker
{
    internal static int Run(string[] args)
    {
        if (args.Length != 3) return 2;
        try
        {
            var settings = InspectionSettings.CaptureDefaults() with
            {
                IncludeInstaller = false, BreadcrumbsEnabled = false,
                VerifyAuthenticodeWithWinTrust = false, VerifyAuthenticodeRevocation = false,
                ResolveNetworkHostsInHeuristics = false, PingHostsInHeuristics = false,
                ReferencePathExistenceChecksEnabled = false, CheckNetworkPathsInReferences = false,
                ReportHostFileMetadataEnabled = false, FindingEvidenceSnippetsEnabled = false,
                EtlValidation = Settings.EtlValidationMode.MagicOnly
            };
            using var input = File.OpenRead(args[1]);
            var report = FileInspector.AnalyzeReport(input, args[2], new InspectionReportOptions
            {
                Detection = new FileInspector.DetectionOptions { Settings = settings, IncludePermissions = false, IncludeShellProperties = false, IncludeInstaller = false }
            });
            using var output = Console.OpenStandardOutput();
            JsonSerializer.Serialize(output, report, ReportJson.Options);
            return 0;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException) { return 1; }
    }
}
