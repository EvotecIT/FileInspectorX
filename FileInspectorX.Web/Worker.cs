using System.Diagnostics;
using System.Reflection;

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
                var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true };
                if (Path.GetFileNameWithoutExtension(Environment.ProcessPath!).Equals("dotnet", StringComparison.OrdinalIgnoreCase)) start.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
                foreach (var argument in new[] { "--worker", catalog.Blob(id), catalog.ReportPath(id), job.Name }) start.ArgumentList.Add(argument);
                using var process = Process.Start(start) ?? throw new IOException("Unable to start analysis worker.");
                try
                {
                    var clock = Stopwatch.StartNew();
                    while (!process.HasExited)
                    {
                        stoppingToken.ThrowIfCancellationRequested();
                        if (clock.Elapsed > TimeSpan.FromSeconds(30) || process.WorkingSet64 > 512L * 1024 * 1024)
                            throw new TimeoutException("Worker exceeded its time or observed memory limit.");
                        await Task.Delay(100, stoppingToken);
                    }
                    if (process.ExitCode != 0 || !File.Exists(catalog.ReportPath(id))) throw new InvalidDataException("Worker could not produce a report.");
                    catalog.Update(id, "completed");
                }
                finally { if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(CancellationToken.None); } }
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
}

internal static class Worker
{
    internal static int Run(string[] args)
    {
        if (args.Length != 4) return 2;
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
            var report = FileInspector.AnalyzeReport(input, args[3], new InspectionReportOptions
            {
                Detection = new FileInspector.DetectionOptions { Settings = settings, IncludePermissions = false, IncludeShellProperties = false, IncludeInstaller = false }
            });
            ReportJson.WriteAtomic(args[2], report);
            return 0;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException) { return 1; }
    }
}
