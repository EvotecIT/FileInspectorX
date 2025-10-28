using System;
using System.Diagnostics;
using System.IO;

namespace FileInspectorX;

internal static class Breadcrumbs
{
    private static string ResolvePath()
    {
        try
        {
            if (!string.IsNullOrWhiteSpace(Settings.BreadcrumbsPath)) return Settings.BreadcrumbsPath!;
            var baseDir = Environment.ExpandEnvironmentVariables("%ProgramData%/TierBridge");
            Directory.CreateDirectory(baseDir);
            return Path.Combine(baseDir, "FileInspectorX.Breadcrumbs.log");
        }
        catch
        {
            return Path.Combine(Path.GetTempPath(), "FileInspectorX.Breadcrumbs.log");
        }
    }

    internal static void Write(string tag, string? message = null, string? path = null)
    {
        try
        {
            // Allow env var to force-enable regardless of Settings
            if (!Settings.BreadcrumbsEnabled)
            {
                var env = Environment.GetEnvironmentVariable("TIERBRIDGE_BREADCRUMBS");
                if (!string.Equals(env, "1", StringComparison.Ordinal)) return;
            }
            var file = ResolvePath();
            try
            {
                var fi = new FileInfo(file);
                if (fi.Exists && fi.Length > Settings.BreadcrumbsMaxBytes)
                {
                    var bak = file + ".1";
                    try { if (File.Exists(bak)) File.Delete(bak); } catch { }
                    try { File.Move(file, bak); } catch { }
                }
            } catch { }
            var now = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fffZ");
            var pid = Process.GetCurrentProcess().Id;
            var tid = Environment.CurrentManagedThreadId;
            var line = $"{now} PID={pid} TID={tid} TAG={tag}{(path!=null?" PATH="+path:"")}{(message!=null?" MSG="+message:"")}";
            File.AppendAllText(file, line + Environment.NewLine);
        }
        catch { /* never throw from breadcrumbs */ }
    }
}

