using System;
using System.Diagnostics;
using System.IO;

namespace FileInspectorX;

    /// <summary>
    /// Safe ETL validation helper using tracerpt.exe with timeout; no direct ETW P/Invoke.
    /// </summary>
    public static class EtlProbe
{
    /// <summary>
        /// Attempts to validate that the given file is a readable ETL by invoking the built-in Windows
        /// tracerpt.exe tool with a timeout. Returns true on clear success (exit code 0), false on clear failure,
        /// and null when the probe is unavailable (non-Windows), times out, or an unexpected error occurs.
        /// </summary>
    public static bool? TryValidate(string path, int timeoutMs)
        {
            try
            {
                if (!System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                    return null;
                if (!File.Exists(path)) return false;
                // tracerpt requires an output file; write to a temp file and delete afterwards
                var tmp = Path.Combine(Path.GetTempPath(), "etlprobe-" + Guid.NewGuid().ToString("N") + ".xml");
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "tracerpt.exe",
                    Arguments = $"\"{path}\" -y -q -o \"{tmp}\" -of XML",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                    using var p = Process.Start(psi);
                    if (p == null) return null;
                    var waitMs = Math.Max(1000, timeoutMs);
                    if (!p.WaitForExit(waitMs))
                    {
                        try { p.Kill(); } catch { }
                        return null; // timeout
                    }
                    // tracerpt returns 0 on success; non-zero on failures to parse the ETL
                    return p.ExitCode == 0;
                }
                finally
                {
                    try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
                }
            }
            catch { return null; }
        }
}
