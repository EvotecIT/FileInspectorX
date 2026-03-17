using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace FileInspectorX;

/// <summary>
/// Windows-only policy verification via WinVerifyTrust to complement cross‑platform Authenticode parsing.
/// </summary>
public static partial class FileInspector
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string,(int status,bool trusted, DateTime ts)> _winTrustCache = new(StringComparer.OrdinalIgnoreCase);
    private static DateTime _lastPrune = DateTime.MinValue;
    private const int TrustENoSignature = unchecked((int)0x800B0100);

    /// <summary>
    /// On Windows, invokes WinVerifyTrust to evaluate Authenticode policy (catalog-aware).
    /// Populates <see cref="AuthenticodeInfo.IsTrustedWindowsPolicy"/> and <see cref="AuthenticodeInfo.WinTrustStatusCode"/>.
    /// </summary>
    private static void TryVerifyAuthenticodeWinTrust(string path, FileAnalysis res)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        if (res.Authenticode == null) res.Authenticode = new AuthenticodeInfo();
        Breadcrumbs.Write("WVT_BEGIN", path: path);
        try
        {
            var fi = new System.IO.FileInfo(path);
            string key = $"{fi.FullName}|{fi.Length}|{fi.LastWriteTimeUtc.Ticks}|rev={(Settings.VerifyAuthenticodeRevocation ? 1 : 0)}";
            if (_winTrustCache.TryGetValue(key, out var cached))
            {
                if ((DateTime.UtcNow - cached.ts).TotalMinutes < Settings.WinTrustCacheTtlMinutes)
                {
                    res.Authenticode.WinTrustStatusCode = cached.status;
                    res.Authenticode.IsTrustedWindowsPolicy = cached.trusted;
                    if (cached.trusted)
                    {
                        res.Authenticode.Present = true;
                        if (string.IsNullOrWhiteSpace(res.Authenticode.VerificationNote))
                            res.Authenticode.VerificationNote = "WinTrust policy validation";
                    }
                    return;
                }
                else
                {
                    _winTrustCache.TryRemove(key, out _);
                }
            }
        }
        catch { /* ignore cache key issues */ }
        IntPtr pFile = IntPtr.Zero;
        IntPtr pPath = IntPtr.Zero;
        try {
            var guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            // Build unmanaged WINTRUST_FILE_INFO with explicit unmanaged string to avoid GC/marshalling issues
            var fileInfo = new WINTRUST_FILE_INFO();
            fileInfo.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
            pPath = Marshal.StringToHGlobalUni(path);
            fileInfo.pcwszFilePath = pPath;
            fileInfo.hFile = IntPtr.Zero;
            fileInfo.pgKnownSubject = IntPtr.Zero;

            var data = new WINTRUST_DATA();
            data.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
            data.dwUIChoice = WTD_UI_NONE;
            data.fdwRevocationChecks = Settings.VerifyAuthenticodeRevocation ? WTD_REVOKE_WHOLECHAIN : WTD_REVOKE_NONE;
            data.dwUnionChoice = WTD_CHOICE_FILE;
            data.dwStateAction = WTD_STATEACTION_IGNORE;
            // Allocate unmanaged WINTRUST_FILE_INFO and ensure cleanup afterward
            pFile = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
            Marshal.StructureToPtr(fileInfo, pFile, fDeleteOld: false);
            data.pFile = pFile;
            data.dwProvFlags = WTD_SAFER_FLAG | WTD_REVOCATION_CHECK_NONE | WTD_HASH_ONLY_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;
            if (Settings.VerifyAuthenticodeRevocation) data.dwProvFlags &= ~WTD_REVOCATION_CHECK_NONE;

            int status = WinVerifyTrust(IntPtr.Zero, ref guidAction, ref data);
            res.Authenticode.WinTrustStatusCode = status;
            res.Authenticode.IsTrustedWindowsPolicy = status == 0;
            if (status == 0)
            {
                res.Authenticode.Present = true;
                if (string.IsNullOrWhiteSpace(res.Authenticode.VerificationNote))
                    res.Authenticode.VerificationNote = "WinTrust policy validation";
            }
            else if (status == TrustENoSignature)
            {
                TryPopulateAuthenticodeFromPowerShell(path, res.Authenticode);
                if (res.Authenticode.IsTrustedWindowsPolicy == true)
                {
                    status = 0;
                    res.Authenticode.WinTrustStatusCode = 0;
                }
            }
            Breadcrumbs.Write("WVT_END", message: $"status=0x{status:X8}", path: path);
            // store in cache
            try
            {
                var fi2 = new System.IO.FileInfo(path);
                string key2 = $"{fi2.FullName}|{fi2.Length}|{fi2.LastWriteTimeUtc.Ticks}|rev={(Settings.VerifyAuthenticodeRevocation ? 1 : 0)}";
                _winTrustCache[key2] = (status, status == 0, DateTime.UtcNow);
                // opportunistic prune
                if (_winTrustCache.Count > Settings.WinTrustCacheMaxEntries)
                {
                    PruneWinTrustCache();
                }
            }
            catch { }
        } catch (Exception ex) { Breadcrumbs.Write("WVT_ERROR", message: ex.GetType().Name+":"+ex.Message, path: path); }
        finally {
            if (pFile != IntPtr.Zero) {
                try { Marshal.FreeHGlobal(pFile); } catch { }
            }
            if (pPath != IntPtr.Zero) {
                try { Marshal.FreeHGlobal(pPath); } catch { }
            }
            Breadcrumbs.Write("WVT_FINALLY", path: path);
        }
    }

    private static void PruneWinTrustCache()
    {
        // Limit prune frequency to once per minute
        var now = DateTime.UtcNow;
        if ((now - _lastPrune).TotalSeconds < 60) return;
        _lastPrune = now;
        try
        {
            // Drop expired first
            foreach (var kv in _winTrustCache)
            {
                if ((now - kv.Value.ts).TotalMinutes >= Settings.WinTrustCacheTtlMinutes)
                {
                    _winTrustCache.TryRemove(kv.Key, out _);
                }
            }
            // If still above cap, drop oldest
            int max = Settings.WinTrustCacheMaxEntries;
            if (_winTrustCache.Count > max)
            {
                var ordered = _winTrustCache.ToArray().OrderBy(kv => kv.Value.ts).ToList();
                int toDrop = _winTrustCache.Count - max;
                for (int i = 0; i < toDrop && i < ordered.Count; i++)
                {
                    _winTrustCache.TryRemove(ordered[i].Key, out _);
                }
            }
        }
        catch { }
    }

    // P/Invoke
    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_REVOKE_WHOLECHAIN = 1;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_IGNORE = 0;

    // Provider flags
    private const uint WTD_REVOCATION_CHECK_NONE = 0x00000010;
    private const uint WTD_HASH_ONLY_FLAG = 0x00000200;
    private const uint WTD_SAFER_FLAG = 0x00000100;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00080000;

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath; // LPCWSTR
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        // Remaining fields omitted (not needed for our use case)
    }

    private static void TryPopulateAuthenticodeFromPowerShell(string path, AuthenticodeInfo info)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        if (info == null) return;
        if (info.IsTrustedWindowsPolicy == true && info.Present) return;

        try
        {
            var quotedPath = path.Replace("'", "''");
            var baseScript = string.Join(Environment.NewLine, new[]
            {
                "$signature = Get-AuthenticodeSignature -LiteralPath '" + quotedPath + "'",
                "$signer = $signature.SignerCertificate",
                "$tsa = $signature.TimeStamperCertificate",
                "'Status=' + [string]$signature.Status",
                "'StatusMessage=' + [string]$signature.StatusMessage",
                "'SignatureType=' + [string]$signature.SignatureType",
                "'IsOSBinary=' + [string]$signature.IsOSBinary",
                "'SignerSubject=' + $(if ($signer) { [string]$signer.Subject } else { '' })",
                "'SignerIssuer=' + $(if ($signer) { [string]$signer.Issuer } else { '' })",
                "'SignerThumbprint=' + $(if ($signer) { [string]$signer.Thumbprint } else { '' })",
                "'SignerSerialHex=' + $(if ($signer) { [string]$signer.SerialNumber } else { '' })",
                "'SignerNotBefore=' + $(if ($signer) { [string]$signer.NotBefore.ToUniversalTime().ToString('o') } else { '' })",
                "'SignerNotAfter=' + $(if ($signer) { [string]$signer.NotAfter.ToUniversalTime().ToString('o') } else { '' })",
                "'TimestampSubject=' + $(if ($tsa) { [string]$tsa.Subject } else { '' })"
            });
            string stdout;
            if (!TryRunAuthenticodeShellScript(baseScript, out stdout)) return;

            var values = ParsePowerShellKeyValueOutput(stdout);
            string? statusText;
            if (!TryGetValue(values, "Status", out statusText)) return;

            if (string.Equals(statusText, "Valid", StringComparison.OrdinalIgnoreCase))
            {
                info.Present = true;
                info.IsTrustedWindowsPolicy = true;
                info.WinTrustStatusCode = 0;
                info.VerificationNote ??= "PowerShell Authenticode validation";
            }
            else if (string.Equals(statusText, "NotSigned", StringComparison.OrdinalIgnoreCase))
            {
                info.Present = false;
                info.IsTrustedWindowsPolicy = false;
                info.WinTrustStatusCode ??= TrustENoSignature;
            }
            else if (!string.IsNullOrWhiteSpace(GetValueOrNull(values, "SignerSubject")))
            {
                info.Present = true;
                info.IsTrustedWindowsPolicy = false;
            }

            var signerSubject = GetValueOrNull(values, "SignerSubject");
            var signerIssuer = GetValueOrNull(values, "SignerIssuer");
            var signerThumbprint = GetValueOrNull(values, "SignerThumbprint");
            var signerSerialHex = GetValueOrNull(values, "SignerSerialHex");
            var timestampSubject = GetValueOrNull(values, "TimestampSubject");

            if (!string.IsNullOrWhiteSpace(signerSubject))
            {
                info.SignerSubject = signerSubject;
                info.SignerSubjectCN ??= GetRdnValue(signerSubject, "CN");
                info.SignerSubjectO ??= GetRdnValue(signerSubject, "O");
            }

            if (!string.IsNullOrWhiteSpace(signerIssuer))
            {
                info.SignerIssuer = signerIssuer;
                info.IssuerCN ??= GetRdnValue(signerIssuer, "CN");
                info.IssuerO ??= GetRdnValue(signerIssuer, "O");
            }

            if (!string.IsNullOrWhiteSpace(signerThumbprint)) info.SignerThumbprint = signerThumbprint;
            if (!string.IsNullOrWhiteSpace(signerSerialHex)) info.SignerSerialHex = signerSerialHex;
            DateTimeOffset notBefore;
            DateTimeOffset notAfter;
            if (TryParseDateTimeOffset(GetValueOrNull(values, "SignerNotBefore"), out notBefore)) info.NotBefore = notBefore.UtcDateTime;
            if (TryParseDateTimeOffset(GetValueOrNull(values, "SignerNotAfter"), out notAfter)) info.NotAfter = notAfter.UtcDateTime;

            if (!string.IsNullOrWhiteSpace(timestampSubject))
            {
                info.TimestampPresent ??= true;
                info.TimestampAuthority ??= timestampSubject;
                info.TimestampAuthorityCN ??= GetRdnValue(timestampSubject, "CN");
            }
        }
        catch
        {
            // PowerShell fallback is best-effort only.
        }
    }

    private static Dictionary<string, string> ParsePowerShellKeyValueOutput(string stdout)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using var reader = new StringReader(stdout);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var idx = line.IndexOf('=');
            if (idx <= 0) continue;
            values[line.Substring(0, idx).Trim()] = line.Substring(idx + 1).Trim();
        }

        return values;
    }

    private static string EscapePowerShellCommandArgument(string script)
    {
        var sb = new StringBuilder(script.Length + 8);
        sb.Append('"');
        foreach (var ch in script)
        {
            if (ch == '"') sb.Append("\\\"");
            else sb.Append(ch);
        }
        sb.Append('"');
        return sb.ToString();
    }

    private static bool TryRunAuthenticodeShellScript(string baseScript, out string stdout)
    {
        foreach (var shell in new[] { "pwsh", "powershell.exe" })
        {
            try
            {
                var shellScript = shell.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase)
                    ? "Import-Module Microsoft.PowerShell.Security" + Environment.NewLine + baseScript
                    : baseScript;

                var psi = new ProcessStartInfo
                {
                    FileName = shell,
                    Arguments = "-NoProfile -NonInteractive -Command " + EscapePowerShellCommandArgument(shellScript),
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process == null) continue;

                if (!process.WaitForExit(5000))
                {
                    try { process.Kill(); } catch { }
                    continue;
                }

                var currentStdout = process.StandardOutput.ReadToEnd();
                if (process.ExitCode == 0 && !string.IsNullOrWhiteSpace(currentStdout))
                {
                    stdout = currentStdout;
                    return true;
                }
            }
            catch
            {
                // Try the next available shell.
            }
        }

        stdout = string.Empty;
        return false;
    }

    private static string? GetRdnValue(string? distinguishedName, string key)
    {
        if (string.IsNullOrWhiteSpace(distinguishedName) || string.IsNullOrWhiteSpace(key)) return null;
        var dn = distinguishedName;
        if (dn == null) return null;

        foreach (var part in dn.Split(','))
        {
            var kv = part.Trim();
            var eq = kv.IndexOf('=');
            if (eq <= 0) continue;

            var currentKey = kv.Substring(0, eq).Trim();
            if (!currentKey.Equals(key, StringComparison.OrdinalIgnoreCase)) continue;
            return kv.Substring(eq + 1).Trim();
        }

        return null;
    }

    private static bool TryGetValue(Dictionary<string, string> values, string key, out string? value)
    {
        string? found;
        if (values.TryGetValue(key, out found))
        {
            value = found;
            return true;
        }

        value = null;
        return false;
    }

    private static string? GetValueOrNull(Dictionary<string, string> values, string key)
    {
        string? value;
        return TryGetValue(values, key, out value) ? value : null;
    }

    private static bool TryParseDateTimeOffset(string? value, out DateTimeOffset timestamp)
    {
        if (!string.IsNullOrWhiteSpace(value) && DateTimeOffset.TryParse(value, out timestamp)) return true;
        timestamp = default;
        return false;
    }
}
