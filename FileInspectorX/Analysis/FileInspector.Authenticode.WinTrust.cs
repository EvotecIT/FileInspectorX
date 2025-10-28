using System;
using System.Runtime.InteropServices;

namespace FileInspectorX;

/// <summary>
/// Windows-only policy verification via WinVerifyTrust to complement cross‑platform Authenticode parsing.
/// </summary>
public static partial class FileInspector
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string,(int status,bool trusted, DateTime ts)> _winTrustCache = new(StringComparer.OrdinalIgnoreCase);
    private static DateTime _lastPrune = DateTime.MinValue;

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
}
