using System;
using System.Runtime.InteropServices;

namespace FileInspectorX;

public static partial class FileInspector
{
    /// <summary>
    /// On Windows, invokes WinVerifyTrust to evaluate Authenticode policy (catalog-aware).
    /// Populates <see cref="AuthenticodeInfo.IsTrustedWindowsPolicy"/> and <see cref="AuthenticodeInfo.WinTrustStatusCode"/>.
    /// </summary>
    private static void TryVerifyAuthenticodeWinTrust(string path, FileAnalysis res)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        if (res.Authenticode == null) res.Authenticode = new AuthenticodeInfo();
        try {
            var guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            var fileInfo = new WINTRUST_FILE_INFO(path);
            var data = new WINTRUST_DATA();
            data.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
            data.dwUIChoice = WTD_UI_NONE;
            data.fdwRevocationChecks = Settings.VerifyAuthenticodeRevocation ? WTD_REVOKE_WHOLECHAIN : WTD_REVOKE_NONE;
            data.dwUnionChoice = WTD_CHOICE_FILE;
            data.dwStateAction = WTD_STATEACTION_IGNORE;
            data.pFile = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
            Marshal.StructureToPtr(fileInfo, data.pFile, false);
            data.dwProvFlags = WTD_SAFER_FLAG | WTD_REVOCATION_CHECK_NONE | WTD_HASH_ONLY_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;
            if (Settings.VerifyAuthenticodeRevocation) data.dwProvFlags &= ~WTD_REVOCATION_CHECK_NONE;

            int status = WinVerifyTrust(IntPtr.Zero, ref guidAction, ref data);
            res.Authenticode.WinTrustStatusCode = status;
            res.Authenticode.IsTrustedWindowsPolicy = status == 0;
        } catch { }
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
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;

        public WINTRUST_FILE_INFO(string filePath)
        {
            cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
            pcwszFilePath = filePath;
            hFile = IntPtr.Zero;
            pgKnownSubject = IntPtr.Zero;
        }
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
