using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace FileInspectorX;

/// <summary>
/// Minimal, self-contained MSI P/Invoke wrappers with SafeHandle usage. No external dependencies.
/// Only implements the subset needed by FileInspectorX (read-only metadata).
/// </summary>
internal static class MsiNative
{
    internal const int ERROR_SUCCESS = 0;
    internal const int ERROR_MORE_DATA = 234;

    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiCloseHandle")]
    private static extern int MsiCloseHandle(IntPtr hAny);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiOpenDatabaseW")]
    private static extern int MsiOpenDatabaseW(string szDatabasePath, string? szPersist, out IntPtr phDatabase);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiDatabaseOpenViewW")]
    private static extern int MsiDatabaseOpenViewW(IntPtr hDatabase, string szQuery, out IntPtr phView);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiViewExecute")]
    internal static extern int MsiViewExecute(IntPtr hView, IntPtr hRecord);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiViewFetch")]
    internal static extern int MsiViewFetch(IntPtr hView, out IntPtr phRecord);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiRecordGetStringW")]
    private static extern int MsiRecordGetStringW(IntPtr hRecord, int iField, System.Text.StringBuilder? szValueBuf, ref int pcchValueBuf);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiGetSummaryInformationW")]
    private static extern int MsiGetSummaryInformationW(IntPtr hDatabase, string? szDatabasePath, uint uiUpdateCount, out IntPtr phSummaryInfo);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiSummaryInfoGetPropertyW")]
    private static extern int MsiSummaryInfoGetPropertyW(IntPtr hSummaryInfo, uint uiProperty, out uint puiDataType, out int piValue, System.Text.StringBuilder? szValueBuf, ref uint pcchValueBuf);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiFormatRecordW")]
    private static extern int MsiFormatRecordW(IntPtr hInstall, IntPtr hRecord, System.Text.StringBuilder? szResult, ref int pcchResult);

    [DllImport("msi.dll", SetLastError = false, EntryPoint = "MsiGetLastErrorRecord")]
    private static extern IntPtr MsiGetLastErrorRecord();

    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiSetInternalUI")]
    private static extern int MsiSetInternalUI(int dwUILevel, IntPtr phWnd);

    internal const string MSIDBOPEN_READONLY = "MSIDBOPEN_READONLY";
    internal const int INSTALLUILEVEL_NONE = 2; // basic enum subset

    internal static void SuppressUI()
    {
        try { _ = MsiSetInternalUI(INSTALLUILEVEL_NONE, IntPtr.Zero); } catch { }
    }

    internal sealed class SafeMsiHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeMsiHandle() : base(true) { }
        internal SafeMsiHandle(IntPtr preexistingHandle, bool ownsHandle) : base(ownsHandle) { SetHandle(preexistingHandle); }
        protected override bool ReleaseHandle() => MsiCloseHandle(handle) == ERROR_SUCCESS;
    }

    internal static bool TryOpenDatabase(string path, out SafeMsiHandle hDb)
    {
        hDb = new SafeMsiHandle();
        IntPtr raw;
        int rc = MsiOpenDatabaseW(path, MSIDBOPEN_READONLY, out raw);
        if (rc != ERROR_SUCCESS || raw == IntPtr.Zero) return false;
        hDb = new SafeMsiHandle(raw, true);
        return true;
    }

    internal static bool TryOpenView(SafeMsiHandle db, string query, out SafeMsiHandle hView)
    {
        hView = new SafeMsiHandle();
        IntPtr raw;
        int rc = MsiDatabaseOpenViewW(db.DangerousGetHandle(), query, out raw);
        if (rc != ERROR_SUCCESS || raw == IntPtr.Zero) return false;
        hView = new SafeMsiHandle(raw, true);
        return true;
    }

    internal static bool TryGetSummaryInfo(SafeMsiHandle db, out SafeMsiHandle hSum)
    {
        hSum = new SafeMsiHandle();
        IntPtr raw;
        int rc = MsiGetSummaryInformationW(db.DangerousGetHandle(), null, 0, out raw);
        if (rc != ERROR_SUCCESS || raw == IntPtr.Zero) return false;
        hSum = new SafeMsiHandle(raw, true);
        return true;
    }

    internal static string? GetRecordString(IntPtr hRec, int field)
    {
        int cch = 0;
        int rc = MsiRecordGetStringW(hRec, field, null, ref cch);
        if (rc != ERROR_MORE_DATA && rc != ERROR_SUCCESS) return null;
        if (cch <= 0) return null;
        var sb = new System.Text.StringBuilder(cch + 1);
        rc = MsiRecordGetStringW(hRec, field, sb, ref cch);
        if (rc != ERROR_SUCCESS) return null;
        return sb.ToString();
    }

    internal static string? GetSummaryString(SafeMsiHandle hSum, uint pid)
    {
        uint type; int ival; uint cch = 0;
        int rc = MsiSummaryInfoGetPropertyW(hSum.DangerousGetHandle(), pid, out type, out ival, null, ref cch);
        if (rc != ERROR_MORE_DATA && rc != ERROR_SUCCESS) return null;
        if (cch == 0) return null;
        var sb = new System.Text.StringBuilder((int)cch + 1);
        rc = MsiSummaryInfoGetPropertyW(hSum.DangerousGetHandle(), pid, out type, out ival, sb, ref cch);
        if (rc != ERROR_SUCCESS) return null;
        return sb.ToString();
    }

    internal static bool CloseHandle(IntPtr h) { try { return MsiCloseHandle(h) == ERROR_SUCCESS; } catch { return false; } }

    internal static string? GetLastErrorString()
    {
        try
        {
            var rec = MsiGetLastErrorRecord();
            if (rec == IntPtr.Zero) return null;
            try
            {
                int cch = 0; _ = MsiFormatRecordW(IntPtr.Zero, rec, null, ref cch);
                if (cch <= 0) return null;
                var sb = new System.Text.StringBuilder(cch + 1);
                if (MsiFormatRecordW(IntPtr.Zero, rec, sb, ref cch) != ERROR_SUCCESS) return null;
                return sb.ToString();
            }
            finally { CloseHandle(rec); }
        }
        catch { return null; }
    }
}
