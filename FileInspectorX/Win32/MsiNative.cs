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
    private static extern int MsiCloseHandle(uint hAny);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiOpenDatabaseW")]
    private static extern int MsiOpenDatabaseW(string szDatabasePath, IntPtr szPersist, out uint phDatabase);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiDatabaseOpenViewW")]
    private static extern int MsiDatabaseOpenViewW(uint hDatabase, string szQuery, out uint phView);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiViewExecute")]
    internal static extern int MsiViewExecute(uint hView, uint hRecord);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiViewFetch")]
    internal static extern int MsiViewFetch(uint hView, out uint phRecord);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiRecordGetStringW")]
    private static extern int MsiRecordGetStringW(uint hRecord, int iField, System.Text.StringBuilder szValueBuf, ref int pcchValueBuf);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiGetSummaryInformationW")]
    private static extern int MsiGetSummaryInformationW(uint hDatabase, string? szDatabasePath, uint uiUpdateCount, out uint phSummaryInfo);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiSummaryInfoGetPropertyW")]
    private static extern int MsiSummaryInfoGetPropertyW(uint hSummaryInfo, uint uiProperty, out uint puiDataType, out int piValue, out System.Runtime.InteropServices.ComTypes.FILETIME pftValue, System.Text.StringBuilder? szValueBuf, ref uint pcchValueBuf);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiFormatRecordW")]
    private static extern int MsiFormatRecordW(uint hInstall, uint hRecord, System.Text.StringBuilder szResult, ref int pcchResult);

    [DllImport("msi.dll", SetLastError = false, EntryPoint = "MsiGetLastErrorRecord")]
    private static extern uint MsiGetLastErrorRecord();

    internal sealed class SafeMsiHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeMsiHandle() : base(true) { }
        internal SafeMsiHandle(uint preexistingHandle, bool ownsHandle) : base(ownsHandle) { SetHandle(new IntPtr(preexistingHandle)); }
        // MSIHANDLE is a 32-bit value on every Windows process architecture.
        internal uint Value => unchecked((uint)handle.ToInt64());
        protected override bool ReleaseHandle() => MsiCloseHandle(Value) == ERROR_SUCCESS;
    }

    internal static bool TryOpenDatabase(string path, out SafeMsiHandle hDb)
    {
        hDb = new SafeMsiHandle();
        // MSIDBOPEN_READONLY is (LPCWSTR)0, not the name of the C macro.
        int rc = MsiOpenDatabaseW(path, IntPtr.Zero, out var raw);
        if (rc != ERROR_SUCCESS || raw == 0) return false;
        hDb = new SafeMsiHandle(raw, true);
        return true;
    }

    internal static bool TryOpenView(SafeMsiHandle db, string query, out SafeMsiHandle hView)
    {
        hView = new SafeMsiHandle();
        int rc = MsiDatabaseOpenViewW(db.Value, query, out var raw);
        if (rc != ERROR_SUCCESS || raw == 0) return false;
        hView = new SafeMsiHandle(raw, true);
        return true;
    }

    internal static bool TryGetSummaryInfo(SafeMsiHandle db, out SafeMsiHandle hSum)
    {
        hSum = new SafeMsiHandle();
        int rc = MsiGetSummaryInformationW(db.Value, null, 0, out var raw);
        if (rc != ERROR_SUCCESS || raw == 0) return false;
        hSum = new SafeMsiHandle(raw, true);
        return true;
    }

    internal static string? GetRecordString(uint hRec, int field)
    {
        int cch = 0;
        var sb = new System.Text.StringBuilder(1);
        int rc = MsiRecordGetStringW(hRec, field, sb, ref cch);
        if (rc != ERROR_MORE_DATA && rc != ERROR_SUCCESS) return null;
        if (cch <= 0) return null;
        cch = checked(cch + 1); // The probe length excludes the terminating null.
        sb.EnsureCapacity(cch);
        rc = MsiRecordGetStringW(hRec, field, sb, ref cch);
        if (rc != ERROR_SUCCESS) return null;
        return sb.ToString();
    }

    internal static string? GetSummaryString(SafeMsiHandle hSum, uint pid)
    {
        uint type; int ival; uint cch = 0;
        System.Runtime.InteropServices.ComTypes.FILETIME fileTime;
        int rc = MsiSummaryInfoGetPropertyW(hSum.Value, pid, out type, out ival, out fileTime, null, ref cch);
        if (rc != ERROR_MORE_DATA && rc != ERROR_SUCCESS) return null;
        if (cch == 0) return null;
        cch = checked(cch + 1);
        var sb = new System.Text.StringBuilder(checked((int)cch));
        rc = MsiSummaryInfoGetPropertyW(hSum.Value, pid, out type, out ival, out fileTime, sb, ref cch);
        if (rc != ERROR_SUCCESS) return null;
        return sb.ToString();
    }

    internal static bool CloseHandle(uint h) { try { return MsiCloseHandle(h) == ERROR_SUCCESS; } catch { return false; } }

    internal static string? GetLastErrorString()
    {
        try
        {
            var rec = MsiGetLastErrorRecord();
            if (rec == 0) return null;
            try
            {
                var sb = new System.Text.StringBuilder(1);
                int cch = 0; _ = MsiFormatRecordW(0, rec, sb, ref cch);
                if (cch <= 0) return null;
                cch = checked(cch + 1);
                sb.EnsureCapacity(cch);
                if (MsiFormatRecordW(0, rec, sb, ref cch) != ERROR_SUCCESS) return null;
                return sb.ToString();
            }
            finally { CloseHandle(rec); }
        }
        catch { return null; }
    }
}
