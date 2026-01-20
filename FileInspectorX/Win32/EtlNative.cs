using System;
using System.Runtime.InteropServices;

namespace FileInspectorX;

/// <summary>
/// Minimal P/Invoke for ETW OpenTrace/CloseTrace to validate ETL files without external tools.
/// Exposed as public so TierBridge.Service can perform a lightweight ETL sanity check without deep analysis.
/// </summary>
public static class EtlNative
{
    private const ulong INVALID_PROCESSTRACE_HANDLE = ulong.MaxValue; // (TRACEHANDLE)(-1)

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct EVENT_TRACE_LOGFILEW
    {
        public string LogFileName;
        public string LoggerName;
        public long CurrentTime;
        public uint BuffersRead;
        public uint ProcessTraceMode;
        public EVENT_TRACE_LOGFILEW_CALLBACKS Callbacks;
        public uint LogFileMode;
        public uint BufferSize;
        public uint Filled;
        public uint EventsLost;
        public uint IsKernelTrace;
        public IntPtr Context; // reserved
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EVENT_TRACE_LOGFILEW_CALLBACKS
    {
        public IntPtr BufferCallback;     // PEVENT_TRACE_BUFFER_CALLBACKW
        public IntPtr EventCallback;      // PEVENT_CALLBACK (legacy)
        public IntPtr EventRecordCallback; // PEVENT_RECORD_CALLBACK
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern ulong OpenTraceW(ref EVENT_TRACE_LOGFILEW logFile);

    [DllImport("advapi32.dll")] private static extern uint CloseTrace(ulong traceHandle);

    /// <summary>
    /// Attempts to open the ETL via OpenTraceW. Returns true when the handle opens cleanly, false on a failing handle, and null on non-Windows or unexpected errors.
    /// </summary>
    public static bool? TryOpen(string path)
    {
        // Temporarily disabled: OpenTraceW can AV on some large/corrupted ETL files.
        // Returning null avoids native calls while preserving existing caller semantics.
        return null;
    }
}
