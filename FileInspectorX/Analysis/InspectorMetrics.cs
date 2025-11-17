using System.Threading;

namespace FileInspectorX;

/// <summary>
/// Lightweight, process-wide metrics for instrumentation. Public so hosts can read counters in heartbeats.
/// </summary>
/// <summary>
/// Lightweight, process-wide metrics for instrumentation. Hosts may read these in heartbeats.
/// </summary>
public static class InspectorMetrics
{
    /// <summary>
    /// MSI enrichment counters.
    /// </summary>
    public static class Msi
    {
        /// <summary>Total MSI enrichment attempts.</summary>
        private static long _attempts;
        /// <summary>Total MSI enrichments that completed successfully.</summary>
        private static long _success;
        /// <summary>Total MSI enrichments that threw exceptions.</summary>
        private static long _fail;
        /// <summary>Total MSI enrichments that were skipped (e.g., no Property table).</summary>
        private static long _skipped;

        /// <summary>Increment attempt counter.</summary>
        public static void IncAttempt() => Interlocked.Increment(ref _attempts);
        /// <summary>Increment success counter.</summary>
        public static void IncSuccess() => Interlocked.Increment(ref _success);
        /// <summary>Increment failure counter.</summary>
        public static void IncFail() => Interlocked.Increment(ref _fail);
        /// <summary>Increment skipped counter.</summary>
        public static void IncSkipped() => Interlocked.Increment(ref _skipped);

        /// <summary>Return a snapshot of MSI counters (Attempts, Success, Fail, Skipped).</summary>
        public static (long Attempts, long Success, long Fail, long Skipped) Snapshot()
            => (Interlocked.Read(ref _attempts), Interlocked.Read(ref _success), Interlocked.Read(ref _fail), Interlocked.Read(ref _skipped));
    }
}
