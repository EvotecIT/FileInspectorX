namespace FileInspectorX;

internal static class TimeoutHelpers
{
    internal static long GetTimeoutTicks(int timeoutMs)
    {
        if (timeoutMs <= 0) return 0;
        return (long)(timeoutMs * (double)System.Diagnostics.Stopwatch.Frequency / 1000.0);
    }

    internal static bool IsExpired(System.Diagnostics.Stopwatch? sw, long timeoutTicks)
        => sw != null && timeoutTicks > 0 && sw.ElapsedTicks > timeoutTicks;
}
