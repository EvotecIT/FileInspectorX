namespace FileInspectorX;

internal static class TimeoutHelpers
{
    internal static long GetTimeoutTicks(int timeoutMs)
    {
        if (timeoutMs <= 0) return 0;
        double ticks = timeoutMs * (double)System.Diagnostics.Stopwatch.Frequency / 1000.0;
        if (ticks >= long.MaxValue) return long.MaxValue;
        return (long)ticks;
    }

    internal static bool IsExpired(System.Diagnostics.Stopwatch? sw, long timeoutTicks)
        => sw != null && timeoutTicks > 0 && sw.ElapsedTicks > timeoutTicks;
}
