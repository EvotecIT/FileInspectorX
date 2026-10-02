using System.Threading;

namespace FileInspectorX;

// Inspection computation is synchronous. Async directory facades pass a captured options copy
// to each worker rather than leaving ambient state installed across awaits or iterator yields.
internal sealed class InspectionOperation : IDisposable
{
    [ThreadStatic] private static InspectionOperation? _current;
    private readonly InspectionOperation? _previous;
    private readonly CancellationTokenSource? _linkedCancellation;

    internal static InspectionOperation? Current => _current;
    internal InspectionSettings? Settings { get; }
    internal FileInspector.DetectionOptions Options { get; }
    internal bool RetainUnknownDetection { get; }
    internal OperationMetricCollector? Metrics { get; }
    private readonly long[]? _metricStart;
    private readonly long _startTime;

    private InspectionOperation(FileInspector.DetectionOptions? options, bool retainUnknownDetection)
    {
        // Inherited instrumentation must not change the nullable results of nested callers
        // that did not themselves request metrics.
        RetainUnknownDetection = retainUnknownDetection && options?.CollectMetrics == true;
        _previous = _current;
        Settings = options?.Settings ?? _previous?.Settings;
        Options = options?.Copy() ?? new FileInspector.DetectionOptions { IncludeInstaller = Settings?.IncludeInstaller ?? FileInspectorX.Settings.IncludeInstaller };
        Options.Settings = Settings;
        Metrics = _previous?.Metrics ?? (Options.CollectMetrics ? new OperationMetricCollector() : null);
        if (Metrics != null)
        {
            Options.CollectMetrics = true;
            _metricStart = Metrics.Capture();
            _startTime = System.Diagnostics.Stopwatch.GetTimestamp();
        }
        var parentToken = _previous?.Options.CancellationToken ?? default;
        if (parentToken.CanBeCanceled && Options.CancellationToken != parentToken)
        {
            if (Options.CancellationToken.CanBeCanceled)
            {
                _linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(parentToken, Options.CancellationToken);
                Options.CancellationToken = _linkedCancellation.Token;
            }
            else Options.CancellationToken = parentToken;
        }
        try { Options.CancellationToken.ThrowIfCancellationRequested(); }
        catch { _linkedCancellation?.Dispose(); throw; }
        _current = this;
    }

    internal static InspectionOperation Begin(FileInspector.DetectionOptions? options, bool retainUnknownDetection = false) => new(options, retainUnknownDetection);

    internal static FileInspector.DetectionOptions Capture(FileInspector.DetectionOptions? options)
    {
        var result = options?.Copy() ?? new FileInspector.DetectionOptions();
        result.Settings ??= _current?.Settings;
        if (options == null) result.IncludeInstaller = result.Settings?.IncludeInstaller ?? FileInspectorX.Settings.IncludeInstaller;
        return result;
    }

    internal static void CheckCancellation() => _current?.Options.CancellationToken.ThrowIfCancellationRequested();

    internal OperationMetricCollector.MetricScope? Measure(InspectionStage stage) => Metrics?.Measure(stage);
    internal InspectionMetrics? SnapshotMetrics() => Metrics?.Snapshot(_metricStart!, _startTime);

    public void Dispose()
    {
        _current = _previous;
        _linkedCancellation?.Dispose();
        // Best-effort enrichment may catch parser failures. A canceled operation never returns
        // a success/allow result, even if one of those existing catches intercepted cancellation.
        Options.CancellationToken.ThrowIfCancellationRequested();
    }
}
