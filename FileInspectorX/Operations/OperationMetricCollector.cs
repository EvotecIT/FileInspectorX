using System.Diagnostics;
using System.Threading;

namespace FileInspectorX;

// Synchronous nested facades share a collector; each facade snapshots a delta from its entry.
// Async directory workers create independent operations on their executing threads.
internal sealed class OperationMetricCollector
{
    private const int CounterCount = 8;
    private const int StageCount = (int)InspectionStage.EtlValidation + 1;
    private readonly long[] _counts = new long[CounterCount + StageCount * 2];

    internal void Read(int bytes) { Interlocked.Increment(ref _counts[0]); Interlocked.Add(ref _counts[1], bytes); }
    internal void Hash(int bytes) => Interlocked.Add(ref _counts[2], bytes);
    internal void VisitArchiveEntry() => Interlocked.Increment(ref _counts[3]);
    internal void ReadArchivePayload(int bytes) => Interlocked.Add(ref _counts[4], bytes);
    internal void HitArchiveLimit() => Interlocked.Increment(ref _counts[5]);
    internal void AttemptClassifier() => Interlocked.Increment(ref _counts[6]);
    internal void FailClassifier() => Interlocked.Increment(ref _counts[7]);

    internal MetricScope Measure(InspectionStage stage) => new(this, stage);
    internal long[] Capture()
    {
        var snapshot = new long[_counts.Length];
        for (int i = 0; i < snapshot.Length; i++) snapshot[i] = Interlocked.Read(ref _counts[i]);
        return snapshot;
    }

    internal InspectionMetrics Snapshot(long[] start, long startTime)
    {
        var counts = Capture();
        for (int i = 0; i < counts.Length; i++) counts[i] -= start[i];
        var stages = new List<InspectionStageMetric>();
        for (int i = 0; i < StageCount; i++)
        {
            int index = CounterCount + i * 2;
            if (counts[index] > 0)
                stages.Add(new InspectionStageMetric((InspectionStage)i, counts[index], Duration(counts[index + 1])));
        }
        return new InspectionMetrics(Duration(Stopwatch.GetTimestamp() - startTime), counts, stages.ToArray());
    }

    private static TimeSpan Duration(long ticks) => TimeSpan.FromSeconds(ticks / (double)Stopwatch.Frequency);

    internal sealed class MetricScope : IDisposable
    {
        private readonly OperationMetricCollector? _collector;
        private readonly InspectionStage _stage;
        private readonly long _start;
        private int _disposed;
        internal MetricScope(OperationMetricCollector collector, InspectionStage stage)
        { _collector = collector; _stage = stage; _start = Stopwatch.GetTimestamp(); }
        public void Dispose()
        {
            if (_collector == null || Interlocked.Exchange(ref _disposed, 1) != 0) return;
            int index = CounterCount + (int)_stage * 2;
            Interlocked.Increment(ref _collector._counts[index]);
            Interlocked.Add(ref _collector._counts[index + 1], Stopwatch.GetTimestamp() - _start);
        }
    }
}
