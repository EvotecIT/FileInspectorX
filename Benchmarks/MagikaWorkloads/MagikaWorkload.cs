using System.IO.Compression;
using System.Text.Json;
using FileInspectorX.Magika;

namespace FileInspectorX.Benchmarks;

/// <summary>Measures reusable provider inference over the pinned content corpus.</summary>
public sealed class MagikaWorkload : IDisposable
{
    private readonly MagikaContentClassifier _classifier;
    private readonly Func<IReadOnlyList<ReadOnlyMemory<byte>>, CancellationToken, IReadOnlyList<LearnedContentPrediction>>? _batch;
    private readonly ReadOnlyMemory<byte>[] _contents;
    private readonly string[] _labels;
    private readonly int _calls;

    /// <summary>Loads identical complete inputs; session construction happens outside measurement.</summary>
    public MagikaWorkload(string corpusPath, string operation, int threads, int calls)
    {
        if (calls < 1) throw new ArgumentOutOfRangeException(nameof(calls), "Calls must be positive.");
        using var file = File.OpenRead(corpusPath);
        using var gzip = new GZipStream(file, CompressionMode.Decompress);
        using var json = JsonDocument.Parse(gzip);
        var examples = json.RootElement.EnumerateArray().Where(example => example.GetProperty("prediction_mode").GetString() == "high_confidence").ToArray();
        _contents = examples.Select(example => new ReadOnlyMemory<byte>(Convert.FromBase64String(example.GetProperty("content_base64").GetString()!))).ToArray();
        _labels = examples.Select(example => example.GetProperty("prediction").GetProperty("output").GetString()!).ToArray();
        _calls = calls;
        var options = new MagikaClassifierOptions { PredictionMode = MagikaPredictionMode.HighConfidence };
        // Only the baseline lane lacks this new option. It measures scalar inference
        // with the same runtime default; configured lanes require the candidate API.
        var threadProperty = typeof(MagikaClassifierOptions).GetProperty("IntraOpThreadCount");
        if (threadProperty != null) threadProperty.SetValue(options, threads);
        else if (threads != 0) throw new NotSupportedException("The baseline cannot configure native threads.");
        _classifier = new MagikaContentClassifier(options);
        try
        {
            if (operation == "Batch")
            {
                var method = typeof(MagikaContentClassifier).GetMethod("PredictBatch")
                    ?? throw new NotSupportedException("The provider has no batch API.");
                _batch = (Func<IReadOnlyList<ReadOnlyMemory<byte>>, CancellationToken, IReadOnlyList<LearnedContentPrediction>>)method.CreateDelegate(
                    typeof(Func<IReadOnlyList<ReadOnlyMemory<byte>>, CancellationToken, IReadOnlyList<LearnedContentPrediction>>), _classifier);
            }
            else if (operation != "Scalar") throw new ArgumentException("Use Scalar or Batch.", nameof(operation));
        }
        catch { _classifier.Dispose(); throw; }
    }

    /// <summary>Predicts and validates every corpus input, retaining probability range and allocation proof.</summary>
    public MagikaWorkloadResult Run()
    {
        long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        int matched = 0;
        for (int call = 0; call < _calls; call++)
        {
            var predictions = _batch == null ? null : _batch(_contents, default);
            for (int index = 0; index < _contents.Length; index++)
            {
                var prediction = predictions == null ? _classifier.Predict(_contents[index]) : predictions[index];
                if (prediction.OutputLabel == _labels[index] && double.IsFinite(prediction.Probability) && prediction.Probability is >= 0 and <= 1) matched++;
            }
        }
        return new MagikaWorkloadResult(_calls * _contents.Length, matched, GC.GetAllocatedBytesForCurrentThread() - allocatedBefore);
    }

    /// <inheritdoc />
    public void Dispose() => _classifier.Dispose();
}

/// <summary>Observable corpus integrity and managed allocation totals for one sample.</summary>
public sealed record MagikaWorkloadResult(int Inputs, int Matched, long AllocatedBytes);
