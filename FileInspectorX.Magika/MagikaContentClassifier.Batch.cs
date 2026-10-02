using System.Threading;

namespace FileInspectorX.Magika;

public sealed partial class MagikaContentClassifier
{
    /// <summary>Predicts complete memory inputs in order, using native model batches of at most 32 rows.</summary>
    /// <param name="contents">Inputs that remain stable during prediction.</param>
    /// <param name="cancellationToken">Cancels feature extraction and in-flight native inference.</param>
    /// <returns>One prediction for each input, in the same order.</returns>
    /// <remarks>
    /// Empty and tiny inputs retain scalar rule behavior. Native batch kernels can
    /// produce different floating-point probabilities from scalar inference;
    /// labels and confidence decisions near a cutoff can therefore also differ.
    /// Dispose the classifier only after all active predictions have finished.
    /// </remarks>
    public IReadOnlyList<LearnedContentPrediction> PredictBatch(IReadOnlyList<ReadOnlyMemory<byte>> contents, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (contents == null) throw new ArgumentNullException(nameof(contents));
        cancellationToken.ThrowIfCancellationRequested();
        var predictions = new LearnedContentPrediction[contents.Count];
        int width = _config.BeginningSize + _config.MiddleSize + _config.EndSize;
        for (int start = 0; start < contents.Count; start += 32)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int end = Math.Min(contents.Count, start + 32);
            var indices = new List<int>(end - start);
            for (int index = start; index < end; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var content = contents[index];
                if (content.Length == 0) predictions[index] = CreateRulePrediction("empty", 1);
                else if (content.Length < _config.MinimumFileSizeForModel)
                    predictions[index] = CreateRulePrediction(IsValidUtf8(content.Span) ? "txt" : "unknown", 1);
                else indices.Add(index);
            }
            if (indices.Count == 0) continue;
            var features = new int[indices.Count * width];
            for (int row = 0; row < indices.Count; row++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                MagikaFeatureExtractor.Fill(contents[indices[row]], _config, features.AsSpan(row * width, width));
            }
            var batch = RunModelBatch(features, indices.Count, cancellationToken);
            for (int row = 0; row < indices.Count; row++) predictions[indices[row]] = batch[row];
        }
        cancellationToken.ThrowIfCancellationRequested();
        return predictions;
    }
}
