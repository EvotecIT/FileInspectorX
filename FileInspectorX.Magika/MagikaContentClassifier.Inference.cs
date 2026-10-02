using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using System.Threading;

namespace FileInspectorX.Magika;

public sealed partial class MagikaContentClassifier
{
    private void ValidateModelShape()
    {
        int width = _config.BeginningSize + _config.MiddleSize + _config.EndSize;
        if (!_session.InputMetadata.TryGetValue("bytes", out var input) || input.ElementType != typeof(int) ||
            input.Dimensions.Length != 2 || input.Dimensions[0] != -1 || input.Dimensions[1] != width)
            throw new InvalidOperationException("The bundled Magika model has an unsupported input shape.");
        if (!_session.OutputMetadata.TryGetValue("target_label", out var output) || output.ElementType != typeof(float) ||
            output.Dimensions.Length != 2 || output.Dimensions[0] != -1 || output.Dimensions[1] != _config.TargetLabels.Length)
            throw new InvalidOperationException("The bundled Magika model has an unsupported output shape.");
    }

    private LearnedContentPrediction RunModel(int[] features, CancellationToken cancellationToken)
        => RunModelInference(features, 1, cancellationToken, batch: false).Scalar!;

    private LearnedContentPrediction[] RunModelBatch(int[] features, int rows, CancellationToken cancellationToken)
        => RunModelInference(features, rows, cancellationToken, batch: true).Batch!;

    private (LearnedContentPrediction? Scalar, LearnedContentPrediction[]? Batch) RunModelInference(
        int[] features, int rows, CancellationToken cancellationToken, bool batch)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var tensor = new DenseTensor<int>(features, new[] { rows, features.Length / rows });
        var inputs = new[] { NamedOnnxValue.CreateFromTensor("bytes", tensor) };
        // A run owns its termination flag, so canceling one prediction cannot
        // terminate another prediction using this shared inference session.
        using var runOptions = cancellationToken.CanBeCanceled ? new RunOptions() : null;
        using var registration = runOptions != null
            ? cancellationToken.Register(() => runOptions.Terminate = true) : default;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var results = runOptions == null
                ? _session.Run(inputs) : _session.Run(inputs, new[] { "target_label" }, runOptions);
            cancellationToken.ThrowIfCancellationRequested();
            var output = results.FirstOrDefault(result => result.Name == "target_label")
                ?? throw new InvalidOperationException("The Magika model did not return target_label.");
            var probabilities = output.AsTensor<float>();
            if (probabilities.Dimensions.Length != 2 || probabilities.Dimensions[0] != rows ||
                probabilities.Dimensions[1] != _config.TargetLabels.Length)
                throw new InvalidOperationException("The Magika model returned an unexpected output shape.");
            if (!batch) return (CreateModelPrediction(probabilities, 0), null);
            var predictions = new LearnedContentPrediction[rows];
            for (int row = 0; row < rows; row++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                predictions[row] = CreateModelPrediction(probabilities, row);
            }
            return (null, predictions);
        }
        catch (OnnxRuntimeException) when (cancellationToken.IsCancellationRequested)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw;
        }
    }

    private LearnedContentPrediction CreateModelPrediction(Tensor<float> probabilities, int row)
    {
        int offset = row * _config.TargetLabels.Length;
        int bestIndex = 0;
        for (int index = 1; index < _config.TargetLabels.Length; index++)
            if (probabilities.GetValue(offset + index) > probabilities.GetValue(offset + bestIndex)) bestIndex = index;
        var rawLabel = _config.TargetLabels[bestIndex];
        var probability = probabilities.GetValue(offset + bestIndex);
        var threshold = ThresholdFor(rawLabel);
        var thresholdMet = _predictionMode == MagikaPredictionMode.BestGuess || probability >= threshold;
        var outputLabel = _config.OverwriteMap.TryGetValue(rawLabel, out var overwritten) ? overwritten : rawLabel;
        string? overwriteReason = outputLabel == rawLabel ? null : "overwrite_map";
        if (!thresholdMet)
        {
            outputLabel = ContentType(rawLabel).IsText ? "txt" : "unknown";
            if (!outputLabel.Equals(rawLabel, StringComparison.Ordinal)) overwriteReason = "low_confidence";
        }
        return CreatePrediction(rawLabel, outputLabel, probability, threshold, thresholdMet, overwriteReason);
    }
}
