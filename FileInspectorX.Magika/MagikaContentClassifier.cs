using System.Text;
using System.Text.Json;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;

namespace FileInspectorX.Magika;

/// <summary>
/// Runs Google's pinned Magika <c>standard_v3_3</c> ONNX model through ONNX Runtime.
/// The classifier is safe for concurrent prediction and should be reused and disposed.
/// </summary>
public sealed class MagikaContentClassifier : ILearnedContentClassifier, IDisposable
{
    /// <summary>Identifier for the bundled upstream model and source revision.</summary>
    public const string BundledModelId = "google-magika/standard_v3_3@5e2f437fb7b7452368c8c1fa9354858f5487a5c4";

    private const string ModelResourceName = "FileInspectorX.Magika.Models.standard_v3_3.model.onnx";
    private const string ConfigResourceName = "FileInspectorX.Magika.Models.standard_v3_3.config.min.json";
    private const string ContentTypesResourceName = "FileInspectorX.Magika.Models.standard_v3_3.content_types_kb.min.json";

    private readonly InferenceSession _session;
    private readonly MagikaModelConfig _config;
    private readonly Dictionary<string, MagikaContentType> _contentTypes;
    private readonly MagikaPredictionMode _predictionMode;
    private bool _disposed;

    /// <summary>Creates a classifier with high-confidence thresholding.</summary>
    public MagikaContentClassifier()
        : this(new MagikaClassifierOptions())
    {
    }

    /// <summary>Creates a classifier with explicit prediction options.</summary>
    /// <param name="options">Prediction behavior.</param>
    public MagikaContentClassifier(MagikaClassifierOptions options)
    {
        if (options is null)
            throw new ArgumentNullException(nameof(options));

        _predictionMode = options.PredictionMode;
        _config = JsonSerializer.Deserialize(
            ReadResourceBytes(ConfigResourceName),
            MagikaJsonContext.Default.MagikaModelConfig)
            ?? throw new InvalidOperationException("Unable to parse the embedded Magika model configuration.");
        _contentTypes = JsonSerializer.Deserialize(
            ReadResourceBytes(ContentTypesResourceName),
            MagikaJsonContext.Default.DictionaryStringMagikaContentType)
            ?? throw new InvalidOperationException("Unable to parse the embedded Magika content-type knowledge base.");
        ValidateConfig(_config);
        _session = new InferenceSession(ReadResourceBytes(ModelResourceName));
    }

    /// <inheritdoc />
    public LearnedContentPrediction Predict(ReadOnlyMemory<byte> content)
    {
        ThrowIfDisposed();
        if (content.Length == 0)
            return CreateRulePrediction("empty", 1);

        if (content.Length < _config.MinimumFileSizeForModel)
            return CreateRulePrediction(IsValidUtf8(content.Span) ? "txt" : "unknown", 1);
        var features = MagikaFeatureExtractor.Extract(content, _config);
        return RunModel(features);
    }

    /// <inheritdoc />
    public LearnedContentPrediction Predict(Stream content)
    {
        ThrowIfDisposed();
        if (content is null)
            throw new ArgumentNullException(nameof(content));
        if (!content.CanSeek)
            throw new NotSupportedException("Magika classification requires a seekable stream.");
        if (content.Length == 0)
            return CreateRulePrediction("empty", 1);

        if (content.Length < _config.MinimumFileSizeForModel)
        {
            var original = content.Position;
            try
            {
                content.Seek(0, SeekOrigin.Begin);
                var sample = new byte[(int)Math.Min(_config.BlockSize, content.Length)];
                var read = 0;
                while (read < sample.Length)
                {
                    var current = content.Read(sample, read, sample.Length - read);
                    if (current == 0)
                        break;
                    read += current;
                }
                return CreateRulePrediction(IsValidUtf8(new ReadOnlySpan<byte>(sample, 0, read)) ? "txt" : "unknown", 1);
            }
            finally
            {
                content.Seek(original, SeekOrigin.Begin);
            }
        }
        var features = MagikaFeatureExtractor.Extract(content, _config);
        return RunModel(features);
    }

    /// <summary>Releases the ONNX inference session and its native resources.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _session.Dispose();
        _disposed = true;
    }

    private LearnedContentPrediction RunModel(int[] features)
    {
        var tensor = new DenseTensor<int>(features, new[] { 1, features.Length });
        var input = NamedOnnxValue.CreateFromTensor("bytes", tensor);
        using var results = _session.Run(new[] { input });
        var output = results.FirstOrDefault(result => result.Name == "target_label")
            ?? throw new InvalidOperationException("The Magika model did not return target_label.");
        var probabilities = output.AsTensor<float>();
        if (probabilities.Length != _config.TargetLabels.Length)
            throw new InvalidOperationException("The Magika model returned an unexpected label count.");

        var bestIndex = 0;
        for (var index = 1; index < probabilities.Length; index++)
        {
            if (probabilities.GetValue(index) > probabilities.GetValue(bestIndex))
                bestIndex = index;
        }

        var rawLabel = _config.TargetLabels[bestIndex];
        var probability = probabilities.GetValue(bestIndex);
        var threshold = ThresholdFor(rawLabel);
        var thresholdMet = _predictionMode == MagikaPredictionMode.BestGuess || probability >= threshold;
        var outputLabel = _config.OverwriteMap.TryGetValue(rawLabel, out var overwritten)
            ? overwritten
            : rawLabel;
        string? overwriteReason = outputLabel == rawLabel ? null : "overwrite_map";

        if (!thresholdMet)
        {
            outputLabel = ContentType(rawLabel).IsText ? "txt" : "unknown";
            if (!outputLabel.Equals(rawLabel, StringComparison.Ordinal))
                overwriteReason = "low_confidence";
        }

        return CreatePrediction(rawLabel, outputLabel, probability, threshold, thresholdMet, overwriteReason);
    }

    private LearnedContentPrediction CreateRulePrediction(string outputLabel, double probability)
        => CreatePrediction("undefined", outputLabel, probability, 1, true, null);

    private LearnedContentPrediction CreatePrediction(
        string rawLabel,
        string outputLabel,
        double probability,
        double threshold,
        bool thresholdMet,
        string? overwriteReason)
    {
        var contentType = ContentType(outputLabel);
        return new LearnedContentPrediction
        {
            Provider = "Magika",
            ModelId = BundledModelId,
            RawLabel = rawLabel,
            OutputLabel = outputLabel,
            Extension = contentType.Extensions.FirstOrDefault(),
            ExtensionAliases = contentType.Extensions.ToArray(),
            MimeType = contentType.MimeType,
            Probability = probability,
            Threshold = threshold,
            ThresholdMet = thresholdMet,
            PredictionMode = _predictionMode.ToString(),
            OverwriteReason = overwriteReason,
            IsText = contentType.IsText
        };
    }

    private double ThresholdFor(string label)
    {
        return _predictionMode switch
        {
            MagikaPredictionMode.BestGuess => 0,
            MagikaPredictionMode.MediumConfidence => _config.MediumConfidenceThreshold,
            _ => _config.Thresholds.TryGetValue(label, out var threshold)
                ? threshold
                : _config.MediumConfidenceThreshold
        };
    }

    private MagikaContentType ContentType(string label)
        => _contentTypes.TryGetValue(label, out var contentType)
            ? contentType
            : throw new InvalidOperationException("The Magika content-type knowledge base has no entry for '" + label + "'.");

    private static bool IsValidUtf8(ReadOnlySpan<byte> content)
    {
        try
        {
            _ = new UTF8Encoding(false, true).GetString(content.ToArray());
            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }

    private static void ValidateConfig(MagikaModelConfig config)
    {
        if (config.BeginningSize <= 0 || config.MiddleSize != 0 || config.EndSize <= 0)
            throw new InvalidOperationException("The bundled Magika feature configuration is unsupported.");
        if (config.MinimumFileSizeForModel <= 0 ||
            config.MinimumFileSizeForModel > config.BeginningSize)
            throw new InvalidOperationException("The bundled Magika minimum file size is invalid.");
        if (config.TargetLabels.Length == 0)
            throw new InvalidOperationException("The bundled Magika label space is empty.");
    }

    private static byte[] ReadResourceBytes(string resourceName)
    {
        using var stream = typeof(MagikaContentClassifier).Assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException("Embedded Magika resource '" + resourceName + "' could not be opened.");
        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        return memory.ToArray();
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(MagikaContentClassifier));
    }
}
