using System.IO.Compression;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace FileInspectorX.Magika.Tests;

public sealed class MagikaReferenceParityTests
{
    [Fact]
    public void Predict_MatchesAllPinnedUpstreamContentExamples()
    {
        var referencePath = Path.Combine(
            AppContext.BaseDirectory,
            "Reference",
            "standard_v3_3-inference_examples_by_content.json.gz");
        using var file = File.OpenRead(referencePath);
        using var gzip = new GZipStream(file, CompressionMode.Decompress);
        var examples = JsonSerializer.Deserialize<List<ReferenceExample>>(gzip)
            ?? throw new InvalidOperationException("Unable to read pinned Magika reference examples.");
        var classifiers = new Dictionary<string, MagikaContentClassifier>(StringComparer.Ordinal)
        {
            ["high_confidence"] = Create(MagikaPredictionMode.HighConfidence),
            ["medium_confidence"] = Create(MagikaPredictionMode.MediumConfidence),
            ["best_guess"] = Create(MagikaPredictionMode.BestGuess)
        };

        try
        {
            foreach (var example in examples)
            {
                var content = Convert.FromBase64String(example.ContentBase64);
                var actual = classifiers[example.PredictionMode].Predict(content);

                Assert.Equal(example.Prediction.Output, actual.OutputLabel);
                if (content.Length >= 8)
                {
                    Assert.Equal(example.Prediction.DeepLearning, actual.RawLabel);
                    Assert.InRange(
                        Math.Abs(example.Prediction.Score - actual.Probability),
                        0,
                        0.000005);
                    Assert.Equal(
                        example.Prediction.OverwriteReason,
                        actual.OverwriteReason ?? "none");
                }
            }
        }
        finally
        {
            foreach (var classifier in classifiers.Values)
                classifier.Dispose();
        }
    }

    private static MagikaContentClassifier Create(MagikaPredictionMode mode)
        => new(new MagikaClassifierOptions { PredictionMode = mode });

    [Fact]
    public void PredictBatch_MatchesPinnedExamplesAndScalarPolicyAcrossAllModes()
    {
        using var file = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "Reference", "standard_v3_3-inference_examples_by_content.json.gz"));
        using var gzip = new GZipStream(file, CompressionMode.Decompress);
        var examples = JsonSerializer.Deserialize<List<ReferenceExample>>(gzip)!;
        foreach (var group in examples.GroupBy(example => example.PredictionMode))
        {
            var mode = group.Key == "high_confidence" ? MagikaPredictionMode.HighConfidence
                : group.Key == "medium_confidence" ? MagikaPredictionMode.MediumConfidence : MagikaPredictionMode.BestGuess;
            using var classifier = new MagikaContentClassifier(new MagikaClassifierOptions { PredictionMode = mode, IntraOpThreadCount = 1 });
            var inputs = group.Select(example => new ReadOnlyMemory<byte>(Convert.FromBase64String(example.ContentBase64))).ToArray();
            var predictions = classifier.PredictBatch(inputs);
            Assert.Equal(inputs.Length, predictions.Count);
            int index = 0;
            foreach (var example in group)
            {
                var scalar = classifier.Predict(inputs[index]);
                var batch = predictions[index++];
                Assert.Equal(example.Prediction.Output, batch.OutputLabel);
                Assert.Equal(scalar.RawLabel, batch.RawLabel);
                Assert.Equal(scalar.OverwriteReason, batch.OverwriteReason);
                Assert.Equal(scalar.ThresholdMet, batch.ThresholdMet);
                Assert.Equal(scalar.Threshold, batch.Threshold);
                Assert.Equal(scalar.MimeType, batch.MimeType);
                Assert.Equal(scalar.ExtensionAliases, batch.ExtensionAliases);
                // The native CPU batch kernel differs from its scalar kernel on
                // identical real features (maximum pinned-corpus delta 0.003493).
                // Keep scalar's tighter upstream score check above; batch also
                // protects every pinned label and all confidence policy fields.
                Assert.InRange(Math.Abs(scalar.Probability - batch.Probability), 0, 0.005);
            }
        }
    }

    private sealed class ReferenceExample
    {
        [JsonPropertyName("prediction_mode")]
        public string PredictionMode { get; set; } = string.Empty;

        [JsonPropertyName("content_base64")]
        public string ContentBase64 { get; set; } = string.Empty;

        [JsonPropertyName("prediction")]
        public ReferencePrediction Prediction { get; set; } = new();
    }

    private sealed class ReferencePrediction
    {
        [JsonPropertyName("dl")]
        public string DeepLearning { get; set; } = string.Empty;

        [JsonPropertyName("output")]
        public string Output { get; set; } = string.Empty;

        [JsonPropertyName("score")]
        public double Score { get; set; }

        [JsonPropertyName("overwrite_reason")]
        public string OverwriteReason { get; set; } = string.Empty;
    }
}
