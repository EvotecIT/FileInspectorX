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
                        0.000001);
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
