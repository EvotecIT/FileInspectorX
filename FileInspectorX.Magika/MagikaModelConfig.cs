using System.Text.Json.Serialization;

namespace FileInspectorX.Magika;

internal sealed class MagikaModelConfig
{
    [JsonPropertyName("beg_size")]
    public int BeginningSize { get; set; }

    [JsonPropertyName("mid_size")]
    public int MiddleSize { get; set; }

    [JsonPropertyName("end_size")]
    public int EndSize { get; set; }

    [JsonPropertyName("medium_confidence_threshold")]
    public double MediumConfidenceThreshold { get; set; }

    [JsonPropertyName("min_file_size_for_dl")]
    public int MinimumFileSizeForModel { get; set; }

    [JsonPropertyName("padding_token")]
    public int PaddingToken { get; set; }

    [JsonPropertyName("block_size")]
    public int BlockSize { get; set; }

    [JsonPropertyName("target_labels_space")]
    public string[] TargetLabels { get; set; } = Array.Empty<string>();

    [JsonPropertyName("thresholds")]
    public Dictionary<string, double> Thresholds { get; set; } = new(StringComparer.Ordinal);

    [JsonPropertyName("overwrite_map")]
    public Dictionary<string, string> OverwriteMap { get; set; } = new(StringComparer.Ordinal);
}

internal sealed class MagikaContentType
{
    [JsonPropertyName("mime_type")]
    public string? MimeType { get; set; }

    [JsonPropertyName("extensions")]
    public string[] Extensions { get; set; } = Array.Empty<string>();

    [JsonPropertyName("is_text")]
    public bool IsText { get; set; }
}
