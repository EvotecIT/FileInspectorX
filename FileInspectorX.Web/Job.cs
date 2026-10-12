using System.Text.Json;
using System.Text.Json.Serialization;

namespace FileInspectorX.Web;

internal sealed class Job
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = string.Empty;
    public string State { get; set; } = "queued";
    public string? Sha256 { get; set; }
    public long SizeBytes { get; set; }
    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;
    public string? Error { get; set; }
}

internal sealed class CatalogFullException : Exception;

internal static class ReportJson
{
    internal static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
        MaxDepth = 64
    };
    internal static void WriteAtomic<T>(string path, T value)
    {
        var temporary = path + ".tmp";
        try { File.WriteAllText(temporary, JsonSerializer.Serialize(value, Options)); File.Move(temporary, path, true); }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
