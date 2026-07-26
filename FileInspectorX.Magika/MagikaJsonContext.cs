using System.Text.Json.Serialization;

namespace FileInspectorX.Magika;

[JsonSourceGenerationOptions(GenerationMode = JsonSourceGenerationMode.Metadata)]
[JsonSerializable(typeof(MagikaModelConfig))]
[JsonSerializable(typeof(Dictionary<string, MagikaContentType>))]
internal sealed partial class MagikaJsonContext : JsonSerializerContext
{
}
