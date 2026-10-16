using FileInspectorX.OfficeIMO;

namespace FileInspectorX.Web;

internal enum ContentReaderProfile { Builtin, OfficeIMO }

internal static class ContentReaderProfiles
{
    internal static ContentReaderProfile Parse(string value) => value.ToLowerInvariant() switch
    {
        "builtin" => ContentReaderProfile.Builtin,
        "officeimo" => ContentReaderProfile.OfficeIMO,
        _ => throw new ArgumentException("Content reader must be Builtin or OfficeIMO.", nameof(value))
    };

    // Composition occurs only in the isolated child process that performs native parsing.
    internal static IInspectionContentReader? Create(ContentReaderProfile profile) => profile switch
    {
        ContentReaderProfile.Builtin => null,
        ContentReaderProfile.OfficeIMO => new OfficeImoContentReader(),
        _ => throw new ArgumentOutOfRangeException(nameof(profile))
    };
}
