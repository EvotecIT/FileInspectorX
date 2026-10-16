using System.Collections.ObjectModel;

namespace FileInspectorX;

/// <summary>One compatibility policy for primary-text comparisons and their saved extraction evidence.</summary>
internal static class ReportTextCompatibility
{
    internal static bool CanCompare(InspectionReport left, InspectionReport right)
    {
        if (left.SchemaVersion != 3 || right.SchemaVersion != 3) return false;
        var a = left.Content.Extraction;
        var b = right.Content.Extraction;
        if (!Complete(a) || !Complete(b)) return false;
        if (!string.Equals(a!.ReaderId, b!.ReaderId, StringComparison.Ordinal) ||
            !string.Equals(a.ReaderVersion, b.ReaderVersion, StringComparison.Ordinal) ||
            !string.Equals(a.ProfileId, b.ProfileId, StringComparison.Ordinal) || a.TextBasis != b.TextBasis ||
            a.Settings.Count != b.Settings.Count) return false;
        var first = a.Settings.OrderBy(pair => pair.Key, StringComparer.Ordinal).ToArray();
        var second = b.Settings.OrderBy(pair => pair.Key, StringComparer.Ordinal).ToArray();
        for (var index = 0; index < first.Length; index++)
            if (!string.Equals(first[index].Key, second[index].Key, StringComparison.Ordinal) ||
                !string.Equals(first[index].Value, second[index].Value, StringComparison.Ordinal)) return false;
        return true;
    }

    internal static ReportExtractionDescriptor Copy(ReportExtractionDescriptor source) => new()
    {
        ReaderId = source.ReaderId,
        ReaderVersion = source.ReaderVersion,
        ProfileId = source.ProfileId,
        TextBasis = source.TextBasis,
        Settings = new ReadOnlyDictionary<string, string>(source.Settings.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal))
    };

    private static bool Complete(ReportExtractionDescriptor? descriptor)
    {
        if (descriptor is null || string.IsNullOrWhiteSpace(descriptor.ReaderId) ||
            string.IsNullOrWhiteSpace(descriptor.ReaderVersion) || string.IsNullOrWhiteSpace(descriptor.ProfileId) ||
            descriptor.TextBasis is not (ReportTextBasis.BuiltinPlainText or ReportTextBasis.CanonicalDocumentText) ||
            descriptor.Settings is null) return false;
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var setting in descriptor.Settings)
            if (string.IsNullOrEmpty(setting.Key) || setting.Value is null || !keys.Add(setting.Key)) return false;
        return true;
    }
}
