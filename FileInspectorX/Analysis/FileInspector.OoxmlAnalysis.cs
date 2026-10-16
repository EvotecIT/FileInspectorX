using System.Xml;

namespace FileInspectorX;

public static partial class FileInspector
{
    /// <summary>Reads bounded relationship XML from its original bytes, preserving its declared encoding.</summary>
    private static IReadOnlyList<(string Target, string Mode)> ReadOoxmlRelationships(byte[]? xml, ArchiveInspectionBudget budget)
    {
        var relationships = new List<(string, string)>();
        if (xml == null) return relationships;
        using var source = new MemoryStream(xml, writable: false);
        if (!BoundedXmlDocument.TryLoad(source, OperationSettings.ArchiveMaxEntryReadBytes, out var document, out var outcome, out var issue))
        {
            budget.AddIssue(outcome == StructuredValidationOutcome.Failed
                ? "archive:ooxml-relationships-rejected"
                : "archive:ooxml-relationships-" + (issue ?? "unavailable"));
            return relationships;
        }
        foreach (XmlNode node in document.GetElementsByTagName("*"))
        {
            if (node is XmlElement element && element.LocalName == "Relationship")
                relationships.Add((element.GetAttribute("Target"), element.GetAttribute("TargetMode")));
        }
        return relationships;
    }

    /// <summary>Normalizes workbook-relative external link part names so references and parts share one identity.</summary>
    private static string? ExternalWorkbookLinkPart(string target)
    {
        if (string.IsNullOrWhiteSpace(target) || target.IndexOf(':') >= 0) return null;
        var path = target.Replace('\\', '/');
        if (!path.StartsWith("/", StringComparison.Ordinal)) path = "xl/" + path;
        var parts = new List<string>();
        foreach (var segment in path.Split('/'))
        {
            if (segment.Length == 0 || segment == ".") continue;
            if (segment == "..") { if (parts.Count == 0) return null; parts.RemoveAt(parts.Count - 1); }
            else parts.Add(segment);
        }
        var normalized = string.Join("/", parts);
        return normalized.StartsWith("xl/externalLinks/", StringComparison.OrdinalIgnoreCase) && normalized.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)
            ? normalized : null;
    }
}
