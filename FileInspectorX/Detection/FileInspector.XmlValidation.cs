using System.Xml;

namespace FileInspectorX;

public static partial class FileInspector
{
    // Full validation differs from the signature scorer's quick XML-root probe.
    private static StructuredValidationOutcome ValidateXmlWellFormed(string xml, out string? issue)
    {
        issue = "xml:validation-error";
        if (string.IsNullOrWhiteSpace(xml)) return StructuredValidationOutcome.Failed;
        const int maxCharacters = 10_000_000;
        if (xml.Length > maxCharacters)
        { issue = "xml:validation-size-limit"; return StructuredValidationOutcome.Skipped; }
        try
        {
            var settings = new XmlReaderSettings {
                DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null,
                MaxCharactersInDocument = Math.Min(maxCharacters, Math.Max(1024L, (long)xml.Length * 4L)),
                MaxCharactersFromEntities = 1024
            };
            long timeoutTicks = TimeoutHelpers.GetTimeoutTicks(Math.Max(0, OperationSettings.XmlWellFormednessTimeoutMs));
            var timer = timeoutTicks > 0 ? System.Diagnostics.Stopwatch.StartNew() : null;
            using var reader = XmlReader.Create(new StringReader(xml), settings);
            bool hasRoot = false;
            while (reader.Read())
            {
                InspectionOperation.CheckCancellation();
                if (TimeoutHelpers.IsExpired(timer, timeoutTicks))
                { issue = "xml:validation-timeout"; return StructuredValidationOutcome.TimedOut; }
                if (reader.NodeType == XmlNodeType.Element)
                {
                    hasRoot = true;
                    if (reader.Depth > 256)
                    { issue = "xml:validation-depth-limit"; return StructuredValidationOutcome.Skipped; }
                }
            }
            if (!hasRoot) return StructuredValidationOutcome.Failed;
            issue = null;
            return StructuredValidationOutcome.Passed;
        }
        catch (XmlException) { return StructuredValidationOutcome.Failed; }
        catch (Exception ex) when (ex is not OutOfMemoryException and not OperationCanceledException)
        { issue = "xml:validation-unavailable"; return StructuredValidationOutcome.Unavailable; }
    }
}
