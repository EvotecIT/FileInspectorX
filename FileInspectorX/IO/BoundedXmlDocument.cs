using System.Xml;

namespace FileInspectorX;

internal static class BoundedXmlDocument
{
    internal const int DefaultMaxDepth = 256;

    internal static bool TryLoad(
        Stream source,
        long maxBytes,
        out XmlDocument document,
        int maxDepth = DefaultMaxDepth)
        => TryLoad(source, maxBytes, out document, out _, out _, maxDepth);

    // Keep rejected XML distinct from an inspection that could not finish.
    internal static bool TryLoad(
        Stream source,
        long maxBytes,
        out XmlDocument document,
        out StructuredValidationOutcome outcome,
        out string? issue,
        int maxDepth = DefaultMaxDepth)
    {
        document = null!;
        outcome = StructuredValidationOutcome.Skipped;
        issue = "size-limit";
        if (maxBytes <= 0) return false;
        if (maxDepth < 1) { issue = "depth-limit"; return false; }

        try
        {
            using var bounded = new MemoryStream();
            var buffer = new byte[8192];
            long total = 0;
            while (true)
            {
                InspectionOperation.CheckCancellation();
                var remaining = maxBytes - total;
                var requested = remaining >= buffer.Length ? buffer.Length : checked((int)remaining + 1);
                var read = source.Read(buffer, 0, requested);
                if (read == 0) break;
                total += read;
                if (total > maxBytes) return false;
                bounded.Write(buffer, 0, read);
            }

            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                IgnoreComments = true,
                IgnoreProcessingInstructions = true,
                IgnoreWhitespace = true,
                CloseInput = false,
                MaxCharactersInDocument = maxBytes,
                MaxCharactersFromEntities = 0
            };

            bounded.Position = 0;
            using (var preflight = XmlReader.Create(bounded, settings))
            {
                while (preflight.Read())
                {
                    InspectionOperation.CheckCancellation();
                    if (preflight.Depth > maxDepth) { issue = "depth-limit"; return false; }
                }
            }

            bounded.Position = 0;
            using var reader = XmlReader.Create(bounded, settings);
            var loaded = new XmlDocument { XmlResolver = null };
            loaded.Load(reader);
            document = loaded;
            outcome = StructuredValidationOutcome.Passed;
            issue = null;
            return true;
        }
        catch (OutOfMemoryException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (XmlException)
        {
            outcome = StructuredValidationOutcome.Failed;
            issue = null;
            return false;
        }
        catch
        {
            outcome = StructuredValidationOutcome.Unavailable;
            issue = "unavailable";
            return false;
        }
    }
}
