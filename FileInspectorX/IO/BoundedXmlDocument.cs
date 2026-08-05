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
    {
        document = null!;
        if (maxBytes <= 0 || maxDepth < 1) return false;

        try
        {
            using var bounded = new MemoryStream();
            var buffer = new byte[8192];
            long total = 0;
            while (true)
            {
                var remainingWithSentinel = maxBytes - total + 1;
                if (remainingWithSentinel <= 0) return false;
                var requested = (int)Math.Min(buffer.Length, remainingWithSentinel);
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
                    if (preflight.Depth > maxDepth) return false;
                }
            }

            bounded.Position = 0;
            using var reader = XmlReader.Create(bounded, settings);
            var loaded = new XmlDocument { XmlResolver = null };
            loaded.Load(reader);
            document = loaded;
            return true;
        }
        catch (OutOfMemoryException)
        {
            throw;
        }
        catch
        {
            return false;
        }
    }
}
