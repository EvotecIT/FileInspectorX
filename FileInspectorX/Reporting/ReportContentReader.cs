using System.Text;

namespace FileInspectorX;

internal static partial class ReportContentReader
{
    internal static ContentProfile Read(byte[] bytes, FileAnalysis analysis, InspectionReportOptions options)
    {
        var profile = new ContentProfile();
        var metadata = new Dictionary<string, string>(StringComparer.Ordinal);
        var issues = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            if (bytes.Length >= 4 && bytes[0] == 'P' && bytes[1] == 'K') ReadZip(bytes, profile, metadata, issues, options);
            else if (analysis.DetectedExtension == "tar") ReadTar(bytes, profile, metadata, issues, options);
            else if (TryImage(bytes, metadata))
            {
                profile.Reader = "image-header";
                issues.Add("content:pixels-and-ocr-not-inspected");
            }
            else if (analysis.DetectedExtension == "pdf")
            {
                profile.Reader = "pdf-signals";
                metadata["Scope"] = "Direct lexical signals only; text, page tree, compressed objects and rendering require a PDF engine.";
                issues.Add("content:pdf-text-extraction-unavailable");
            }
            else if (InspectHelpers.IsText(analysis.Detection) || analysis.Kind == ContentKind.Text)
            {
                profile.Reader = "utf-text";
                ReadText(bytes, profile, metadata, issues, options);
            }
            else
            {
                profile.Reader = "unsupported";
                issues.Add("content:reader-unavailable");
            }
        }
        catch (Exception ex) when (ex is IOException or System.Xml.XmlException or ArgumentException or System.Text.DecoderFallbackException)
        {
            issues.Add("content:invalid-or-unreadable");
            profile.Status = InspectionStageStatus.Failed;
        }
        profile.Metadata = metadata;
        profile.Issues = issues.OrderBy(x => x, StringComparer.Ordinal).ToArray();
        if (profile.Status != InspectionStageStatus.Failed)
            profile.Status = issues.Count == 0 ? InspectionStageStatus.Completed : InspectionStageStatus.Partial;
        ReportText.Enrich(profile);
        return profile;
    }

    private static void ReadText(byte[] bytes, ContentProfile profile, Dictionary<string, string> metadata, HashSet<string> issues, InspectionReportOptions options)
    {
        // StreamReader honors UTF BOMs, while strict UTF-8 avoids silently replacing invalid binary bytes.
        using var input = new MemoryStream(bytes, writable: false);
        using var reader = new StreamReader(input, new UTF8Encoding(false, true), true, 4096);
        var chars = new char[Math.Min(options.MaxTextCharacters, 4096)];
        var text = new StringBuilder();
        while (text.Length < options.MaxTextCharacters)
        {
            InspectionOperation.CheckCancellation();
            var count = reader.Read(chars, 0, Math.Min(chars.Length, options.MaxTextCharacters - text.Length));
            if (count == 0) break;
            text.Append(chars, 0, count);
        }
        if (reader.Read() >= 0) issues.Add("content:text-character-limit");
        profile.Text = text.ToString();
        metadata["Encoding"] = reader.CurrentEncoding.WebName;
        metadata["SampledLines"] = (profile.Text.Length == 0 ? 0 : profile.Text.Count(c => c == '\n') + 1).ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    private static bool TryImage(byte[] data, Dictionary<string, string> metadata)
    {
        int width = 0, height = 0;
        string? format = null;
        if (data.Length >= 24 && data[0] == 137 && data[1] == 80 && data[2] == 78 && data[3] == 71 &&
            data[4] == 13 && data[5] == 10 && data[6] == 26 && data[7] == 10 && Encoding.ASCII.GetString(data, 12, 4) == "IHDR")
        { format = "PNG"; width = Big32(data, 16); height = Big32(data, 20); }
        else if (data.Length >= 10 && (Encoding.ASCII.GetString(data, 0, 6) is "GIF87a" or "GIF89a"))
        { format = "GIF"; width = data[6] | data[7] << 8; height = data[8] | data[9] << 8; }
        else if (data.Length >= 4 && data[0] == 255 && data[1] == 216)
        {
            format = "JPEG";
            for (var offset = 2; offset + 4 <= data.Length;)
            {
                InspectionOperation.CheckCancellation();
                if (data[offset++] != 255) break;
                while (offset < data.Length && data[offset] == 255) offset++;
                if (offset >= data.Length) break;
                var marker = data[offset++];
                if (marker is 0xD9 or 0xDA) break;
                if (marker is 0x01 or >= 0xD0 and <= 0xD7) continue;
                if (offset + 2 > data.Length) break;
                var length = data[offset] << 8 | data[offset + 1];
                if (length < 2 || offset + length > data.Length) break;
                if (marker is >= 0xC0 and <= 0xCF && marker is not 0xC4 and not 0xC8 and not 0xCC && length >= 8)
                { height = data[offset + 3] << 8 | data[offset + 4]; width = data[offset + 5] << 8 | data[offset + 6]; break; }
                offset += length;
            }
        }
        if (format == null) return false;
        metadata["Format"] = format;
        if (width > 0 && height > 0)
        { metadata["Width"] = width.ToString(System.Globalization.CultureInfo.InvariantCulture); metadata["Height"] = height.ToString(System.Globalization.CultureInfo.InvariantCulture); }
        return true;
    }

    private static int Big32(byte[] data, int offset) => data[offset] << 24 | data[offset + 1] << 16 | data[offset + 2] << 8 | data[offset + 3];
}
