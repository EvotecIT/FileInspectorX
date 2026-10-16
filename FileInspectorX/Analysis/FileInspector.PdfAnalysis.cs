using System.Globalization;
using System.Text;

namespace FileInspectorX;

public static partial class FileInspector
{
    /// <summary>
    /// Collects PDF name-token hints outside comments, strings and stream payloads. This deliberately
    /// does not resolve object references, decompress object streams or establish document validity.
    /// </summary>
    private static void AnalyzePdf(InspectionInput input, FileAnalysis result)
    {
        var issues = new HashSet<string>(StringComparer.Ordinal) { "pdf:lexical-inspection-only" };
        try
        {
            using var source = input.OpenRead();
            int cap = Math.Max(0, Math.Min(OperationSettings.DetectionReadBudgetBytes, 1 << 20));
            var bytes = new byte[(int)Math.Min(source.Length, cap)];
            int read = ReadAvailable(source, bytes, 0, bytes.Length);
            if (source.Length > read) issues.Add("pdf:prefix-only");
            var text = Latin1String(bytes);
            var names = new HashSet<string>(StringComparer.Ordinal);
            int depth = 0, startXrefs = 0, filespecs = 0, streamLength = -1;
            for (int index = 0; index < read;)
            {
                InspectionOperation.CheckCancellation();
                char current = text[index];
                if (IsPdfWhitespace(current)) { index++; continue; }
                if (current == '%') { SkipPdfComment(text, ref index); continue; }
                if (current == '(')
                {
                    if (!SkipPdfLiteralString(text, ref index)) { issues.Add("pdf:unterminated-string"); break; }
                    continue;
                }
                if (current == '<')
                {
                    if (index + 1 < read && text[index + 1] == '<') { if (depth == 0) streamLength = -1; depth++; index += 2; }
                    else
                    {
                        int end = text.IndexOf('>', index + 1);
                        if (end < 0) { issues.Add("pdf:unterminated-hex-string"); break; }
                        index = end + 1;
                    }
                    continue;
                }
                if (current == '>' && index + 1 < read && text[index + 1] == '>')
                { depth = Math.Max(0, depth - 1); index += 2; continue; }
                if (current == '/')
                {
                    var name = ReadPdfName(text, ref index);
                    if (depth > 0)
                    {
                        names.Add(name);
                        if (name == "Filespec") filespecs++;
                        if (name == "Length") streamLength = ReadDirectPdfStreamLength(text, index);
                    }
                    continue;
                }
                if (IsPdfDelimiter(current)) { index++; continue; }
                int start = index;
                while (index < read && !IsPdfDelimiter(text[index])) index++;
                var token = text.Substring(start, index - start);
                if (token == "startxref") startXrefs++;
                if (token != "stream") continue;

                issues.Add("pdf:stream-content-not-inspected");
                // An indirect or invalid length cannot safely establish where arbitrary binary
                // data ends. Stop instead of treating its embedded bytes as PDF names.
                if (streamLength < 0 || !SkipPdfStream(text, ref index, streamLength))
                { issues.Add("pdf:stream-boundary-unavailable"); break; }
                streamLength = -1;
            }
            if (names.Contains("JavaScript") || names.Contains("JS")) result.Flags |= ContentFlags.PdfHasJavaScript;
            if (names.Contains("OpenAction")) result.Flags |= ContentFlags.PdfHasOpenAction;
            if (names.Contains("AA")) result.Flags |= ContentFlags.PdfHasAA;
            if (names.Contains("EmbeddedFiles") || names.Contains("Filespec") && names.Contains("EF")) result.Flags |= ContentFlags.PdfHasEmbeddedFiles;
            if (names.Contains("Launch")) result.Flags |= ContentFlags.PdfHasLaunch;
            if (names.Contains("Names")) result.Flags |= ContentFlags.PdfHasNamesTree;
            if (filespecs > 3) result.Flags |= ContentFlags.PdfHasManyEmbeddedFiles;
            if (names.Contains("XFA")) result.Flags |= ContentFlags.PdfHasXfa;
            if (names.Contains("Encrypt")) result.Flags |= ContentFlags.PdfEncrypted;
            if (names.Contains("ObjStm")) issues.Add("pdf:compressed-objects-not-inspected");
            if (startXrefs > 2) result.Flags |= ContentFlags.PdfManyIncrementalUpdates;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not OperationCanceledException)
        { issues.Add("pdf:read-unavailable"); }
        result.AnalysisComplete = false;
        result.AnalysisIssues = MergeAnalysisIssues(result.AnalysisIssues, issues);
    }

    private static bool IsPdfWhitespace(char value) => value is '\0' or '\t' or '\n' or '\f' or '\r' or ' ';
    private static bool IsPdfDelimiter(char value) => IsPdfWhitespace(value) || value is '(' or ')' or '<' or '>' or '[' or ']' or '{' or '}' or '/' or '%';

    private static void SkipPdfComment(string text, ref int index)
    { while (index < text.Length && text[index] is not '\n' and not '\r') index++; }

    private static bool SkipPdfLiteralString(string text, ref int index)
    {
        int depth = 1; index++;
        while (index < text.Length)
        {
            char value = text[index++];
            if (value == '\\') { if (index < text.Length) index++; continue; }
            if (value == '(') depth++;
            if (value == ')' && --depth == 0) return true;
        }
        return false;
    }

    private static string ReadPdfName(string text, ref int index)
    {
        var name = new StringBuilder(); index++;
        while (index < text.Length && !IsPdfDelimiter(text[index]))
        {
            if (text[index] == '#' && index + 2 < text.Length &&
                byte.TryParse(text.Substring(index + 1, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var escaped))
            { name.Append((char)escaped); index += 3; }
            else name.Append(text[index++]);
        }
        return name.ToString();
    }

    private static int ReadDirectPdfStreamLength(string text, int index)
    {
        SkipPdfSpaceAndComments(text, ref index);
        int start = index;
        while (index < text.Length && text[index] is >= '0' and <= '9') index++;
        if (index == start || index < text.Length && !IsPdfDelimiter(text[index]) ||
            !int.TryParse(text.Substring(start, index - start), NumberStyles.None, CultureInfo.InvariantCulture, out var length)) return -1;
        SkipPdfSpaceAndComments(text, ref index);
        // A second integer denotes an indirect reference, whose target is outside this lexical pass.
        return index < text.Length && text[index] is >= '0' and <= '9' ? -1 : length;
    }

    private static void SkipPdfSpaceAndComments(string text, ref int index)
    {
        while (index < text.Length)
        {
            if (IsPdfWhitespace(text[index])) { index++; continue; }
            if (text[index] == '%') { SkipPdfComment(text, ref index); continue; }
            break;
        }
    }

    private static bool SkipPdfStream(string text, ref int index, int length)
    {
        if (index < text.Length && text[index] == '\r') index++;
        if (index >= text.Length || text[index] != '\n') return false;
        index++;
        if (length > text.Length - index) return false;
        index += length;
        while (index < text.Length && IsPdfWhitespace(text[index])) index++;
        const string end = "endstream";
        if (index + end.Length > text.Length || string.CompareOrdinal(text, index, end, 0, end.Length) != 0) return false;
        index += end.Length;
        return index == text.Length || IsPdfDelimiter(text[index]);
    }
}
