using System.IO.Compression;
using System.Text;
using System.Xml;

namespace FileInspectorX;

internal static partial class ReportContentReader
{
    private static void ReadZip(Stream source, ContentProfile profile, Dictionary<string, string> metadata, HashSet<string> issues, InspectionReportOptions options,
        ReportReadContext context, int depth)
    {
        profile.Reader = "zip-inventory";
        var budget = new ArchiveInspectionBudget(options.MaxArchiveEntries, 4 * 1024 * 1024,
            options.MaxEntryBytes, context.RemainingExpandedBytes, 100);
        source.Position = 0;
        using var input = InspectionInput.FromStream(source, null);
        if (!input.TryOpenZip(budget, out var zip, out var declaredCount) || zip == null)
        { foreach (var issue in budget.Issues) issues.Add(issue); issues.Add("content:zip-directory-unavailable"); return; }
        metadata["DeclaredEntries"] = declaredCount?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "unknown";
        var entries = new List<ReportArchiveEntry>();
        var parts = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        var children = new List<(ReportArchiveEntry Item, byte[] Bytes)>();
        foreach (var entry in zip.Entries)
        {
            if (!budget.TryVisitEntry()) break;
            var item = context.Member(entry.FullName, entry.Length, entry.CompressedLength, entries.Count,
                entry.FullName.EndsWith("/", StringComparison.Ordinal) ? ReportArchiveEntryKind.Directory : ReportArchiveEntryKind.File, issues);
            // Hash only whole members that fit. Bounded inventory still records the rest.
            if (entry.Length <= options.MaxEntryBytes && !entry.FullName.EndsWith("/", StringComparison.Ordinal))
            {
                var content = budget.ReadBytes(entry);
                if (content != null && content.LongLength == entry.Length)
                {
                    item.Sha256 = FileInspector.ReportHash(content);
                    if (!item.NameTruncated && children.Count < options.MaxNestedReports) children.Add((item, content));
                    if (IsContentPart(entry.FullName))
                    {
                        if (!parts.ContainsKey(entry.FullName)) parts.Add(entry.FullName, content);
                        else issues.Add("content:duplicate-package-part");
                    }
                }
                else issues.Add("content:member-not-fully-read");
            }
            else if (!entry.FullName.EndsWith("/", StringComparison.Ordinal))
            {
                issues.Add("content:member-not-fully-read");
                if (IsContentPart(entry.FullName)) issues.Add("content:package-part-size-limit");
            }
            entries.Add(item);
        }
        profile.Entries = entries;
        context.AccountExpandedBytes(checked((int)budget.BytesRead));
        foreach (var issue in budget.Issues) issues.Add(issue);
        var text = new StringBuilder();
        if (parts.ContainsKey("word/document.xml"))
        {
            profile.Reader = "ooxml-word";
            metadata["Scope"] = "Main document text and tables; no layout, drawings, revisions, headers or embedded object interpretation.";
            issues.Add("content:ooxml-layout-and-embedded-content-not-inspected");
            var document = Load(parts["word/document.xml"], issues, options, WordNamespace);
            if (document != null)
            {
                metadata["Paragraphs"] = Nodes(document, "p", WordNamespace).Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
                metadata["Tables"] = Nodes(document, "tbl", WordNamespace).Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
                foreach (XmlNode paragraph in Nodes(document, "p", WordNamespace)) Append(text,
                    string.Concat(Nodes(paragraph, "t", WordNamespace).Cast<XmlNode>().Select(n => n.InnerText)), issues, options);
            }
        }
        else if (parts.ContainsKey("xl/workbook.xml"))
        {
            profile.Reader = "ooxml-excel";
            metadata["Scope"] = "Sheet names, stored cell values and formulas; formulas are never calculated.";
            issues.Add("content:spreadsheet-formulas-not-calculated");
            ReadWorkbook(parts, text, metadata, issues, options);
        }
        else if (parts.ContainsKey("ppt/presentation.xml"))
        {
            profile.Reader = "ooxml-powerpoint";
            metadata["Scope"] = "Slide text from stored slide parts; no rendering, speaker notes or embedded objects.";
            issues.Add("content:presentation-layout-and-notes-not-inspected");
            Load(parts["ppt/presentation.xml"], issues, options, PresentationNamespace);
            var slides = parts.Where(p => p.Key.StartsWith("ppt/slides/slide", StringComparison.Ordinal) && p.Key.EndsWith(".xml", StringComparison.Ordinal)).OrderBy(p => p.Key, StringComparer.Ordinal).ToArray();
            metadata["SampledSlides"] = slides.Length.ToString(System.Globalization.CultureInfo.InvariantCulture);
            foreach (var slide in slides)
            {
                var document = Load(slide.Value, issues, options, PresentationNamespace);
                if (document != null) foreach (XmlNode node in Nodes(document, "t", DrawingNamespace)) Append(text, node.InnerText, issues, options);
            }
        }
        profile.Text = text.ToString();
        // Office package parts are implementation details; a later document provider owns their richer interpretation.
        if (profile.Reader == "zip-inventory")
        {
            foreach (var child in children) child.Item.Report = context.ReadChild(child.Bytes, child.Item.Name, depth, issues);
            if (options.MaxNestedReports > 0 && options.MaxNestedDepth > 0 && entries.Count(e => e.Sha256 != null) > children.Count)
                issues.Add("content:nested-report-limit");
        }
    }

    private const string WordNamespace = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
    private const string SheetNamespace = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
    private const string DrawingNamespace = "http://schemas.openxmlformats.org/drawingml/2006/main";
    private const string PresentationNamespace = "http://schemas.openxmlformats.org/presentationml/2006/main";
    private static bool IsContentPart(string name) => name == "word/document.xml" || name == "xl/workbook.xml" || name == "xl/sharedStrings.xml" || name == "ppt/presentation.xml" ||
        (name.StartsWith("xl/worksheets/", StringComparison.Ordinal) || name.StartsWith("ppt/slides/", StringComparison.Ordinal)) && name.EndsWith(".xml", StringComparison.Ordinal);
    private static XmlNodeList Nodes(XmlNode node, string localName, string ns)
        => node.SelectNodes(".//*[local-name()='" + localName + "' and (namespace-uri()='" + ns + "' or namespace-uri()='" + StrictNamespace(ns) + "')]")!;
    private static string StrictNamespace(string ns) => ns.Replace("http://schemas.openxmlformats.org/", "http://purl.oclc.org/ooxml/").Replace("/2006/main", "/main");
    private static XmlDocument? Load(byte[] bytes, HashSet<string> issues, InspectionReportOptions options, string expectedNamespace)
    {
        using var stream = new MemoryStream(bytes, writable: false);
        if (BoundedXmlDocument.TryLoad(stream, options.MaxEntryBytes, out var document))
        {
            var ns = document?.DocumentElement?.NamespaceURI;
            if (ns == expectedNamespace || ns == StrictNamespace(expectedNamespace)) return document;
            issues.Add("content:package-xml-namespace-unsupported"); return null;
        }
        issues.Add("content:package-xml-invalid-or-limited"); return null;
    }
    private static void Append(StringBuilder text, string value, HashSet<string> issues, InspectionReportOptions options)
    {
        InspectionOperation.CheckCancellation();
        if (value.Length == 0) return;
        var remaining = options.MaxTextCharacters - text.Length;
        if (value.Length + 1 > remaining) issues.Add("content:text-character-limit");
        if (remaining <= 0) return;
        text.Append(ReportReadContext.Prefix(value, remaining));
        if (text.Length < options.MaxTextCharacters) text.Append('\n');
    }

    private static void ReadWorkbook(Dictionary<string, byte[]> parts, StringBuilder text, Dictionary<string, string> metadata, HashSet<string> issues, InspectionReportOptions options)
    {
        var workbook = Load(parts["xl/workbook.xml"], issues, options, SheetNamespace);
        if (workbook != null)
        {
            var names = Nodes(workbook, "sheet", SheetNamespace).Cast<XmlNode>().Select(n => n.Attributes?["name"]?.Value ?? "").ToArray();
            metadata["Sheets"] = names.Length.ToString(System.Globalization.CultureInfo.InvariantCulture);
            metadata["SheetNames"] = string.Join(", ", names);
        }
        var shared = new List<string>();
        if (parts.TryGetValue("xl/sharedStrings.xml", out var sharedBytes))
        {
            var document = Load(sharedBytes, issues, options, SheetNamespace);
            if (document != null) foreach (XmlNode item in Nodes(document, "si", SheetNamespace))
                shared.Add(string.Concat(Nodes(item, "t", SheetNamespace).Cast<XmlNode>().Select(n => n.InnerText)));
        }
        var cells = 0; var formulas = 0;
        foreach (var part in parts.Where(p => p.Key.StartsWith("xl/worksheets/", StringComparison.Ordinal)).OrderBy(p => p.Key, StringComparer.Ordinal))
        {
            var document = Load(part.Value, issues, options, SheetNamespace);
            if (document == null) continue;
            foreach (XmlNode cell in Nodes(document, "c", SheetNamespace))
            {
                cells++;
                var formula = Nodes(cell, "f", SheetNamespace).Cast<XmlNode>().FirstOrDefault();
                if (formula != null) { formulas++; Append(text, "=" + formula.InnerText, issues, options); }
                var value = Nodes(cell, "v", SheetNamespace).Cast<XmlNode>().FirstOrDefault()?.InnerText;
                var type = cell.Attributes?["t"]?.Value;
                if (type == "s")
                {
                    if (int.TryParse(value, out var index) && index >= 0 && index < shared.Count) value = shared[index];
                    else { issues.Add("content:shared-string-unavailable"); value = null; }
                }
                else if (type == "inlineStr") value = string.Concat(Nodes(cell, "t", SheetNamespace).Cast<XmlNode>().Select(n => n.InnerText));
                if (value != null) Append(text, value, issues, options);
            }
        }
        metadata["SampledCells"] = cells.ToString(System.Globalization.CultureInfo.InvariantCulture);
        metadata["SampledFormulas"] = formulas.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }
}
