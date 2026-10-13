namespace FileInspectorX;

internal static partial class ReportContentReader
{
    private static void ReadTar(Stream source, ContentProfile profile, Dictionary<string, string> metadata, HashSet<string> issues, InspectionReportOptions options,
        ReportReadContext context, int depth)
    {
        profile.Reader = "tar-inventory";
        var budget = new ArchiveInspectionBudget(options.MaxArchiveEntries, 1, options.MaxEntryBytes, context.RemainingExpandedBytes, 100);
        source.Position = 0;
        var reader = new TarInspectionReader(source, budget);
        var entries = new List<ReportArchiveEntry>();
        var children = new List<(ReportArchiveEntry Item, byte[] Bytes)>();
        while (reader.MoveNext())
        {
            bool regularFile = reader.Type is 0 or (byte)'0';
            var entry = context.Member(reader.Name, reader.Size, reader.Size, entries.Count,
                regularFile ? ReportArchiveEntryKind.File : reader.Type == (byte)'5' ? ReportArchiveEntryKind.Directory : ReportArchiveEntryKind.Other, issues);
            if (regularFile && reader.Size <= options.MaxEntryBytes)
            {
                using var payload = budget.OpenTarPayload(source, reader.Size, options.MaxEntryBytes);
                if (payload != null)
                {
                    using var output = new MemoryStream();
                    payload.CopyTo(output);
                    if (output.Length == reader.Size)
                    {
                        var content = output.ToArray();
                        entry.Sha256 = FileInspector.ReportHash(content);
                        if (!entry.NameTruncated && children.Count < options.MaxNestedReports) children.Add((entry, content));
                    }
                }
            }
            if (regularFile && entry.Sha256 == null) issues.Add("content:member-not-fully-read");
            entries.Add(entry);
        }
        profile.Entries = entries;
        context.AccountExpandedBytes(checked((int)budget.BytesRead));
        foreach (var child in children) child.Item.Report = context.ReadChild(child.Bytes, child.Item.Name, depth, issues);
        if (options.MaxNestedReports > 0 && options.MaxNestedDepth > 0 && entries.Count(e => e.Sha256 != null) > children.Count)
            issues.Add("content:nested-report-limit");
        metadata["SampledEntries"] = entries.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
        foreach (var issue in budget.Issues) issues.Add(issue);
    }
}
