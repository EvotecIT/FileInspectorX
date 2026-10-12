namespace FileInspectorX;

internal static partial class ReportContentReader
{
    private static void ReadTar(byte[] bytes, ContentProfile profile, Dictionary<string, string> metadata, HashSet<string> issues, InspectionReportOptions options)
    {
        profile.Reader = "tar-inventory";
        var budget = new ArchiveInspectionBudget(options.MaxArchiveEntries, 1, options.MaxEntryBytes, options.MaxExpandedBytes, 100);
        using var source = new MemoryStream(bytes, writable: false);
        var reader = new TarInspectionReader(source, budget);
        var entries = new List<ReportArchiveEntry>();
        while (reader.MoveNext())
        {
            var entry = new ReportArchiveEntry { Name = reader.Name, SizeBytes = reader.Size, CompressedBytes = reader.Size };
            bool regularFile = reader.Type is 0 or (byte)'0';
            if (regularFile && reader.Size <= options.MaxEntryBytes)
            {
                using var payload = budget.OpenTarPayload(source, reader.Size, options.MaxEntryBytes);
                if (payload != null)
                {
                    using var output = new MemoryStream();
                    payload.CopyTo(output);
                    if (output.Length == reader.Size) entry.Sha256 = FileInspector.ReportHash(output.ToArray());
                }
            }
            if (regularFile && entry.Sha256 == null) issues.Add("content:member-not-fully-read");
            entries.Add(entry);
        }
        profile.Entries = entries;
        metadata["SampledEntries"] = entries.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
        foreach (var issue in budget.Issues) issues.Add(issue);
    }
}
