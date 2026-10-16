namespace FileInspectorX;

internal static partial class ReportContentReader
{
    private sealed class AdmittedOptional
    {
        internal bool Claimed;
        internal ContentProfile? Content;
        internal List<(ReportArchiveEntry Entry, byte[] Bytes)> Children = new();
    }

    private static bool TryReadOptional(Stream source, string hash, string name, FileAnalysis analysis, InspectionReportOptions options,
        ReportReadContext context, int depth, CancellationToken token, HashSet<string> issues, out ContentProfile? profile)
    {
        profile = null;
        if (options.ContentReader is null) return false;
        var budgets = context.ReserveNative(depth);
        var request = new InspectionContentReadRequest(source, hash, source.Length, name, analysis.DetectedExtension,
            analysis.DetectedMimeType, analysis.Kind, depth, budgets, token);
        var admitted = InspectionContentReaderInvoker.Invoke(options.ContentReader, request, result =>
        {
            if (result.Disposition == InspectionContentReadDisposition.NotApplicable)
            {
                ValidateNotApplicable(result);
                context.CompleteNative(budgets, result.Work);
                return new AdmittedOptional();
            }
            long selectedBytes = 0;
            if (result.SelectedMembers.Count > options.MaxArchiveEntries)
                throw new InvalidOperationException("A content reader selected more members than its inventory allowance.");
            foreach (var member in result.SelectedMembers) selectedBytes = checked(selectedBytes + member.SizeBytes);
            if (selectedBytes != result.Work.SelectedBytes)
                throw new InvalidOperationException("Selected member work must equal the complete detached payload lengths.");
            context.CompleteNative(budgets, result.Work);
            var noPrimary = result.Disposition is InspectionContentReadDisposition.Refused or InspectionContentReadDisposition.Malformed;
            var content = context.AdmitContent(result.Content, issues, optionalReader: true, suppressText: noPrimary);
            if (noPrimary)
            {
                content.Status = result.Disposition == InspectionContentReadDisposition.Malformed ? InspectionStageStatus.Failed : InspectionStageStatus.Unavailable;
                issues.Add(result.Disposition == InspectionContentReadDisposition.Malformed ? "content:reader-malformed" : "content:reader-refused");
            }
            var response = new AdmittedOptional { Claimed = true, Content = content };
            var identities = new HashSet<(string, int)>();
            foreach (var member in result.SelectedMembers)
            {
                token.ThrowIfCancellationRequested();
                if (!identities.Add((member.Id, member.Ordinal))) throw new InvalidOperationException("Selected member identities must be unique.");
                var entry = content.Entries.SingleOrDefault(e => e.InventorySource == ReportArchiveInventorySource.ContentReader &&
                    e.MemberId == member.Id && e.Ordinal == member.Ordinal);
                if (entry is null) { issues.Add("content:selected-member-identity-not-retained"); continue; }
                if (member.Kind != ReportArchiveEntryKind.File || entry.Kind != member.Kind ||
                    entry.DeclaredSizeBytes.HasValue && member.DeclaredSizeBytes.HasValue && entry.DeclaredSizeBytes != member.DeclaredSizeBytes)
                    throw new InvalidOperationException("Selected member identity does not match its native inventory.");
                if (member.SizeBytes > options.MaxEntryBytes || member.SizeBytes > context.RemainingExpandedBytes)
                { issues.Add("content:selected-member-byte-limit"); continue; }
                // The bridge's detached copy was charged by Work.SelectedBytes. Charge this Core-owned copy separately.
                context.AccountExpandedBytes(checked((int)member.SizeBytes));
                var bytes = new byte[checked((int)member.SizeBytes)];
                using (var input = member.OpenRead())
                {
                    var offset = 0;
                    while (offset < bytes.Length)
                    {
                        token.ThrowIfCancellationRequested();
                        var count = input.Read(bytes, offset, bytes.Length - offset);
                        if (count == 0) throw new InvalidOperationException("A detached member ended before its declared complete length.");
                        offset += count;
                    }
                    if (input.ReadByte() != -1) throw new InvalidOperationException("A detached member exceeded its declared complete length.");
                }
                token.ThrowIfCancellationRequested();
                entry.SizeBytes = bytes.LongLength;
                entry.Sha256 = FileInspector.ReportHash(bytes);
                response.Children.Add((entry, bytes));
            }
            return response;
        }, token);
        if (!admitted.Claimed) return false;
        // Native owners, source leases and the reader invocation gate have all ended before recursion.
        foreach (var child in admitted.Children)
            child.Entry.Report = context.ReadChild(child.Bytes, child.Entry.Name, depth, issues);
        profile = admitted.Content!;
        return true;
    }

    private static void ValidateNotApplicable(InspectionContentReadResult result)
    {
        var content = result.Content;
        if (content.Text is null || content.Text.Length != 0 || content.Extraction is not null ||
            content.Metadata is null || content.Metadata.Count != 0 || content.Facts is null || content.Facts.Count != 0 ||
            content.Entries is null || content.Entries.Count != 0 || content.Issues is null || content.Issues.Count != 0 ||
            content.DocumentUnits is null || content.DocumentUnits.Count != 0 || content.Diagnostics is null || content.Diagnostics.Count != 0 ||
            content.Omissions is null || content.Omissions.Count != 0 || content.Regions is null || content.Regions.Count != 0 ||
            content.Keywords is null || content.Keywords.Count != 0 || content.TextFingerprint is null || content.TextFingerprint.Count != 0 ||
            content.Status != InspectionStageStatus.NotApplicable || result.SelectedMembers.Count != 0 || result.Work.SelectedBytes != 0 ||
            result.Work.ReadBytes != 0 || result.Work.DecodedBytes != 0 || result.Work.DecompressionWorkBytes != 0)
            throw new InvalidOperationException("NotApplicable must contain no source content, selected members or work.");
    }

    private static void ReadClaimedZipInventory(Stream source, ContentProfile profile, InspectionReportOptions options,
        ReportReadContext context, HashSet<string> issues)
    {
        source.Position = 0;
        var first = source.ReadByte(); var second = source.ReadByte(); source.Position = 0;
        if (first != 'P' || second != 'K') return;
        if (profile.Entries.Count >= options.MaxArchiveEntries) { issues.Add("content:archive-entry-count-limit"); return; }
        var inventoryOptions = options.Copy();
        inventoryOptions.MaxArchiveEntries = options.MaxArchiveEntries - profile.Entries.Count;
        var inventory = new ContentProfile();
        var metadata = new Dictionary<string, string>(StringComparer.Ordinal);
        try { ReadZip(source, inventory, metadata, issues, inventoryOptions, context, new List<(ReportArchiveEntry Item, byte[] Bytes)>(), inventoryOnly: true); }
        catch (Exception ex) when (ex is IOException or InvalidDataException or NotSupportedException) { issues.Add("content:zip-directory-unreadable"); }
        inventory.Metadata = metadata.ToDictionary(item => "RawZip." + item.Key, item => item.Value, StringComparer.Ordinal);
        inventory = context.AdmitContent(inventory, issues, optionalReader: false);
        profile.Entries = profile.Entries.Concat(inventory.Entries).ToArray();
        // Raw ZIP identity remains distinct from native payload/relationship identity; no display-name joins.
        var merged = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var item in profile.Metadata) merged.Add(item.Key, item.Value);
        foreach (var item in inventory.Metadata)
        {
            if (merged.Count >= options.MaxFacts) { issues.Add("content:fact-count-limit"); break; }
            if (!merged.ContainsKey(item.Key)) merged.Add(item.Key, item.Value);
        }
        profile.Metadata = merged;
    }
}
