namespace FileInspectorX;

/// <summary>Copies reader DTOs while their invocation gate is held and accounts every retained source field.</summary>
internal sealed partial class ReportContentAdmission
{
    private readonly InspectionReportOptions _options;
    private readonly ReportReadContext _context;
    private readonly HashSet<string> _issues;
    private readonly bool _optional;

    internal ReportContentAdmission(InspectionReportOptions options, ReportReadContext context, HashSet<string> issues, bool optional)
    { _options = options; _context = context; _issues = issues; _optional = optional; }

    internal ContentProfile Copy(ContentProfile source, bool suppressText = false)
    {
        if (source is null) throw Contract("Content is required.");
        Defined(source.Status);
        if (_optional && (Required(source.Regions).Count != 0 || Required(source.Keywords).Count != 0 || Required(source.TextFingerprint).Count != 0))
            throw Contract("Readers return primary evidence; Core owns regions and text enrichment.");
        var originalText = Required(source.Text);
        var text = suppressText ? string.Empty : Text(originalText, _options.MaxTextCharacters);
        var result = new ContentProfile { Text = text, Status = source.Status,
            Reader = Whole(Required(source.Reader), _options.MaxIdentifierCharacters) ?? "unknown" };
        result.Extraction = Extraction(source.Extraction);
        var retainedIssues = new List<string>();
        var sourceIssues = Required(source.Issues);
        for (var i = 0; i < Count(sourceIssues.Count, _options.MaxDiagnostics, "content:diagnostic-count-limit"); i++)
        {
            var issue = Whole(Required(sourceIssues[i]), _options.MaxIdentifierCharacters);
            if (issue is not null) retainedIssues.Add(issue);
        }
        result.Issues = retainedIssues.ToArray();
        var facts = new List<ReportFact>();
        var sourceFacts = Required(source.Facts);
        for (var i = 0; i < Count(sourceFacts.Count, _options.MaxFacts, "content:fact-count-limit"); i++)
        {
            var fact = Fact(Required(sourceFacts[i]));
            if (fact is not null) facts.Add(fact);
        }
        result.Facts = facts.ToArray();
        result.Metadata = Dictionary(Required(source.Metadata));
        result.Entries = Entries(Required(source.Entries));
        result.DocumentUnits = Units(Required(source.DocumentUnits), originalText.Length, text.Length);
        result.Diagnostics = Diagnostics(Required(source.Diagnostics));
        result.Omissions = Omissions(Required(source.Omissions));
        return result;
    }

    internal IReadOnlyList<ReportArchiveEntry> Entries(IReadOnlyList<ReportArchiveEntry> source)
    {
        var result = new List<ReportArchiveEntry>();
        var identities = new HashSet<(ReportArchiveInventorySource, string, int)>();
        for (var i = 0; i < Count(source.Count, _options.MaxArchiveEntries, "content:archive-entry-count-limit"); i++)
        {
            var entry = Required(source[i]);
            Defined(entry.Kind);
            Defined(entry.InventorySource);
            if (_optional && entry.InventorySource is not ReportArchiveInventorySource.Unknown and not ReportArchiveInventorySource.ContentReader)
                throw Contract("Optional readers cannot claim a Core raw inventory scope.");
            var inventorySource = _optional ? ReportArchiveInventorySource.ContentReader : entry.InventorySource;
            if (entry.Ordinal < 0 || entry.SizeBytes < 0 || entry.CompressedBytes < 0 || entry.DeclaredSizeBytes < 0 || entry.SourceNameCharacters < 0)
                throw Contract("Member inventory contains a negative coordinate or size.");
            if (_optional && entry.Report is not null) throw Contract("Readers cannot return descendant reports.");
            var originalName = Required(entry.Name);
            var name = Text(originalName, _options.MaxEntryNameCharacters);
            var id = entry.MemberId is null ? null : Whole(entry.MemberId, _options.MaxIdentifierCharacters);
            if (id is not null && !identities.Add((inventorySource, id, entry.Ordinal))) throw Contract("Member inventory identities must be unique within their producing scope.");
            result.Add(new ReportArchiveEntry { Name = name, MemberId = id, Ordinal = entry.Ordinal, Kind = entry.Kind, InventorySource = inventorySource,
                DeclaredSizeBytes = entry.DeclaredSizeBytes, SizeBytes = entry.SizeBytes, CompressedBytes = entry.CompressedBytes,
                Sha256 = entry.Sha256 is null ? null : Whole(entry.Sha256, 64),
                SourceNameCharacters = Math.Max(originalName.Length, entry.SourceNameCharacters),
                NameTruncated = entry.NameTruncated || name.Length != originalName.Length, Report = _optional ? null : entry.Report });
        }
        return result.ToArray();
    }

    private ReportFact? Fact(ReportFact source)
    {
        Defined(source.Kind); Defined(source.Origin);
        var name = Whole(Required(source.Name), _options.MaxIdentifierCharacters);
        if (name is null) return null;
        var original = Required(source.Value);
        var value = source.Kind == ReportFactKind.Text ? Text(original, _options.MaxFactCharacters) : Whole(original, _options.MaxFactCharacters);
        if (value is null) return null;
        return new ReportFact { Name = name, Value = value, Kind = source.Kind, Origin = source.Origin,
            Truncated = source.Truncated || original.Length != value.Length, Source = Physical(source.Source),
            LogicalSource = Logical(source.LogicalSource), Attributes = Dictionary(Required(source.Attributes)) };
    }

    private ReportExtractionDescriptor? Extraction(ReportExtractionDescriptor? source)
    {
        if (source is null) return null;
        Defined(source.TextBasis);
        var reader = Whole(Required(source.ReaderId), _options.MaxIdentifierCharacters);
        var version = Whole(Required(source.ReaderVersion), _options.MaxIdentifierCharacters);
        var profile = Whole(Required(source.ProfileId), _options.MaxIdentifierCharacters);
        var settings = Required(source.Settings);
        var copied = Dictionary(settings);
        if (string.IsNullOrEmpty(reader) || string.IsNullOrEmpty(version) || string.IsNullOrEmpty(profile) || copied.Count != settings.Count)
        { _issues.Add("content:extraction-descriptor-incomplete"); return null; }
        return new ReportExtractionDescriptor { ReaderId = reader!, ReaderVersion = version!, ProfileId = profile!,
            TextBasis = source.TextBasis, Settings = copied };
    }

    private IReadOnlyDictionary<string, string> Dictionary(IReadOnlyDictionary<string, string> source)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        int count = 0;
        foreach (var item in source)
        {
            if (count++ >= _options.MaxFacts) { _issues.Add("content:fact-count-limit"); break; }
            var key = Required(item.Key); var value = Required(item.Value);
            if (key.Length > _options.MaxIdentifierCharacters || value.Length > _options.MaxFactCharacters)
            { _issues.Add("content:fact-character-limit"); continue; }
            if (!_context.TryAccountCharacters(checked(key.Length + value.Length)))
            { _issues.Add("content:aggregate-character-limit"); continue; }
            if (result.ContainsKey(key)) throw Contract("A reader dictionary contains duplicate ordinal keys.");
            result.Add(key, value);
        }
        return result;
    }

    private int Count(int actual, int maximum, string code)
    {
        if (actual < 0) throw Contract("A collection count cannot be negative.");
        if (actual > maximum) _issues.Add(code);
        return Math.Min(actual, maximum);
    }

    private string Text(string value, int maximum)
    {
        if (value.Length > maximum) _issues.Add("content:field-character-limit");
        var length = Math.Min(maximum, _context.RemainingContentCharacters);
        if (value.Length > _context.RemainingContentCharacters) _issues.Add("content:aggregate-character-limit");
        var retained = ReportReadContext.Prefix(value, length);
        if (!_context.TryAccountCharacters(retained.Length)) throw Contract("Content accounting failed.");
        return retained;
    }

    private string? Whole(string value, int maximum)
    {
        if (value.Length > maximum) { _issues.Add("content:field-character-limit"); return null; }
        if (!_context.TryAccountCharacters(value.Length)) { _issues.Add("content:aggregate-character-limit"); return null; }
        return value;
    }

    private static T Required<T>(T? value) where T : class => value ?? throw Contract("Reader output cannot contain null fields or items.");
    private static void Defined<T>(T value) where T : struct
    { if (!Enum.IsDefined(typeof(T), value)) throw Contract("Reader output contains an unknown enum value."); }
    private static InvalidOperationException Contract(string message) => new("Invalid content reader response: " + message);
}
