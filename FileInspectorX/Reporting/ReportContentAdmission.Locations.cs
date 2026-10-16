namespace FileInspectorX;

internal sealed partial class ReportContentAdmission
{
    private ReportSourceLocation? Physical(ReportSourceLocation? source)
    {
        if (source is null) return null;
        Defined(source.ByteSpace);
        if (source.ByteOffset < 0 || source.ByteLength < 0) throw Contract("Physical source coordinates cannot be negative.");
        return new ReportSourceLocation { Part = Optional(source.Part), Record = Optional(source.Record),
            ByteSpace = source.ByteSpace, ByteOffset = source.ByteOffset, ByteLength = source.ByteLength };
    }

    private string? Optional(string? value) => value is null ? null : Whole(value, _options.MaxIdentifierCharacters);

    private ReportLogicalLocation? Logical(ReportLogicalLocation? source)
    {
        if (source is null) return null;
        if (source.LogicalOrder < 0 || source.BlockIndex < 0 || source.SourceBlockIndex < 0 || source.StartLine < 0 || source.EndLine < 0 ||
            source.NormalizedStartLine < 0 || source.NormalizedEndLine < 0 || source.Page < 0 || source.Slide < 0 || source.TableIndex < 0 ||
            source.SourceCharacterOffset < 0 || source.SourceCharacterLength < 0)
            throw Contract("Logical source coordinates cannot be negative.");
        return new ReportLogicalLocation { Part = Optional(source.Part), Story = Optional(source.Story), Sheet = Optional(source.Sheet),
            A1Range = Optional(source.A1Range), BlockAnchor = Optional(source.BlockAnchor), SourceBlockKind = Optional(source.SourceBlockKind),
            HeadingPath = Optional(source.HeadingPath), HierarchyHeadingPath = Optional(source.HierarchyHeadingPath), HeadingSlug = Optional(source.HeadingSlug),
            LogicalOrder = source.LogicalOrder, BlockIndex = source.BlockIndex, SourceBlockIndex = source.SourceBlockIndex,
            StartLine = source.StartLine, EndLine = source.EndLine, NormalizedStartLine = source.NormalizedStartLine,
            NormalizedEndLine = source.NormalizedEndLine, Page = source.Page, Slide = source.Slide, TableIndex = source.TableIndex,
            SourceCharacterOffset = source.SourceCharacterOffset, SourceCharacterLength = source.SourceCharacterLength };
    }

    private IReadOnlyList<ReportDocumentUnit> Units(IReadOnlyList<ReportDocumentUnit> source, int sourceTextLength, int retainedTextLength)
    {
        var result = new List<ReportDocumentUnit>();
        var identities = new HashSet<(string, int)>();
        for (var i = 0; i < Count(source.Count, _options.MaxDocumentUnits, "content:document-unit-count-limit"); i++)
        {
            var unit = Required(source[i]); Defined(unit.Status);
            if (unit.Ordinal < 0 || unit.TextStart < 0 || unit.TextLength < 0 || unit.TextStart.HasValue != unit.TextLength.HasValue ||
                unit.TextStart.HasValue && (long)unit.TextStart.Value + unit.TextLength!.Value > sourceTextLength)
                throw Contract("A document unit has an invalid retained-text span or ordinal.");
            var id = Whole(Required(unit.Id), _options.MaxIdentifierCharacters);
            var kind = Whole(Required(unit.Kind), _options.MaxIdentifierCharacters);
            if (id is null || kind is null) continue;
            if (id.Length == 0 || kind.Length == 0 || !identities.Add((id, unit.Ordinal))) throw Contract("Logical unit occurrence identities must be nonempty and unique.");
            int? start = unit.TextStart; int? length = unit.TextLength;
            var status = unit.Status;
            if (start > retainedTextLength) { start = length = null; status = InspectionStageStatus.Partial; }
            else if (start.HasValue && length > retainedTextLength - start.Value)
            { length = retainedTextLength - start.Value; status = InspectionStageStatus.Partial; }
            result.Add(new ReportDocumentUnit { Id = id, Kind = kind, Ordinal = unit.Ordinal, Status = status,
                Location = Logical(unit.Location), TextStart = start, TextLength = length });
        }
        return result.ToArray();
    }

    private IReadOnlyList<ReportDiagnostic> Diagnostics(IReadOnlyList<ReportDiagnostic> source)
    {
        var result = new List<ReportDiagnostic>();
        for (var i = 0; i < Count(source.Count, _options.MaxDiagnostics, "content:diagnostic-count-limit"); i++)
        {
            var diagnostic = Required(source[i]); Defined(diagnostic.Severity); Defined(diagnostic.Recovery);
            var category = Whole(Required(diagnostic.Category), _options.MaxIdentifierCharacters);
            var code = Whole(Required(diagnostic.Code), _options.MaxIdentifierCharacters);
            if (category is null || code is null) continue;
            result.Add(new ReportDiagnostic { Category = category, Code = code, Message = Text(Required(diagnostic.Message), _options.MaxFactCharacters),
                Severity = diagnostic.Severity, IsRecoverable = diagnostic.IsRecoverable, Recovery = diagnostic.Recovery,
                Source = Physical(diagnostic.Source), LogicalSource = Logical(diagnostic.LogicalSource),
                Attributes = Dictionary(Required(diagnostic.Attributes)) });
        }
        return result.ToArray();
    }

    private IReadOnlyList<ReportContentOmission> Omissions(IReadOnlyList<ReportContentOmission> source)
    {
        var result = new List<ReportContentOmission>();
        for (var i = 0; i < Count(source.Count, _options.MaxDiagnostics, "content:omission-count-limit"); i++)
        {
            var omission = Required(source[i]);
            if (omission.Count < 0) throw Contract("An omission count cannot be negative.");
            var code = Whole(Required(omission.Code), _options.MaxIdentifierCharacters);
            var scope = Whole(Required(omission.Scope), _options.MaxIdentifierCharacters);
            if (code is null || scope is null) continue;
            result.Add(new ReportContentOmission { Code = code, Scope = scope, Count = omission.Count, LogicalSource = Logical(omission.LogicalSource) });
        }
        return result.ToArray();
    }
}
