using System.Globalization;
using System.Text;
using System.Threading;
using OfficeIMO.Pdf;
using OfficeIMO.Reader;
using OfficeIMO.Excel;
using OfficeIMO.OpenDocument;
using OfficeIMO.PowerPoint;
using OfficeIMO.Rtf;
using OfficeIMO.Word;

namespace FileInspectorX.OfficeIMO;

/// <summary>Detaches native evidence while preflighting every retained string and collection.</summary>
internal sealed partial class Projection
{
    private readonly ContentProfile _content;
    private readonly List<ReportFact> _facts = new();
    private readonly List<ReportDocumentUnit> _units = new();
    private readonly List<ReportDiagnostic> _diagnostics = new();
    private readonly List<ReportContentOmission> _omissions = new();
    private readonly List<ReportArchiveEntry> _entries = new();
    private readonly List<InspectionContentMember> _members = new();
    private readonly StringBuilder _text = new();
    private int _remaining;
    private bool _limited;
    private readonly long _expandedReservation;
    internal Projection(InspectionContentReadRequest request, OfficeImoContentReaderOptions options, string family)
    {
        Budgets = request.Budgets; Name = request.DisplayName;
        _remaining = Budgets.RemainingContentCharacters;
        _expandedReservation = Budgets.NativeExpandedBytes;
        _content = new ContentProfile { Reader = Exact("officeimo-" + family) ?? string.Empty, Status = InspectionStageStatus.Completed };
        var settings = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["projection"] = "TextAndMetadata", ["textSeparator"] = "LF-between-chunks", ["normalization"] = "native-reader-v1",
            ["wordFootnotes"] = "true", ["rtfHeadersAndFooters"] = "true", ["notes"] = options.IncludeNotes.ToString(),
            ["hiddenShapes"] = options.IncludeHiddenShapes.ToString(), ["formulaValues"] = options.UseCachedFormulaResults ? "saved-cache-uncomputed" : "authored-expression-uncomputed",
            ["pdfProfile"] = "Fast", ["pdfParsing"] = "Lenient", ["pdfPreferToUnicode"] = "true", ["pdfWinAnsiFallback"] = "true",
            ["pdfArtifactText"] = "false", ["pageSelection"] = "all-source-pages", ["ocr"] = "none", ["legacyConversion"] = "disabled"
        };
        settings["readerChunkCharacters"] = Math.Max(256, Math.Min(8192, Budgets.MaxTextCharacters)).ToString(CultureInfo.InvariantCulture);
        settings["adapterVersion"] = Version(typeof(OfficeImoContentReader));
        settings["nativeVersion"] = Version(family switch
        {
            "word" => typeof(WordDocument), "excel" => typeof(ExcelDocument), "powerpoint" => typeof(PowerPointPresentation),
            "opendocument" => typeof(OdfDocument), "rtf" => typeof(RtfDocument), "pdf" => typeof(PdfDocument),
            "archive" => typeof(global::OfficeIMO.Archives.ArchiveInspector), _ => typeof(global::OfficeIMO.Drawing.OfficeImageMetadata)
        });
        settings["formatReaderVersion"] = family switch
        {
            "word" => Version(typeof(global::OfficeIMO.Reader.Word.WordDocumentReaderExtensions)),
            "excel" => Version(typeof(global::OfficeIMO.Reader.Excel.ExcelDocumentReaderExtensions)),
            "powerpoint" => Version(typeof(global::OfficeIMO.Reader.PowerPoint.PowerPointPresentationReaderExtensions)),
            "opendocument" => Version(typeof(global::OfficeIMO.Reader.OpenDocument.OdfDocumentReaderExtensions)),
            "rtf" => Version(typeof(global::OfficeIMO.Reader.Rtf.RtfReadResultReaderExtensions)),
            "pdf" => Version(typeof(global::OfficeIMO.Reader.Pdf.PdfDocumentReaderExtensions)), _ => "none"
        };
        string? id = Exact("officeimo.reader"), version = Exact(Version(typeof(OfficeDocumentReadResult))), profile = Exact("fileinspector/finite-text-metadata/v1/" + family);
        IReadOnlyDictionary<string, string> detachedSettings = Attributes(settings);
        if (id != null && version != null && profile != null && detachedSettings.Count == settings.Count)
            _content.Extraction = new ReportExtractionDescriptor
            {
                ReaderId = id, ReaderVersion = version, ProfileId = profile,
                TextBasis = family is "image" or "archive" or "legacy" ? ReportTextBasis.None : ReportTextBasis.CanonicalDocumentText,
                Settings = detachedSettings
            };
    }
    private static string Version(Type type) => type.Assembly.GetName().Version?.ToString() ?? "unknown";
    internal InspectionContentBudgets Budgets { get; }
    internal string Name { get; }
    internal long SnapshotReadBytes { get; set; }
    internal long PayloadReadBytes { get; set; }
    internal long DecompressionWorkBytes { get; set; }
    private long _decodedBytes;
    private long _selectedBytes;
    internal long SelectedCapacity => Budgets.RemainingExpandedBytes / 2;
    // Owner model expansion is not fully instrumented. Charge the entire reservation instead of claiming measured zero.
    internal void ChargeUnknownExpansion() => _decodedBytes = _expandedReservation;

    internal string? Exact(string? value, bool identifier = true)
    {
        if (value == null) return null;
        int limit = identifier ? Budgets.MaxIdentifierCharacters : Budgets.MaxFactCharacters;
        if (value.Length > limit || value.Length > _remaining) { _limited = true; return null; }
        _remaining -= value.Length; return value;
    }
    internal string Prefix(string? value, bool name = false)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        int count = Math.Min(value!.Length, Math.Min(_remaining, name ? Budgets.MaxEntryNameCharacters : Budgets.MaxFactCharacters));
        if (count > 0 && count < value.Length && char.IsHighSurrogate(value[count - 1])) count--;
        _remaining -= count;
        if (count < value.Length) _limited = true;
        return count == value.Length ? value : value.Substring(0, count);
    }
    internal IReadOnlyDictionary<string, string> Attributes(IReadOnlyDictionary<string, string>? source)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (source == null) return result;
        foreach (var item in source)
        {
            if (result.Count >= Budgets.MaxFacts) { _limited = true; break; }
            string? key = Exact(item.Key), value = Exact(item.Value, identifier: false);
            if (key != null && value != null) result[key] = value;
        }
        return result;
    }
    internal void Fact(string name, string? value, ReportFactOrigin origin = ReportFactOrigin.Embedded,
        ReportFactKind kind = ReportFactKind.Text, ReaderLocation? location = null,
        IReadOnlyDictionary<string, string>? attributes = null, ReportSourceLocation? source = null)
    {
        if (value == null) return;
        if (_facts.Count >= Budgets.MaxFacts) { _limited = true; return; }
        string? field = Exact(name);
        if (field == null) return;
        string? retained = kind == ReportFactKind.Text ? Prefix(value) : Exact(value, identifier: false);
        if (retained == null) return;
        _facts.Add(new ReportFact
        {
            Name = field, Value = retained, Kind = kind, Origin = origin,
            Truncated = retained.Length != value.Length, LogicalSource = Location(location),
            Attributes = Attributes(attributes), Source = source
        });
    }
    internal void Diagnostic(string code, string message, ReportDiagnosticSeverity severity = ReportDiagnosticSeverity.Warning,
        ReaderLocation? location = null, string category = "officeimo", bool recoverable = false,
        ReportRecoveryKind recovery = ReportRecoveryKind.None, IReadOnlyDictionary<string, string>? attributes = null)
    {
        if (_diagnostics.Count >= Budgets.MaxDiagnostics) { _limited = true; return; }
        string? retainedCode = Exact(code), retainedCategory = Exact(category);
        if (retainedCode == null || retainedCategory == null) return;
        _diagnostics.Add(new ReportDiagnostic
        {
            Code = retainedCode, Category = retainedCategory, Message = Prefix(message), Severity = severity,
            LogicalSource = Location(location), IsRecoverable = recoverable, Recovery = recovery, Attributes = Attributes(attributes)
        });
        if (severity != ReportDiagnosticSeverity.Info) _content.Status = InspectionStageStatus.Partial;
    }
    internal void Omit(string code, string scope, long? count = null)
    {
        _content.Status = InspectionStageStatus.Partial;
        if (_omissions.Count >= Budgets.MaxDiagnostics) { _limited = true; return; }
        string? retainedCode = Exact(code), retainedScope = Exact(scope);
        if (retainedCode != null && retainedScope != null) _omissions.Add(new ReportContentOmission { Code = retainedCode, Scope = retainedScope, Count = count });
    }
    internal ReportLogicalLocation? Location(ReaderLocation? source)
    {
        if (source == null) return null;
        return new ReportLogicalLocation
        {
            Sheet = Exact(source.Sheet), A1Range = Exact(source.A1Range), BlockAnchor = Exact(source.BlockAnchor),
            SourceBlockKind = Exact(source.SourceBlockKind), HeadingPath = Exact(source.HeadingPath),
            HierarchyHeadingPath = Exact(source.HierarchyHeadingPath), HeadingSlug = Exact(source.HeadingSlug),
            LogicalOrder = source.LogicalOrder is >= int.MinValue and <= int.MaxValue ? (int?)source.LogicalOrder : null,
            BlockIndex = source.BlockIndex, SourceBlockIndex = source.SourceBlockIndex, StartLine = source.StartLine,
            EndLine = source.EndLine, NormalizedStartLine = source.NormalizedStartLine, NormalizedEndLine = source.NormalizedEndLine,
            Page = source.Page, Slide = source.Slide, TableIndex = source.TableIndex
        };
    }
    internal void Map(OfficeDocumentReadResult native, CancellationToken token)
    {
        Fact("document.title", native.Source.Title); Fact("document.author", native.Source.Author);
        Fact("document.subject", native.Source.Subject); Fact("document.keywords", native.Source.Keywords);
        foreach (ReaderChunk chunk in native.Chunks)
        {
            token.ThrowIfCancellationRequested();
            bool evidenceOnly = chunk.Location.SourceBlockKind is "warning" or "diagnostic" or "page-outcome";
            int start = _text.Length, retained = 0;
            if (!evidenceOnly && chunk.Text.Length > 0)
            {
                int separator = _text.Length == 0 ? 0 : 1;
                int count = Math.Min(chunk.Text.Length, Math.Min(Budgets.MaxTextCharacters - _text.Length - separator, _remaining - separator));
                count = Math.Max(0, count);
                if (count > 0 && count < chunk.Text.Length && char.IsHighSurrogate(chunk.Text[count - 1])) count--;
                if (count > 0)
                {
                    if (separator != 0) { _text.Append('\n'); _remaining--; start++; }
                    _text.Append(chunk.Text, 0, count); _remaining -= count; retained = count;
                }
                if (count != chunk.Text.Length) _limited = true;
            }
            Unit(chunk.Id, chunk.Location.SourceBlockKind ?? "chunk", chunk.Location, evidenceOnly ? InspectionStageStatus.Failed : retained != chunk.Text.Length ? InspectionStageStatus.Partial : InspectionStageStatus.Completed,
                retained > 0 ? start : null, retained > 0 ? retained : null);
            if (chunk.Warnings != null) foreach (string warning in chunk.Warnings)
                Diagnostic("officeimo:chunk-warning", warning, location: chunk.Location, recoverable: true);
        }
        foreach (OfficeDocumentMetadataEntry metadata in native.Metadata)
        {
            token.ThrowIfCancellationRequested();
            bool derived = metadata.ValueType == "count" || metadata.Category == "inspection.coverage" ||
                metadata.Category.EndsWith(".projection", StringComparison.Ordinal) || metadata.Category is
                    "inspection.content-safety" or "inspection.text-integrity" or "inspection.package-security" or "pdf.text-decoding" or "pdf.page-outcome" or "pdf.repair";
            ReportFactKind kind = metadata.ValueType is "count" or "integer" && long.TryParse(metadata.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out _) ?
                ReportFactKind.Integer : metadata.ValueType == "boolean" && bool.TryParse(metadata.Value, out _) ? ReportFactKind.Boolean : ReportFactKind.Text;
            string? objectId = Exact(metadata.SourceObjectId);
            var source = objectId == null ? null : new ReportSourceLocation { Record = objectId, ByteSpace = ReportByteSpace.Unknown };
            // An object descriptor can carry attributes and identity without a display value.
            Fact(metadata.Category + "." + metadata.Name, metadata.Value ?? string.Empty, derived ? ReportFactOrigin.Derived : ReportFactOrigin.Embedded,
                kind, metadata.Location, metadata.Attributes, source);
        }
        foreach (OfficeDocumentDiagnostic diagnostic in native.Diagnostics)
        {
            token.ThrowIfCancellationRequested();
            ReportRecoveryKind recovery = ReportRecoveryKind.None;
            if (diagnostic.Attributes.TryGetValue("disposition", out string? disposition))
                recovery = disposition is "Recovered" or "Repaired" ? ReportRecoveryKind.Repaired : disposition == "Skipped" ? ReportRecoveryKind.Skipped : ReportRecoveryKind.None;
            Diagnostic(diagnostic.Code, diagnostic.Message,
                diagnostic.Severity == OfficeDocumentDiagnosticSeverity.Error ? ReportDiagnosticSeverity.Error :
                diagnostic.Severity == OfficeDocumentDiagnosticSeverity.Information ? ReportDiagnosticSeverity.Info : ReportDiagnosticSeverity.Warning,
                diagnostic.Location, diagnostic.Category.ToString(), diagnostic.IsRecoverable == true, recovery, diagnostic.Attributes);
        }
    }
    internal void Unit(string id, string kind, ReaderLocation? location, InspectionStageStatus status, int? start = null, int? length = null)
    {
        if (_units.Count >= Budgets.MaxDocumentUnits) { _limited = true; return; }
        string? retainedId = Exact(id), retainedKind = Exact(kind);
        if (retainedId != null && retainedKind != null) _units.Add(new ReportDocumentUnit
        { Id = retainedId, Kind = retainedKind, Ordinal = _units.Count, Location = Location(location), Status = status, TextStart = start, TextLength = length });
    }
    internal void MapPdfInspection(PdfInspectionReadResult inspection, CancellationToken token)
    {
        Fact("pdf.source.pageCount", inspection.SourceInfo.PageCount.ToString(CultureInfo.InvariantCulture), ReportFactOrigin.Derived, ReportFactKind.Integer);
        Fact("pdf.source.formFieldCount", inspection.SourceInfo.FormFieldCount.ToString(CultureInfo.InvariantCulture), ReportFactOrigin.Derived, ReportFactKind.Integer);
        Fact("pdf.source.formWidgetCount", inspection.SourceInfo.FormWidgetCount.ToString(CultureInfo.InvariantCulture), ReportFactOrigin.Derived, ReportFactKind.Integer);
        Fact("pdf.source.headerVersion", inspection.SourceInfo.HeaderVersion);
        foreach (PdfPageInfo page in inspection.SourceInfo.Pages)
        {
            token.ThrowIfCancellationRequested();
            var sourceLocation = new ReaderLocation { Page = page.PageNumber, SourceBlockKind = "source-page" };
            Fact("pdf.source.page.width", page.Width.ToString("R", CultureInfo.InvariantCulture), kind: ReportFactKind.Decimal, location: sourceLocation);
            Fact("pdf.source.page.height", page.Height.ToString("R", CultureInfo.InvariantCulture), kind: ReportFactKind.Decimal, location: sourceLocation);
            Fact("pdf.source.page.rotation", page.RotationDegrees.ToString(CultureInfo.InvariantCulture), kind: ReportFactKind.Integer, location: sourceLocation);
            foreach (PdfLinkAnnotation link in page.LinkAnnotations)
                Fact("pdf.source.link.target", link.Uri ?? link.DestinationName ?? link.NamedAction ?? link.RemoteFile, location: sourceLocation);
            foreach (PdfAnnotation annotation in page.Annotations)
                Fact("pdf.source.annotation", annotation.Contents ?? annotation.Subtype, location: sourceLocation,
                    attributes: new Dictionary<string, string> { ["subtype"] = annotation.Subtype, ["objectNumber"] = annotation.ObjectNumber?.ToString(CultureInfo.InvariantCulture) ?? string.Empty });
            foreach (var widget in page.FormWidgets)
                Fact("pdf.source.form-widget", widget.FieldName, location: sourceLocation);
            foreach (PdfPageAction action in page.PageActions)
                Fact("pdf.source.page-action", action.ActionType, location: sourceLocation,
                    attributes: new Dictionary<string, string> { ["trigger"] = action.TriggerName, ["actionPath"] = action.ActionPath, ["uri"] = action.Uri ?? string.Empty });
        }
        foreach (PdfPageReadOutcome outcome in inspection.PageOutcomes)
        {
            token.ThrowIfCancellationRequested();
            var location = new ReaderLocation { Page = outcome.PageNumber, SourceBlockIndex = outcome.SelectionIndex, SourceBlockKind = "page-outcome" };
            Unit("pdf-selection-" + outcome.SelectionIndex.ToString(CultureInfo.InvariantCulture), "page-outcome", location,
                outcome.Succeeded ? InspectionStageStatus.Completed : InspectionStageStatus.Failed);
            Fact("pdf.page.nativeTextOutcome", outcome.Status.ToString(), ReportFactOrigin.Derived, location: location);
            if (!outcome.Succeeded) Diagnostic(outcome.MappingFailure != null ? "pdf-page-unmappable-text" : "pdf-page-unsupported-content-filter",
                outcome.MappingFailure?.Message ?? "The native page content filter is unsupported.", ReportDiagnosticSeverity.Error, location,
                recoverable: true, recovery: ReportRecoveryKind.Skipped,
                attributes: new Dictionary<string, string> { ["unsupportedFilters"] = string.Join(",", outcome.UnsupportedFilters) });
        }
        foreach (PdfRepairDiagnostic repair in inspection.RepairReport.Diagnostics)
            Diagnostic(repair.Code, repair.Message, recovery: repair.WasRecovered ? ReportRecoveryKind.Repaired : ReportRecoveryKind.None,
                attributes: new Dictionary<string, string> { ["disposition"] = repair.Disposition.ToString(), ["objectNumber"] = repair.ObjectNumber?.ToString(CultureInfo.InvariantCulture) ?? string.Empty });
    }
    internal InspectionContentReadResult Failure(InspectionContentReadDisposition disposition, string code, string message,
        IReadOnlyDictionary<string, string>? attributes = null)
    {
        _text.Clear(); _members.Clear(); _selectedBytes = 0;
        foreach (ReportDocumentUnit unit in _units) { unit.TextStart = null; unit.TextLength = null; }
        Diagnostic(code, message, ReportDiagnosticSeverity.Error, attributes: attributes);
        _content.Status = disposition == InspectionContentReadDisposition.Malformed ? InspectionStageStatus.Failed : InspectionStageStatus.Unavailable;
        return Complete(disposition);
    }
    internal InspectionContentReadResult Complete(InspectionContentReadDisposition disposition = InspectionContentReadDisposition.Handled)
    {
        if (_limited) { _content.Status = InspectionStageStatus.Partial; Omit("officeimo:response-limit", "native-evidence"); }
        _content.Text = _text.ToString(); _content.Facts = _facts.ToArray(); _content.DocumentUnits = _units.ToArray();
        _content.Diagnostics = _diagnostics.ToArray(); _content.Omissions = _omissions.ToArray(); _content.Entries = _entries.ToArray();
        return new InspectionContentReadResult(disposition, _content, _members.ToArray(),
            new InspectionContentWork(_selectedBytes, checked(SnapshotReadBytes + PayloadReadBytes), _decodedBytes, DecompressionWorkBytes));
    }
}
