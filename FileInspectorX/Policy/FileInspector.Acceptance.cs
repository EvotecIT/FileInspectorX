namespace FileInspectorX;

public static partial class FileInspector
{
    /// <summary>
    /// Evaluates already-collected evidence for an untrusted client filename. Unknown, partial and
    /// unavailable evidence never produces Accepted. Callers must bind the result to the inspected bytes.
    /// </summary>
    /// <param name="analysis">The inspection result, or null when inspection could not run.</param>
    /// <param name="clientFileName">A filename without directory components, before any host-side renaming.</param>
    /// <param name="options">Content restrictions; defaults reject encrypted, active and embedded document content.</param>
    /// <returns>A scoped acceptance decision with stable, path-free reasons.</returns>
    public static FileAcceptanceResult EvaluateAcceptance(FileAnalysis? analysis, string? clientFileName, FileAcceptanceOptions? options = null)
    {
        options ??= new FileAcceptanceOptions();
        var rejected = new List<string>();
        var incomplete = new List<string>();
        if (!IsAcceptanceFileName(clientFileName)) rejected.Add("file-policy:invalid-filename");

        if (analysis == null || analysis.InputStatus == InspectionInputStatus.Unreadable)
            incomplete.Add("file-policy:input-unavailable");
        else
        {
            var detection = analysis.Detection;
            if (!analysis.StageOutcomes.Any(stage => stage.Stage == InspectionStage.Assessment && stage.Status == InspectionStageStatus.Completed))
                incomplete.Add("file-policy:analysis-not-completed");
            if ((InspectHelpers.IsArchive(detection) || analysis.Kind is ContentKind.Archive or ContentKind.Package or ContentKind.DiskImage ||
                 detection?.Extension is "docx" or "xlsx" or "pptx") &&
                !analysis.StageOutcomes.Any(stage => stage.Stage == InspectionStage.Container && stage.Status == InspectionStageStatus.Completed))
                incomplete.Add("file-policy:container-not-completed");
            if (RequiresAdditionalDocumentInspection(analysis, options))
                incomplete.Add("file-policy:document-coverage-unavailable");
            if (analysis.InputStatus != InspectionInputStatus.Recognized)
                incomplete.Add("file-policy:type-unrecognized");
            else if (options.RequireDeclaredTypeMatch && IsAcceptanceFileName(clientFileName) &&
                CompareDeclaredDetailed(GetExtension(clientFileName!), detection).Mismatch)
                rejected.Add("file-policy:declared-type-mismatch");

            if (detection?.StructuredValidation == StructuredValidationOutcome.Failed)
                rejected.Add("file-policy:invalid-structure");
            if (analysis.Outcome != InspectionOutcome.Complete || detection?.StructuredValidation is
                StructuredValidationOutcome.Skipped or StructuredValidationOutcome.TimedOut or StructuredValidationOutcome.Unavailable)
                incomplete.Add("file-policy:inspection-incomplete");

            var flags = analysis.Flags;
            if (options.RejectResourceLimits && (analysis.AnalysisIssues ?? Array.Empty<string>())
                .Concat(analysis.StageOutcomes.SelectMany(stage => stage.Issues)).Any(issue =>
                    issue.EndsWith("-limit", StringComparison.Ordinal) || issue.EndsWith("-timeout", StringComparison.Ordinal)))
                rejected.Add("file-policy:resource-limit");
            if (options.RejectEncryptedContent && (flags & (ContentFlags.PdfEncrypted | ContentFlags.OoxmlEncrypted | ContentFlags.ArchiveHasEncryptedEntries)) != 0)
                rejected.Add("file-policy:encrypted-content");
            if (options.RejectActiveDocuments && (flags & (ContentFlags.HasOoxmlMacros | ContentFlags.OleHasVbaMacros |
                ContentFlags.OfficeHasActiveX | ContentFlags.OfficeRemoteTemplate | ContentFlags.OfficePossibleDde | ContentFlags.OfficeExternalLinks |
                ContentFlags.PdfHasJavaScript | ContentFlags.PdfHasOpenAction | ContentFlags.PdfHasAA |
                ContentFlags.PdfHasLaunch | ContentFlags.PdfHasXfa | ContentFlags.PdfHasRemoteActions |
                ContentFlags.PdfHasFormSubmission | ContentFlags.PdfHasRichMedia)) != 0)
                rejected.Add("file-policy:active-document");
            if (options.RejectEmbeddedPayloads && (flags & (ContentFlags.PdfHasEmbeddedFiles | ContentFlags.OfficeHasEmbeddedObjects)) != 0)
                rejected.Add("file-policy:embedded-payload");
            if (options.RejectUnsafeArchivePaths && (flags & (ContentFlags.ArchiveHasPathTraversal | ContentFlags.ArchiveHasAbsolutePaths | ContentFlags.ArchiveHasSymlinks)) != 0)
                rejected.Add("file-policy:unsafe-archive-path");
        }

        return new FileAcceptanceResult(rejected.Count > 0 ? FileAcceptanceDecision.Rejected :
            incomplete.Count > 0 ? FileAcceptanceDecision.Incomplete : FileAcceptanceDecision.Accepted,
            rejected.Concat(incomplete));
    }

    private static bool IsAcceptanceFileName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name) || name is "." or ".." || name![name.Length - 1] is '.' or ' ') return false;
        foreach (char value in name)
            if (char.IsControl(value) || "/\\:*?\"<>|".IndexOf(value) >= 0 || value is >= '\u202a' and <= '\u202e' or >= '\u2066' and <= '\u2069') return false;
        return true;
    }

    private static bool RequiresAdditionalDocumentInspection(FileAnalysis analysis, FileAcceptanceOptions options)
    {
        if (!options.RejectActiveDocuments && !options.RejectEmbeddedPayloads && !options.RejectEncryptedContent) return false;
        // These recognized carriers have no complete active/embedded-content policy pass in the core.
        // Their native engines remain optional; recognition alone cannot establish content acceptance.
        bool Unsupported(string? extension) => extension is "doc" or "xls" or "ppt" or "rtf" or "eml" or "msg" or
            "odt" or "ods" or "odp" or "odg" or "odf" or "ott" or "ots" or "otp" or "epub" or "xps" or "oxps";
        var mime = analysis.Detection?.MimeType ?? string.Empty;
        return Unsupported(analysis.Detection?.Extension) || Unsupported(analysis.GuessedExtension) || Unsupported(analysis.ContainerSubtype) ||
            mime.IndexOf("opendocument", StringComparison.OrdinalIgnoreCase) >= 0 ||
            mime.StartsWith("message/", StringComparison.OrdinalIgnoreCase);
    }
}
