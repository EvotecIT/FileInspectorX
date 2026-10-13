namespace FileInspectorX;

internal static class ReportExplainer
{
    internal static IReadOnlyList<ReportObservation> Explain(InspectionReport report)
    {
        var observations = new List<ReportObservation>();
        void Add(string code, string text, string evidence) => observations.Add(new ReportObservation { Code = code, Text = text, Evidence = evidence });
        var analysis = report.Analysis;
        if (analysis.Detection != null)
            Add("type", "The content is identified as " + analysis.Detection.Extension + " (" + analysis.Detection.Confidence + " confidence).", "Analysis.Detection");
        else Add("type-unrecognized", "The content type could not be identified.", "Analysis.InputStatus");
        if (report.Content.Reader.StartsWith("ooxml-", StringComparison.Ordinal))
            Add("document", "Office document parts were found. The content section records extracted text, structure and reader limits.", "Content.Reader;Content.Issues");
        if (report.Content.Keywords.Count > 0)
            Add("text-topics", "Frequent words in the extracted text: " + string.Join(", ", report.Content.Keywords) + ". These are word frequencies, not an inferred purpose.", "Content.Keywords");
        if (report.Content.Entries.Count > 0)
            Add("archive", "The report inventories " + report.Content.Entries.Count + " archive entries. Member hashes are included only where whole entries fit the read budget.", "Content.Entries");
        if (report.Content.Facts.Count > 0 && report.Content.Reader.EndsWith("-metadata", StringComparison.Ordinal))
            Add("media", "The report contains " + report.Content.Facts.Count + " media container facts and their source locations. Declared properties do not prove playback or successful decoding.", "Content.Facts;Content.Issues");
        if (report.Content.Regions.Count > 0)
            Add("regions", "Whole binary region hashes are available where ranges fit the budget. Region matches describe those bytes, not equal program behavior or meaning.", "Content.Regions");
        if (!string.IsNullOrEmpty(analysis.ScriptLanguage))
            Add("script", "The content has " + analysis.ScriptLanguage + " script characteristics. It was inspected without execution.", "Analysis.ScriptLanguage");
        foreach (var finding in (analysis.SecurityFindings ?? Array.Empty<string>()).Take(24))
            Add("signal:" + finding, "A static inspection signal was recorded: " + finding + ". Review the underlying evidence before drawing conclusions.", "Analysis.SecurityFindings");
        if (report.Outcome == InspectionOutcome.Partial)
            Add("coverage", "Some analysis is limited or unavailable. Consult the stage outcomes and content issues before interpreting missing signals as absent.", "Content.Issues;Analysis.StageOutcomes");
        return observations;
    }
}
