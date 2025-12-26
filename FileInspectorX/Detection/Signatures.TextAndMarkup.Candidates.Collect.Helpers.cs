namespace FileInspectorX;

internal static partial class Signatures
{
    private delegate void CandidateAdder(string ext, string mime, string confidence, string reason, string? details, int scoreAdjust, bool? dangerousOverride);

    private static void TryAddNdjsonCandidate(
        ReadOnlySpan<byte> line1,
        ReadOnlySpan<byte> line2,
        ReadOnlySpan<byte> line3,
        CandidateAdder addCandidate)
    {
        int ndjsonLines2Boost = Math.Max(0, Settings.DetectionNdjsonLines2Boost);
        int ndjsonLines3Boost = Math.Max(0, Settings.DetectionNdjsonLines3Boost);

        static bool LooksJsonLine(ReadOnlySpan<byte> l)
        {
            if (l.Length < 2) return false;
            int i = 0; while (i < l.Length && (l[i] == (byte)' ' || l[i] == (byte)'\t')) i++;
            if (i >= l.Length || l[i] != (byte)'{') return false;
            int q = l.IndexOf((byte)'"'); if (q < 0) return false;
            int colon = l.IndexOf((byte)':'); if (colon < 0) return false;
            int end = l.LastIndexOf((byte)'}'); if (end < 0) return false;
            int depth = 0; bool inQ = false; bool colonOut = false;
            for (int k = 0; k < l.Length; k++)
            {
                byte c = l[k];
                if (c == (byte)'"') inQ = !inQ;
                else if (!inQ)
                {
                    if (c == (byte)'{') depth++;
                    else if (c == (byte)'}') depth--;
                    else if (c == (byte)':') colonOut = true;
                }
            }
            if (depth != 0) return false;
            return colonOut && colon > q && end > colon;
        }

        var l1 = TrimBytes(line1);
        var l2 = TrimBytes(line2);
        bool j1 = LooksJsonLine(l1);
        bool j2 = LooksJsonLine(l2);
        if (!j1 || !j2) return;

        var l3 = TrimBytes(line3);
        bool j3 = LooksJsonLine(l3);
        string conf = j3 ? "High" : "Medium";
        int boost = j3 ? ndjsonLines3Boost : ndjsonLines2Boost;
        addCandidate("ndjson", "application/x-ndjson", conf, "text:ndjson", j3 ? "ndjson:lines-3" : "ndjson:lines-2", boost, null);
    }

    private static void TryAddJsonCandidates(
        ReadOnlySpan<byte> head,
        ReadOnlySpan<byte> line1,
        string headStr,
        int jsonPenalty,
        CandidateAdder addCandidate,
        int jsonValidBoost)
    {
        if (head.Length == 0) return;
        if (head[0] != (byte)'{' && head[0] != (byte)'[') return;

        bool jsonLooksLikeLog = LooksLikeTimestamp(TrimBytes(line1)) || StartsWithLevelToken(TrimBytes(line1));
        if (jsonLooksLikeLog) return;

        bool jsonComplete = LooksLikeCompleteJson(headStr);
        bool jsonValid = jsonComplete && JsonStructureValidator.TryValidate(headStr, head.Length, out _);

        int len = Math.Min(JSON_DETECTION_SCAN_LIMIT, head.Length);
        var slice = head.Slice(0, len);
        bool looksObject = slice[0] == (byte)'{';
        bool looksArray = slice[0] == (byte)'[';
        int jsonBoost = jsonValid ? jsonValidBoost : 0;

        if (looksArray)
        {
            bool hasClose = slice.IndexOf((byte)']') >= 0;
            int commaCount = Count(slice, (byte)',');
            bool hasObjectItem = slice.IndexOf((byte)'{') >= 0;
            if ((commaCount >= 1 && hasClose) || hasObjectItem)
            {
                bool hasQuotedColon = HasQuotedKeyColon(slice);
                if (hasObjectItem ? hasQuotedColon : true)
                {
                    addCandidate("json", "application/json", hasObjectItem ? "Medium" : "Low", "text:json", hasObjectItem ? "json:array-of-objects" : "json:array-of-primitives", jsonBoost + jsonPenalty, null);
                }
            }
        }
        if (looksObject)
        {
            bool hasQuotedColon = HasQuotedKeyColon(slice);
            bool hasClose = slice.IndexOf((byte)'}') >= 0;
            if (hasQuotedColon && hasClose)
                addCandidate("json", "application/json", "Medium", "text:json", "json:object-key-colon", jsonBoost + jsonPenalty, null);
        }
    }

    private static void TryAddXmlCandidates(
        ReadOnlySpan<byte> head,
        string headStr,
        string headLower,
        bool declaredAdmx,
        bool declaredAdml,
        bool htmlHasScript,
        CandidateAdder addCandidate,
        int xmlWellFormedBoost)
    {
        if (head.Length < 1 || head[0] != (byte)'<') return;

        var rootLower = TryGetXmlRootName(headLower);
        if (!string.IsNullOrEmpty(rootLower))
        {
            var rootLowerValue = rootLower!;
            int colon = rootLowerValue.IndexOf(':');
            if (colon >= 0 && colon < rootLowerValue.Length - 1)
                rootLowerValue = rootLowerValue.Substring(colon + 1);
            bool xmlComplete = LooksLikeCompleteXml(headLower, rootLowerValue);
            bool xmlWellFormed = xmlComplete && TryXmlWellFormed(headStr, out _);

            if (rootLowerValue == "policydefinitions")
            {
                int admxCues = CountAdmxCues(headLower, out bool admxStrong);
                bool admxHigh = admxStrong || declaredAdmx || admxCues >= 5;
                string details = admxStrong ? "xml:policydefinitions+strong" :
                    (admxCues >= 3 ? $"xml:policydefinitions+cues-{admxCues}" :
                    (declaredAdmx ? "xml:policydefinitions+decl" : "xml:policydefinitions"));
                addCandidate("admx", "application/xml", admxHigh ? "High" : "Medium", "text:admx", details, xmlWellFormed ? xmlWellFormedBoost : 0, null);
            }
            else if (rootLowerValue == "policydefinitionresources")
            {
                int admlCues = CountAdmlCues(headLower, out bool admlStrong);
                bool admlHigh = admlStrong || declaredAdml || admlCues >= 4;
                string details = admlStrong ? "xml:policydefinitionresources+strong" :
                    (admlCues >= 3 ? $"xml:policydefinitionresources+cues-{admlCues}" :
                    (declaredAdml ? "xml:policydefinitionresources+decl" : "xml:policydefinitionresources"));
                addCandidate("adml", "application/xml", admlHigh ? "High" : "Medium", "text:adml", details, xmlWellFormed ? xmlWellFormedBoost : 0, null);
            }
        }
        if (head.Length >= 5 && head.Slice(0, 5).SequenceEqual("<?xml"u8))
        {
            var ext = declaredAdmx ? "admx" : (declaredAdml ? "adml" : "xml");
            bool xmlComplete = LooksLikeCompleteXml(headLower, null);
            bool xmlWellFormed = xmlComplete && TryXmlWellFormed(headStr, out _);
            addCandidate(ext, "application/xml", "Medium", "text:xml", ext == "xml" ? null : $"xml:decl-{ext}", xmlWellFormed ? xmlWellFormedBoost : 0, null);
        }
        if (head.IndexOf("<!DOCTYPE html"u8) >= 0 || head.IndexOf("<html"u8) >= 0)
            addCandidate("html", "text/html", "Medium", "text:html", null, 0, htmlHasScript);
    }
}
