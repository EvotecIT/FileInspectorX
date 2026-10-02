using System.IO.Compression;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace FileInspectorX;

public static partial class FileInspector
{
    private static void TryValidateAdmxAdmlXmlWellFormedness(Stream stream, string path, ContentTypeDetectionResult? det, string? declaredExt)
    {
        if (det is null) return;
        if (!OperationSettings.AdmxAdmlXmlWellFormednessValidationEnabled) return;

        var detExt = (det.Extension ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();
        var decl = (declaredExt ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();
        // A declared name is attacker controlled. Only parse when content detection
        // already established an XML-family document.
        bool wantsAdmxAdml = detExt == "admx" || detExt == "adml" ||
                             ((decl == "admx" || decl == "adml") && detExt == "xml");
        if (!wantsAdmxAdml) return;
        using var timing = InspectionOperation.Current?.Measure(InspectionStage.StructuredValidation);

        try
        {
            var max = OperationSettings.AdmxAdmlXmlWellFormednessMaxBytes;
            if (max > 0)
            {
                long len = -1;
                try { if (stream.CanSeek) len = stream.Length; } catch { len = -1; }
                if (len < 0)
                {
                    try { len = new FileInfo(path).Length; } catch { len = -1; }
                }
                if (len > 0 && len > max)
                {
                    det.ValidationStatus = "skipped";
                    return;
                }
            }

            long pos = 0;
            try { if (stream.CanSeek) pos = stream.Position; } catch { pos = 0; }
            try
            {
                if (stream.CanSeek) stream.Seek(0, SeekOrigin.Begin);
                var settings = new System.Xml.XmlReaderSettings
                {
                    DtdProcessing = System.Xml.DtdProcessing.Prohibit,
                    XmlResolver = null,
                    MaxCharactersInDocument = Math.Min(OperationSettings.AdmxAdmlXmlWellFormednessMaxBytes > 0
                        ? OperationSettings.AdmxAdmlXmlWellFormednessMaxBytes
                        : 100L * 1024L * 1024L, 100L * 1024L * 1024L),
                    MaxCharactersFromEntities = 1024,
                    CloseInput = false
                };
                int timeoutMs = Math.Max(0, OperationSettings.XmlWellFormednessTimeoutMs);
                long timeoutTicks = TimeoutHelpers.GetTimeoutTicks(timeoutMs);
                var sw = timeoutTicks > 0 ? System.Diagnostics.Stopwatch.StartNew() : null;
                using var reader = System.Xml.XmlReader.Create(stream, settings);
                while (reader.Read())
                {
                    if (TimeoutHelpers.IsExpired(sw, timeoutTicks))
                        throw new TimeoutException("XML well-formedness validation timed out.");
                    if (reader.Depth > 256)
                        throw new System.Xml.XmlException("XML nesting depth exceeds the safe validation limit.");
                }
                det.ValidationStatus = "passed";
            }
            finally
            {
                try { if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin); } catch { /* ignore */ }
            }
        }
            catch (System.Xml.XmlException ex)
            {
                Breadcrumbs.Write("XML_MALFORMED", message: ex.Message, path: path);
                if (detExt == "admx" || detExt == "adml" || detExt == "xml") det.Confidence = "Low";
                det.Reason = AppendReason(det.Reason, "xml:malformed");
                det.ValidationStatus = "failed";
            }
        catch (TimeoutException ex)
        {
            Breadcrumbs.Write("XML_TIMEOUT", message: ex.Message, path: path);
            if (detExt == "admx" || detExt == "adml" || detExt == "xml") det.Confidence = "Low";
            det.Reason = AppendReason(det.Reason, "xml:validation-timeout");
            det.ValidationStatus = "timeout";
        }
        catch
        {
            // Ignore validation failures (I/O, access, etc.). Detection must remain best-effort.
            if (string.IsNullOrEmpty(det.ValidationStatus))
                det.ValidationStatus = "failed";
        }
    }

    private static void TryValidateStructuredTextWithBudget(Stream? stream, ContentTypeDetectionResult? det, bool skipAdmxAdml)
    {
        if (stream == null || det == null) return;
        if (!stream.CanSeek) return;

        var ext = (det.Extension ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();
        if (string.IsNullOrEmpty(ext)) return;
        if (ext == "admx" || ext == "adml")
        {
            if (skipAdmxAdml) return;
        }
        else if (ext != "json" && ext != "xml")
        {
            return;
        }

        const long MaxStructuredValidationBytes = 100L * 1024L * 1024L;
        using var timing = InspectionOperation.Current?.Measure(InspectionStage.StructuredValidation);
        long budget = OperationSettings.DetectionReadBudgetBytes;
        if (budget <= 0) return;
        if (budget > MaxStructuredValidationBytes) budget = MaxStructuredValidationBytes;

        long len = -1;
        try { len = stream.Length; } catch { len = -1; }
        long readBytes = budget;
        bool budgetLimited = len > 0 && len > budget;
        if (len > 0) readBytes = Math.Min(len, budget);
        if (readBytes <= 0) return;

        long pos = 0;
        try { pos = stream.Position; } catch { pos = 0; }
        byte[] buffer = new byte[(int)Math.Min(readBytes, int.MaxValue)];
        int n = 0;
        try
        {
            stream.Seek(0, SeekOrigin.Begin);
            n = ReadAvailable(stream, buffer, 0, buffer.Length);
        }
        catch
        {
            return;
        }
        finally
        {
            try { stream.Seek(pos, SeekOrigin.Begin); } catch { /* ignore */ }
        }

        if (n <= 0) return;
        string sample = DecodeTextSample(buffer, n);
        if (string.IsNullOrWhiteSpace(sample)) return;

        bool complete = false;
        if (len > 0 && n >= len) complete = true;

        if (ext == "json")
        {
            bool looksComplete = complete || LooksLikeCompleteJson(sample);
            if (!looksComplete)
            {
                if (budgetLimited && string.IsNullOrEmpty(det.ValidationStatus))
                    det.ValidationStatus = "skipped";
                return;
            }
            bool jsonValid = JsonStructureValidator.TryValidate(sample, n, out bool jsonSkipped);
            if (!jsonValid)
            {
                if (jsonSkipped)
                {
                    if (string.IsNullOrEmpty(det.ValidationStatus))
                        det.ValidationStatus = "skipped";
                    return;
                }
                det.Confidence = "Low";
                det.Reason = AppendReason(det.Reason, "json:validation-error");
                det.ValidationStatus = "failed";
                if (det.Score.HasValue) det.Score = ScoreFromConfidence(det.Confidence);
            }
            else
            {
                det.ValidationStatus = budgetLimited ? "skipped" : "passed";
            }
            return;
        }

        // xml/admx/adml
        string? root = TryGetXmlRootName(sample);
        bool xmlComplete = complete || LooksLikeCompleteXml(sample, root);
        if (!xmlComplete)
        {
            if (budgetLimited && string.IsNullOrEmpty(det.ValidationStatus))
                det.ValidationStatus = "skipped";
            return;
        }
        if (!TryXmlWellFormed(sample, out _))
        {
            det.Confidence = "Low";
            det.Reason = AppendReason(det.Reason, "xml:validation-error");
            det.ValidationStatus = "failed";
            if (det.Score.HasValue) det.Score = ScoreFromConfidence(det.Confidence);
        }
        else
        {
            det.ValidationStatus = budgetLimited ? "skipped" : "passed";
        }
    }

    private static string DecodeTextSample(byte[] buffer, int count)
    {
        if (buffer == null || count <= 0) return string.Empty;
        int bomSkip = 0;
        System.Text.Encoding enc = System.Text.Encoding.UTF8;
        if (count >= 4 && buffer[0] == 0xFF && buffer[1] == 0xFE && buffer[2] == 0x00 && buffer[3] == 0x00)
        {
            enc = new System.Text.UTF32Encoding(false, true);
            bomSkip = 4;
        }
        else if (count >= 4 && buffer[0] == 0x00 && buffer[1] == 0x00 && buffer[2] == 0xFE && buffer[3] == 0xFF)
        {
            enc = new System.Text.UTF32Encoding(true, true);
            bomSkip = 4;
        }
        else if (count >= 2 && buffer[0] == 0xFF && buffer[1] == 0xFE)
        {
            enc = System.Text.Encoding.Unicode;
            bomSkip = 2;
        }
        else if (count >= 2 && buffer[0] == 0xFE && buffer[1] == 0xFF)
        {
            enc = System.Text.Encoding.BigEndianUnicode;
            bomSkip = 2;
        }
        else if (count >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF)
        {
            enc = System.Text.Encoding.UTF8;
            bomSkip = 3;
        }
        else
        {
            int scan = Math.Min(count, 2048);
            int nulTotal = 0;
            int nulEven = 0;
            int nulOdd = 0;
            for (int i = 0; i < scan; i++)
            {
                if (buffer[i] == 0x00)
                {
                    nulTotal++;
                    if ((i & 1) == 0) nulEven++; else nulOdd++;
                }
            }
            if (nulTotal > 0 && ((double)nulTotal / scan) >= 0.2)
            {
                if (nulOdd > nulEven * 4) enc = System.Text.Encoding.Unicode;
                else if (nulEven > nulOdd * 4) enc = System.Text.Encoding.BigEndianUnicode;
            }
        }

        if (bomSkip >= count) return string.Empty;
        int len = count - bomSkip;
        if (len == 0) return string.Empty;
        return enc.GetString(buffer, bomSkip, len);
    }

    private static int ScoreFromConfidence(string? confidence)
    {
        if (string.Equals(confidence, "High", StringComparison.OrdinalIgnoreCase)) return 90;
        if (string.Equals(confidence, "Medium", StringComparison.OrdinalIgnoreCase)) return 70;
        if (string.Equals(confidence, "Low", StringComparison.OrdinalIgnoreCase)) return 50;
        return 40;
    }

    private static bool LooksLikeCompleteJson(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return false;
        var t = s.Trim();
        if (t.Length < 2) return false;
        char first = t[0];
        char last = t[t.Length - 1];
        return (first == '{' || first == '[') && (last == '}' || last == ']');
    }

    private static bool LooksLikeCompleteXml(string s, string? rootName)
    {
        if (string.IsNullOrWhiteSpace(s)) return false;
        var lower = s.ToLowerInvariant();
        if (!lower.Contains("</")) return false;
        if (!lower.TrimEnd().EndsWith(">")) return false;
        if (!string.IsNullOrEmpty(rootName))
        {
            var rootLower = rootName!.ToLowerInvariant();
            return lower.Contains("</" + rootLower);
        }
        return true;
    }

    private static string? TryGetXmlRootName(string s)
    {
        if (string.IsNullOrEmpty(s)) return null;
        int i = 0;
        while (i < s.Length)
        {
            int lt = s.IndexOf('<', i);
            if (lt < 0 || lt + 1 >= s.Length) return null;
            char next = s[lt + 1];
            if (next == '?' || next == '!')
            {
                int gt = s.IndexOf('>', lt + 2);
                if (gt < 0) return null;
                i = gt + 1;
                continue;
            }
            int start = lt + 1;
            while (start < s.Length && char.IsWhiteSpace(s[start])) start++;
            int end = start;
            while (end < s.Length && (char.IsLetterOrDigit(s[end]) || s[end] == ':' || s[end] == '_' || s[end] == '-')) end++;
            if (end > start) return s.Substring(start, end - start);
            i = lt + 1;
        }
        return null;
    }

    private static bool TryXmlWellFormed(string xml, out string? rootName)
    {
        rootName = null;
        if (string.IsNullOrWhiteSpace(xml)) return false;
        try
        {
            var settings = new System.Xml.XmlReaderSettings
            {
                DtdProcessing = System.Xml.DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = Math.Min(10_000_000L, Math.Max(1024L, (long)xml.Length * 4L)),
                MaxCharactersFromEntities = 1024
            };
            int timeoutMs = Math.Max(0, OperationSettings.XmlWellFormednessTimeoutMs);
            long timeoutTicks = TimeoutHelpers.GetTimeoutTicks(timeoutMs);
            var sw = timeoutTicks > 0 ? System.Diagnostics.Stopwatch.StartNew() : null;
            using var reader = System.Xml.XmlReader.Create(new System.IO.StringReader(xml), settings);
            while (reader.Read())
            {
                if (TimeoutHelpers.IsExpired(sw, timeoutTicks)) return false;
                if (reader.NodeType == System.Xml.XmlNodeType.Element)
                {
                    rootName ??= reader.Name;
                    if (reader.Depth > 256) return false;
                }
            }
            return !string.IsNullOrEmpty(rootName);
        }
        catch
        {
            return false;
        }
    }

}
