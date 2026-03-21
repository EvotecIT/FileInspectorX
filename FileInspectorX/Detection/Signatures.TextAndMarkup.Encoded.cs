namespace FileInspectorX;

internal static partial class Signatures
{
    private static bool TryDetectRtf(in TextContext ctx, out ContentTypeDetectionResult? result)
    {
        var head = ctx.Head;
        if (head.Length >= 5 && head[0] == '{' && head[1] == '\\' && head[2] == 'r' && head[3] == 't' && head[4] == 'f')
        {
            result = new ContentTypeDetectionResult { Extension = "rtf", MimeType = "application/rtf", Confidence = "Medium", Reason = "text:rtf" };
            return true;
        }
        result = null;
        return false;
    }

    private static bool TryDetectEncodedBlocks(in TextContext ctx, out ContentTypeDetectionResult? result)
    {
        result = null;
        var head = ctx.Head;
        var headStr = ctx.HeadStr;
        var headLower = ctx.HeadLower;
        bool scriptCues = ctx.ScriptCues;
        bool looksMarkup = ctx.LooksMarkup;
        int nl = head.IndexOf((byte)'\n'); if (nl < 0) nl = head.Length;
        var line1 = head.Slice(0, nl);
        var rest = head.Slice(Math.Min(nl + 1, head.Length));
        int nl2 = rest.IndexOf((byte)'\n'); if (nl2 < 0) nl2 = rest.Length;
        var line2 = rest.Slice(0, nl2);
        bool looksLogLike =
            LooksLikeTimestamp(line1) ||
            LooksLikeTimestamp(line2) ||
            StartsWithLevelToken(line1) ||
            StartsWithLevelToken(line2) ||
            StartsWithTimestampedLevelToken(line1) ||
            StartsWithTimestampedLevelToken(line2) ||
            LooksLikeSyslogLine(line1) ||
            LooksLikeSyslogLine(line2);

        // ASCII85 / Base85 with Adobe markers <~ ... ~>
        {
            int a = headStr.IndexOf("<~", StringComparison.Ordinal);
            int b = a >= 0 ? headStr.IndexOf("~>", a + 2, StringComparison.Ordinal) : -1;
            if (a >= 0 && b > a + 2)
            {
                result = new ContentTypeDetectionResult { Extension = "b85", MimeType = "application/base85", Confidence = "Low", Reason = "text:ascii85" };
                return true;
            }
        }

        // UUEncode block: look for a header line starting with 'begin ' and a terminating 'end'
        {
            // Scan first few KB for lines
            var s = headStr;
            int beg = s.IndexOf("begin ", StringComparison.OrdinalIgnoreCase);
            if (beg >= 0)
            {
                // Require 'end' later to reduce false positives
                int endIdx = s.IndexOf("\nend", beg, StringComparison.OrdinalIgnoreCase);
                if (endIdx < 0) endIdx = s.IndexOf("\r\nend", beg, StringComparison.OrdinalIgnoreCase);
                if (endIdx > beg)
                {
                    result = new ContentTypeDetectionResult { Extension = "uu", MimeType = "text/x-uuencode", Confidence = "Low", Reason = "text:uu" };
                    return true;
                }
            }
        }

        // Quoted-printable (RFC 2045): look for repeated =HH escapes and/or soft line breaks.
        {
            if (!looksMarkup)
            {
                bool declaredQp = ctx.Decl == "qp";
                bool hasQpHeader = headLower.Contains("content-transfer-encoding: quoted-printable");
                int escapes = 0;
                int softBreaks = 0;
                int printable = 0;
                int nonWs = 0;
                int limit = Math.Min(headStr.Length, Settings.EncodedBase64ProbeChars);
                for (int i = 0; i < limit; i++)
                {
                    char ch = headStr[i];
                    if (ch == '=')
                    {
                        if (i + 2 < limit && IsHex(headStr[i + 1]) && IsHex(headStr[i + 2]))
                        {
                            escapes++;
                            nonWs += 3;
                            printable += 3;
                            i += 2;
                            continue;
                        }

                        if (i + 1 < limit && headStr[i + 1] == '\n')
                        {
                            softBreaks++;
                            i += 1;
                            continue;
                        }

                        if (i + 2 < limit && headStr[i + 1] == '\r' && headStr[i + 2] == '\n')
                        {
                            softBreaks++;
                            i += 2;
                            continue;
                        }
                    }

                    if (ch == '\r' || ch == '\n' || ch == '\t' || ch == ' ')
                        continue;

                    nonWs++;
                    if (ch >= 32 && ch <= 126) printable++;
                }

                bool mostlyPrintable = nonWs > 0 && printable >= (int)(nonWs * 0.75);
                bool qpLikely = hasQpHeader
                    ? (escapes >= 2 || softBreaks >= 1)
                    : ((softBreaks >= 1 && escapes >= 2) || escapes >= 6);
                if ((declaredQp || qpLikely) && mostlyPrintable)
                {
                    string details = hasQpHeader ? "qp:cte-header" :
                        softBreaks > 0 ? $"qp:escapes-{escapes}+softbreaks-{softBreaks}" :
                        $"qp:escapes-{escapes}";
                    result = new ContentTypeDetectionResult { Extension = "qp", MimeType = "message/quoted-printable", Confidence = declaredQp || hasQpHeader ? "Medium" : "Low", Reason = "text:quoted-printable", ReasonDetails = details };
                    return true;
                }
            }
        }

        // Raw/Base64-heavy text (no explicit armor) — look for long runs of base64 charset
        {
            // Skip when PEM/PGP armor headers are present; those are handled later with specific types.
            if (scriptCues) { }
            else if (looksMarkup) { }
            else if (headLower.Contains("-----begin ")) { }
            else if (looksLogLike) { }
            else
            {
                int allowed = 0, total = 0, eq = 0, contig = 0, maxContig = 0, urlSafe = 0, hexish = 0;
                int limit = Math.Min(head.Length, Settings.EncodedBase64ProbeChars);
                for (int i = 0; i < limit; i++)
                {
                    byte c = head[i];
                    bool ws = c == (byte)'\r' || c == (byte)'\n' || c == (byte)'\t' || c == (byte)' ';
                    bool isHex = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
                    bool b64 = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
                    bool url = c == '-' || c == '_'; if (url) urlSafe++; // URL-safe variant
                    if (!ws)
                    {
                        total++;
                        if (b64 || url)
                        {
                            allowed++;
                            contig++;
                            if (isHex) hexish++;
                            if (c == '=') eq++;
                        }
                        else
                        {
                            if (contig > maxContig) maxContig = contig;
                            contig = 0;
                        }
                    }
                }
                if (contig > maxContig) maxContig = contig;
                // Prefer hex classification when the run is almost pure hex and lacks '=' and URL-safe tokens
                if (total > 0 && hexish >= (int)(total * 0.95) && eq == 0 && urlSafe == 0) { }
                else if (total >= Settings.EncodedBase64MinBlock && allowed >= (int)(total * Settings.EncodedBase64AllowedRatio) && (maxContig >= Settings.EncodedBase64MinBlock))
                {
                    // Avoid trivial JSON with many base64-like tokens by requiring some '=' padding or long continuous chunk
                    bool acceptRaw = eq > 0 || urlSafe > 0 || (maxContig >= 256 && (allowed >= (int)(total * 0.98)));
                    if (acceptRaw)
                    {
                        string variant = urlSafe > 0 ? "urlsafe" : (eq > 0 ? "padded" : "raw");
                        result = new ContentTypeDetectionResult { Extension = "b64", MimeType = "application/base64", Confidence = "Low", Reason = "text:base64", ReasonDetails = variant };
                        return true;
                    }
                }
            }
        }

        // Large hex dump (continuous hex digits possibly with spaces/newlines)
        {
            if (!scriptCues)
            {
                if (looksLogLike) { }
                else
                {
                int hex = 0, other = 0, contigHex = 0, maxContigHex = 0;
                int limit = Math.Min(head.Length, Settings.EncodedBase64ProbeChars);
                for (int i = 0; i < limit; i++)
                {
                    byte c = head[i];
                    bool ws = c == (byte)'\r' || c == (byte)'\n' || c == (byte)'\t' || c == (byte)' ';
                    bool hx = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
                    if (!ws)
                    {
                        if (hx) { hex++; contigHex++; }
                        else { other++; if (contigHex > maxContigHex) maxContigHex = contigHex; contigHex = 0; }
                    }
                }
                if (contigHex > maxContigHex) maxContigHex = contigHex;
                if (hex >= Settings.EncodedHexMinChars && maxContigHex >= Settings.EncodedHexMinChars && hex > other * 4)
                {
                    result = new ContentTypeDetectionResult { Extension = "hex", MimeType = "text/plain", Confidence = "Low", Reason = "text:hex" };
                    return true;
                }
                }
            }
        }

        return false;

        static bool IsHex(char c) => (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
    }
}
