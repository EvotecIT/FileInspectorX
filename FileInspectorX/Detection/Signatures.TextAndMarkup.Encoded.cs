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

        // Raw/Base64-heavy text (no explicit armor) — look for long runs of base64 charset
        {
            // Skip when PEM/PGP armor headers are present; those are handled later with specific types.
            if (scriptCues) { }
            else if (looksMarkup) { }
            else if (headLower.Contains("-----begin ")) { }
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

        return false;
    }
}
