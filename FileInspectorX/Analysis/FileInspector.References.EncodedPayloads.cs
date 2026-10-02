using System.Xml;

namespace FileInspectorX;

public static partial class FileInspector
{
    private static bool TryClassifyDataUriPayload(string uri, out string? innerExt, out bool isBase64)
    {
        innerExt = null;
        isBase64 = false;
        try
        {
            if (!TryParseDataUriPayload(uri, out var mediaType, out var sample, out isBase64))
                return false;

            if (sample != null && sample.Length > 0)
            {
                try
                {
                    var det = FileInspector.Detect(new ReadOnlySpan<byte>(sample, 0, Math.Min(sample.Length, OperationSettings.EncodedDecodeMaxBytes)), null);
                    var ext = (det?.Extension ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();
                    if (!string.IsNullOrWhiteSpace(ext) && ext is not "txt" and not "log")
                        innerExt = ext;
                }
                catch { }
            }

            if (string.IsNullOrWhiteSpace(innerExt))
                innerExt = InferDataUriExtensionFromMediaType(mediaType);

            return true;
        }
        catch { return false; }
    }

    private static string ReadScriptDataUriCandidate(string text, int startAt, out int consumedEnd)
    {
        consumedEnd = startAt;
        if (string.IsNullOrEmpty(text) || startAt < 0 || startAt >= text.Length)
            return string.Empty;

        var sb = new System.Text.StringBuilder();
        int cursor = startAt;
        int segments = 0;
        while (cursor < text.Length && segments < 8)
        {
            int end = ReadDataUriSegment(text, cursor, sb, ref consumedEnd);
            if (end <= cursor)
                break;
            segments++;

            if (end >= text.Length || !IsStringDelimiter(text[end]))
                break;

            int p = end + 1;
            bool continued = false;
            while (true)
            {
                p = SkipWhitespaceAndClosers(text, p);
                if (TryConsumeConcatCall(text, p, sb, ref consumedEnd, out int concatEnd))
                {
                    p = concatEnd;
                    continued = true;
                    continue;
                }

                if (p >= text.Length || text[p] != '+')
                    break;

                p++;
                if (!TryConsumeStringExpressionPiece(text, p, sb, ref consumedEnd, out int pieceEnd))
                    break;

                p = pieceEnd;
                continued = true;
                continue;
            }

            if (!continued)
                break;

            cursor = p;
        }

        return sb.ToString();

        static int ReadDataUriSegment(string value, int start, System.Text.StringBuilder buffer, ref int consumed)
        {
            int cursor = start;
            int end = start;
            while (end < value.Length)
            {
                if (value[end] == '$' && end + 1 < value.Length && value[end + 1] == '{')
                {
                    if (end > cursor)
                        buffer.Append(value, cursor, end - cursor);

                    consumed = Math.Max(consumed, end + 1);
                    if (!TryReadSimpleStringExpression(value, end + 2, "}", out var interpolationValue, out int interpolationEnd))
                        return end;

                    buffer.Append(interpolationValue);
                    consumed = Math.Max(consumed, interpolationEnd);
                    end = interpolationEnd + 1;
                    cursor = end;
                    continue;
                }

                if (IsTerminal(value[end]))
                    break;

                end++;
            }

            if (end > cursor)
                buffer.Append(value, cursor, end - cursor);

            consumed = Math.Max(consumed, end);
            return end;
        }

        static bool TryConsumeConcatCall(string value, int start, System.Text.StringBuilder buffer, ref int consumed, out int nextIndex)
        {
            nextIndex = start;
            const string concatToken = ".concat";
            if (start < 0 || start >= value.Length) return false;
            if (!value.AsSpan(start).StartsWith(concatToken.AsSpan(), StringComparison.Ordinal))
                return false;

            int p = start + concatToken.Length;
            while (p < value.Length && char.IsWhiteSpace(value[p])) p++;
            if (p >= value.Length || value[p] != '(')
                return false;
            p++;

            bool appended = false;
            while (p < value.Length)
            {
                p = SkipWhitespaceAndOpeners(value, p);
                if (p >= value.Length) return false;
                if (value[p] == ')')
                {
                    nextIndex = p + 1;
                    consumed = Math.Max(consumed, p);
                    return appended;
                }

                if (!TryReadSimpleStringExpression(value, p, ",)", out var segment, out int segmentEnd))
                    return false;

                buffer.Append(segment);
                appended = true;
                p = segmentEnd;
                consumed = Math.Max(consumed, segmentEnd);
                if (p >= value.Length) return false;
                if (value[p] == ',')
                {
                    p++;
                    continue;
                }

                if (value[p] == ')')
                {
                    nextIndex = p + 1;
                    consumed = Math.Max(consumed, p);
                    return true;
                }

                return false;
            }

            return false;
        }

        static bool TryConsumeStringExpressionPiece(string value, int start, System.Text.StringBuilder buffer, ref int consumed, out int nextIndex)
        {
            nextIndex = start;
            int p = SkipWhitespaceAndOpeners(value, start);
            if (p >= value.Length)
                return false;

            if (IsStringDelimiter(value[p]))
            {
                if (!TryReadQuotedStringLiteral(value, p, out var literal, out int literalEnd))
                    return false;

                buffer.Append(literal);
                consumed = Math.Max(consumed, literalEnd);
                nextIndex = literalEnd + 1;
                return true;
            }

            if (!TryReadSimpleArrayJoinExpression(value, p, out var joined, out int joinEnd))
                return false;

            buffer.Append(joined);
            consumed = Math.Max(consumed, joinEnd - 1);
            nextIndex = joinEnd;
            return true;
        }

        static bool TryReadSimpleStringExpression(string value, int start, string terminators, out string result, out int endIndex)
        {
            result = string.Empty;
            endIndex = start;
            var local = new System.Text.StringBuilder();
            int p = start;
            int parenDepth = 0;

            while (p < value.Length)
            {
                p = SkipWhitespace(value, p);
                while (p < value.Length && value[p] == '(')
                {
                    parenDepth++;
                    p++;
                    p = SkipWhitespace(value, p);
                }

                if (!TryConsumeStringExpressionPiece(value, p, local, ref endIndex, out int pieceEnd))
                    return false;

                p = pieceEnd;
                p = SkipWhitespace(value, p);
                while (true)
                {
                    while (parenDepth > 0 && p < value.Length && value[p] == ')')
                    {
                        parenDepth--;
                        p++;
                        p = SkipWhitespace(value, p);
                    }

                    int concatConsumed = p;
                    if (!TryConsumeConcatCall(value, p, local, ref concatConsumed, out int concatEnd))
                        break;

                    p = SkipWhitespace(value, concatEnd);
                }

                if (p >= value.Length)
                    return false;

                if (value[p] == '+')
                {
                    p++;
                    continue;
                }

                if (terminators.IndexOf(value[p]) >= 0)
                {
                    result = local.ToString();
                    endIndex = p;
                    return result.Length > 0;
                }

                return false;
            }

            return false;
        }

        static bool TryReadSimpleArrayJoinExpression(string value, int start, out string result, out int nextIndex)
        {
            result = string.Empty;
            nextIndex = start;
            if (start < 0 || start >= value.Length || value[start] != '[')
                return false;

            var local = new System.Text.StringBuilder();
            bool hasItems = false;
            int p = start + 1;
            while (p < value.Length)
            {
                p = SkipWhitespace(value, p);
                if (p >= value.Length)
                    return false;

                if (value[p] == ']')
                {
                    p++;
                    break;
                }

                if (!TryReadQuotedStringLiteral(value, p, out var item, out int itemEnd))
                    return false;

                local.Append(item);
                hasItems = true;
                p = itemEnd + 1;
                p = SkipWhitespace(value, p);
                if (p >= value.Length)
                    return false;

                if (value[p] == ',')
                {
                    p++;
                    continue;
                }

                if (value[p] == ']')
                {
                    p++;
                    break;
                }

                return false;
            }

            if (!hasItems)
                return false;

            p = SkipWhitespace(value, p);
            const string joinToken = ".join";
            if (p >= value.Length || !value.AsSpan(p).StartsWith(joinToken.AsSpan(), StringComparison.Ordinal))
                return false;

            p += joinToken.Length;
            p = SkipWhitespace(value, p);
            if (p >= value.Length || value[p] != '(')
                return false;

            p++;
            p = SkipWhitespace(value, p);
            if (!TryReadQuotedStringLiteral(value, p, out var separator, out int separatorEnd))
                return false;

            if (separator.Length != 0)
                return false;

            p = separatorEnd + 1;
            p = SkipWhitespace(value, p);
            if (p >= value.Length || value[p] != ')')
                return false;

            nextIndex = p + 1;
            result = local.ToString();
            return true;
        }

        static bool TryReadQuotedStringLiteral(string value, int start, out string result, out int endIndex)
        {
            result = string.Empty;
            endIndex = start;
            if (start >= value.Length || !IsStringDelimiter(value[start]))
                return false;

            char delimiter = value[start];
            var local = new System.Text.StringBuilder();
            for (int i = start + 1; i < value.Length; i++)
            {
                char ch = value[i];
                if (ch == '\\')
                {
                    if (i + 1 >= value.Length)
                        return false;

                    local.Append(value[i + 1]);
                    i++;
                    continue;
                }

                if (delimiter == '`' && ch == '$' && i + 1 < value.Length && value[i + 1] == '{')
                    return false;

                if (ch == delimiter)
                {
                    result = local.ToString();
                    endIndex = i;
                    return true;
                }

                local.Append(ch);
            }

            return false;
        }

        static bool IsTerminal(char c)
            => c == '"' || c == '\'' || c == '`' || char.IsWhiteSpace(c) || c == ')' || c == '<' || c == '>';

        static bool IsStringDelimiter(char c) => c == '"' || c == '\'' || c == '`';
        static int SkipWhitespaceAndClosers(string value, int index)
        {
            int p = index;
            while (p < value.Length)
            {
                if (char.IsWhiteSpace(value[p]) || value[p] == ')')
                {
                    p++;
                    continue;
                }

                break;
            }

            return p;
        }

        static int SkipWhitespace(string value, int index)
        {
            int p = index;
            while (p < value.Length && char.IsWhiteSpace(value[p]))
                p++;
            return p;
        }

        static int SkipWhitespaceAndOpeners(string value, int index)
        {
            int p = index;
            while (p < value.Length)
            {
                if (char.IsWhiteSpace(value[p]) || value[p] == '(')
                {
                    p++;
                    continue;
                }

                break;
            }

            return p;
        }
    }

    private static bool TryParseDataUriPayload(string uri, out string? mediaType, out byte[]? sample, out bool isBase64)
    {
        mediaType = null;
        sample = null;
        isBase64 = false;
        try
        {
            if (!uri.StartsWith("data:", StringComparison.OrdinalIgnoreCase)) return false;
            int comma = uri.IndexOf(','); if (comma < 0) return false;
            var header = uri.Substring(5, comma - 5); // between data: and comma
            var lower = header.ToLowerInvariant();
            // Extract media type before first ';'
            int sc = header.IndexOf(';');
            if (sc > 0) mediaType = header.Substring(0, sc).Trim();
            else if (!string.IsNullOrWhiteSpace(header)) mediaType = header.Trim();
            string payload = uri.Substring(comma + 1);
            int maxDecodedBytes = Math.Max(1, OperationSettings.EncodedDecodeMaxBytes);
            isBase64 = lower.Contains(";base64");
            if (isBase64)
            {
                int maxBase64Chars = ((maxDecodedBytes + 2) / 3) * 4 + 8;
                var sb = new System.Text.StringBuilder(Math.Min(payload.Length, maxBase64Chars));
                foreach (var ch in payload)
                {
                    if (sb.Length >= maxBase64Chars) break;
                    if (ch == '-') sb.Append('+');
                    else if (ch == '_') sb.Append('/');
                    else if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '+' || ch == '/' || ch == '=') sb.Append(ch);
                }
                var s = sb.ToString(); int mod = s.Length % 4; if (mod != 0) s = s.PadRight(s.Length + (4 - mod), '=');
                var raw = Convert.FromBase64String(s);
                int max = Math.Min(raw.Length, maxDecodedBytes);
                sample = raw.Take(max).ToArray();
                return sample.Length > 0;
            }

            var bytes = new List<byte>(Math.Min(maxDecodedBytes, Math.Max(16, payload.Length)));
            for (int i = 0; i < payload.Length && bytes.Count < maxDecodedBytes; i++)
            {
                char ch = payload[i];
                if (ch == '%' && i + 2 < payload.Length && Uri.IsHexDigit(payload[i + 1]) && Uri.IsHexDigit(payload[i + 2]))
                {
                    bytes.Add(Convert.ToByte(payload.Substring(i + 1, 2), 16));
                    i += 2;
                    continue;
                }

                if (ch <= 0x7F)
                {
                    bytes.Add((byte)ch);
                    continue;
                }

                var utf8 = System.Text.Encoding.UTF8.GetBytes(ch.ToString());
                foreach (var b in utf8)
                {
                    if (bytes.Count >= maxDecodedBytes) break;
                    bytes.Add(b);
                }
            }

            sample = bytes.Count > 0 ? bytes.ToArray() : Array.Empty<byte>();
            return sample.Length > 0;
        } catch { return false; }
    }

    private static string? InferDataUriExtensionFromMediaType(string? mediaType)
    {
        if (string.IsNullOrWhiteSpace(mediaType)) return null;
        var normalized = mediaType!.Trim().ToLowerInvariant();
        return normalized switch
        {
            "application/javascript" or "text/javascript" or "application/x-javascript" => "js",
            "text/html" => "html",
            "application/json" or "text/json" => "json",
            "application/xml" or "text/xml" => "xml",
            "image/svg+xml" => "svg",
            "text/css" => "css",
            "text/plain" => "txt",
            "text/x-powershell" or "application/x-powershell" => "ps1",
            "text/vbscript" => "vbs",
            "text/x-shellscript" or "application/x-sh" => "sh",
            _ => null
        };
    }

}
