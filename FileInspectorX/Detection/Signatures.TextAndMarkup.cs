namespace FileInspectorX;

/// <summary>
/// Text and markup format detection (JSON, XML/HTML, YAML, EML, CSV/TSV/INI/LOG) and Outlook MSG hints.
/// </summary>
internal static partial class Signatures {
    private const int BINARY_SCAN_LIMIT = 1024;
    private const int HEADER_BYTES = 2048;
    // see FileInspectorX.Settings for configurable thresholds

internal static bool TryMatchText(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result, string? declaredExtension = null) {
        result = null;
        if (src.Length == 0) return false;

        // Note: we may transcode UTF-16 BOM text to UTF-8 bytes for downstream heuristics.
        // Keep the original BOM charset for MIME/Reason hints.
        ReadOnlySpan<byte> data = src;

        // BOMs: record and continue refining instead of early-returning as plain text.
        // This allows CSV/TSV/JSON/XML detection to work on UTF-8/UTF-16 files exported with BOMs.
        int bomSkip = 0;
        string? bomCharset = null;
        if (src.Length >= 3 && src[0] == 0xEF && src[1] == 0xBB && src[2] == 0xBF) { bomSkip = 3; bomCharset = "utf-8"; }
        else if (src.Length >= 2 && src[0] == 0xFF && src[1] == 0xFE) { bomSkip = 2; bomCharset = "utf-16le"; }
        else if (src.Length >= 2 && src[0] == 0xFE && src[1] == 0xFF) { bomSkip = 2; bomCharset = "utf-16be"; }

        // UTF-16 BOM text contains NUL bytes. Transcode to UTF-8 bytes so the existing heuristics work.
        if (bomCharset == "utf-16le" || bomCharset == "utf-16be")
        {
            try
            {
                var enc = bomCharset == "utf-16le" ? System.Text.Encoding.Unicode : System.Text.Encoding.BigEndianUnicode;
                // Transcode only a small prefix (detection is HEADER_BYTES bounded) to avoid large temporary allocations
                // if callers provide a large buffer.
                int remaining = src.Length - bomSkip;
                int maxUtf16Bytes = Math.Min(remaining, HEADER_BYTES * 4); // 8KB UTF-16 => ~4KB UTF-8 (ASCII-heavy)
                if (maxUtf16Bytes <= 0) return false;
                if ((maxUtf16Bytes & 1) == 1) maxUtf16Bytes--; // UTF-16 code units are 2 bytes
                if (maxUtf16Bytes <= 0) return false;
                var utf16 = src.Slice(bomSkip, maxUtf16Bytes).ToArray();
                var transcoded = System.Text.Encoding.Convert(enc, System.Text.Encoding.UTF8, utf16);
                data = transcoded;
                bomSkip = 0;
            }
            catch
            {
                return false;
            }
        }

        // Binary heuristic: NUL in head implies not text (quick bail-out)
        for (int i = 0; i < data.Length && i < BINARY_SCAN_LIMIT; i++) if (data[i] == 0x00) return false;
        int nulScan = Math.Min(2048, data.Length);
        for (int i = 0; i < nulScan; i++) { if (data[i] == 0x00) return false; }

        var decl = (declaredExtension ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();
        bool declaredMd = decl == "md" || decl == "markdown";
        bool declaredLog = decl == "log";
        bool declaredIni = decl == "ini";
        bool declaredInf = decl == "inf";
        bool declaredToml = decl == "toml";
        bool declaredAdmx = decl == "admx";
        bool declaredAdml = decl == "adml";
        bool declaredCmd = decl == "cmd";

        // Trim leading whitespace for structure checks
        int start = bomSkip; while (start < data.Length && char.IsWhiteSpace((char)data[start])) start++;
        var head = data.Slice(start, Math.Min(HEADER_BYTES, data.Length - start));
        // Cache string conversions (single pass) for heuristics that need them
        static string Utf8(ReadOnlySpan<byte> s) { if (s.Length == 0) return string.Empty; var a = s.ToArray(); return System.Text.Encoding.UTF8.GetString(a); }
        var headStr = Utf8(head);
        var headLower = headStr.ToLowerInvariant();

        // RTF (respect BOM/whitespace trimming)
        if (head.Length >= 5 && head[0] == '{' && head[1] == '\\' && head[2] == 'r' && head[3] == 't' && head[4] == 'f') { result = new ContentTypeDetectionResult { Extension = "rtf", MimeType = "application/rtf", Confidence = "Medium", Reason = "text:rtf" }; return true; }

        // PEM and PGP ASCII-armored blocks are handled later with specific types (asc/crt/key/csr).

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
            if (headLower.Contains("-----begin ")) { }
            else {
            int allowed = 0, total = 0, eq = 0, contig = 0, maxContig = 0, urlSafe = 0, hexish = 0;
            int limit = Math.Min(head.Length, Settings.EncodedBase64ProbeChars);
            for (int i = 0; i < limit; i++)
            {
                byte c = head[i];
                bool ws = c == (byte)'\r' || c == (byte)'\n' || c == (byte)'\t' || c == (byte)' ';
                bool isHex = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
                bool b64 = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
                bool url = c == '-' || c == '_'; if (url) urlSafe++; // URL-safe variant
                if (!ws) { total++; if (b64 || url) { allowed++; contig++; if (isHex) hexish++; if (c == '=') eq++; } else { if (contig > maxContig) maxContig = contig; contig = 0; } }
            }
            if (contig > maxContig) maxContig = contig;
            // Prefer hex classification when the run is almost pure hex and lacks '=' and URL-safe tokens
            if (total > 0 && hexish >= (int)(total * 0.95) && eq == 0 && urlSafe == 0) { }
            else if (total >= Settings.EncodedBase64MinBlock && allowed >= (int)(total * Settings.EncodedBase64AllowedRatio) && (maxContig >= Settings.EncodedBase64MinBlock))
            {
                // Avoid trivial JSON with many base64-like tokens by requiring some '=' padding or long continuous chunk
                bool acceptRaw = eq > 0 || urlSafe > 0 || (maxContig >= 256 && (allowed >= (int)(total * 0.98)));
                if (acceptRaw) {
                    string variant = urlSafe > 0 ? "urlsafe" : (eq > 0 ? "padded" : "raw");
                    result = new ContentTypeDetectionResult { Extension = "b64", MimeType = "application/base64", Confidence = "Low", Reason = "text:base64", ReasonDetails = variant };
                    return true;
                }
            }
            }
        }

        // Large hex dump (continuous hex digits possibly with spaces/newlines)
        {
            int hex = 0, other = 0, contigHex = 0, maxContigHex = 0;
            int limit = Math.Min(head.Length, Settings.EncodedBase64ProbeChars);
            for (int i = 0; i < limit; i++)
            {
                byte c = head[i];
                bool ws = c == (byte)'\r' || c == (byte)'\n' || c == (byte)'\t' || c == (byte)' ';
                bool hx = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
                if (!ws) { if (hx) { hex++; contigHex++; } else { other++; if (contigHex > maxContigHex) maxContigHex = contigHex; contigHex = 0; } }
            }
            if (contigHex > maxContigHex) maxContigHex = contigHex;
            if (hex >= Settings.EncodedHexMinChars && maxContigHex >= Settings.EncodedHexMinChars && hex > other * 4)
            {
                result = new ContentTypeDetectionResult { Extension = "hex", MimeType = "text/plain", Confidence = "Low", Reason = "text:hex" };
                return true;
            }
        }

        // NDJSON / JSON Lines (require at least two JSON-looking lines). Must come before single-object JSON check.
        {
            int ln1 = head.IndexOf((byte)'\n'); if (ln1 < 0) ln1 = head.Length;
            var l1 = TrimBytes(head.Slice(0, ln1));
            var rem = head.Slice(Math.Min(ln1 + 1, head.Length));
            int ln2 = rem.IndexOf((byte)'\n'); if (ln2 < 0) ln2 = rem.Length;
            var l2 = TrimBytes(rem.Slice(0, ln2));
            static bool LooksJsonLine(ReadOnlySpan<byte> l) {
                if (l.Length < 2) return false;
                int i = 0; while (i < l.Length && (l[i] == (byte)' ' || l[i] == (byte)'\t')) i++;
                if (i >= l.Length || l[i] != (byte)'{') return false;
                int q = l.IndexOf((byte)'"'); if (q < 0) return false;
                int colon = l.IndexOf((byte)':'); if (colon < 0) return false;
                int end = l.LastIndexOf((byte)'}'); if (end < 0) return false;
                // light structure check: braces balanced (depth==0), at least one colon outside quotes
                int depth = 0; bool inQ = false; bool colonOut = false; for (int k = 0; k < l.Length; k++) { byte c = l[k]; if (c == (byte)'"') { inQ = !inQ; } else if (!inQ) { if (c == (byte)'{') depth++; else if (c == (byte)'}') depth--; else if (c == (byte)':') colonOut = true; } }
                if (depth != 0) return false; return colonOut && colon > q && end > colon; }
            bool j1 = LooksJsonLine(l1); bool j2 = LooksJsonLine(l2);
            if (j1 && j2) {
                // Confidence: Medium if a third line also looks like JSON; Low otherwise
                var rem2 = rem.Slice(Math.Min(ln2 + 1, rem.Length)); int ln3 = rem2.IndexOf((byte)'\n'); if (ln3 < 0) ln3 = rem2.Length; var l3 = TrimBytes(rem2.Slice(0, ln3));
                string conf = LooksJsonLine(l3) ? "Medium" : "Low";
                result = new ContentTypeDetectionResult { Extension = "ndjson", MimeType = "application/x-ndjson", Confidence = conf, Reason = "text:ndjson" }; return true;
            }
        }

        // JSON (tighter heuristics)
        if (head.Length > 0 && (head[0] == (byte)'{' || head[0] == (byte)'[')) {
            int len = Math.Min(2048, head.Length);
            var slice = head.Slice(0, len);
            bool looksObject = slice[0] == (byte)'{';
            bool looksArray = slice[0] == (byte)'[';

            if (looksArray) {
                bool hasClose = slice.IndexOf((byte)']') >= 0;
                int commaCount = Count(slice, (byte)',');
                bool hasObjectItem = slice.IndexOf((byte)'{') >= 0;
                if ((commaCount >= 1 && hasClose) || hasObjectItem) {
                    bool hasQuotedColon = HasQuotedKeyColon(slice);
                    if (hasObjectItem ? hasQuotedColon : true) {
                        result = new ContentTypeDetectionResult { Extension = "json", MimeType = "application/json", Confidence = hasObjectItem ? "Medium" : "Low", Reason = "text:json", ReasonDetails = hasObjectItem ? "json:array-of-objects" : "json:array-of-primitives" }; return true;
                    }
                }
            }

            if (looksObject) {
                bool hasQuotedColon = HasQuotedKeyColon(slice);
                bool hasClose = slice.IndexOf((byte)'}') >= 0;
                if (hasQuotedColon && hasClose) { result = new ContentTypeDetectionResult { Extension = "json", MimeType = "application/json", Confidence = "Medium", Reason = "text:json", ReasonDetails = "json:object-key-colon" }; return true; }
            }
        }
        // XML / HTML
        if (head.Length >= 5 && head[0] == (byte)'<') {
            if (head.Length >= 5 && head.Slice(0, 5).SequenceEqual("<?xml"u8)) {
                var ext = declaredAdmx ? "admx" : (declaredAdml ? "adml" : "xml");
                result = new ContentTypeDetectionResult { Extension = ext, MimeType = "application/xml", Confidence = "Medium", Reason = "text:xml", ReasonDetails = ext == "xml" ? null : $"xml:decl-{ext}" };
                return true;
            }
            if (head.IndexOf("<!DOCTYPE html"u8) >= 0 || head.IndexOf("<html"u8) >= 0) { result = new ContentTypeDetectionResult { Extension = "html", MimeType = "text/html", Confidence = "Medium", Reason = "text:html" }; return true; }
        }

        // (moved NDJSON block earlier)

        // Quick PGP ASCII-armored blocks (place before YAML '---' to avoid front-matter collision)
        {
            if (headLower.Contains("-----begin pgp message-----")) { result = new ContentTypeDetectionResult { Extension = "asc", MimeType = "application/pgp-encrypted", Confidence = "Medium", Reason = "text:pgp-message" }; return true; }
            if (headLower.Contains("-----begin pgp public key block-----")) { result = new ContentTypeDetectionResult { Extension = "asc", MimeType = "application/pgp-keys", Confidence = "Medium", Reason = "text:pgp-public-key" }; return true; }
            if (headLower.Contains("-----begin pgp signature-----")) { result = new ContentTypeDetectionResult { Extension = "asc", MimeType = "application/pgp-signature", Confidence = "Medium", Reason = "text:pgp-signature" }; return true; }
            if (headLower.Contains("-----begin pgp private key block-----")) { result = new ContentTypeDetectionResult { Extension = "asc", MimeType = "application/pgp-keys", Confidence = "Medium", Reason = "text:pgp-private-key" }; return true; }
        }

        // PEM family (certificate / CSR / private keys) and OpenSSH key — must come before YAML
        // to avoid false positives from lines like "Proc-Type:" / "DEK-Info:".
        {
            var l = headLower;
            if (l.Contains("-----begin certificate-----")) { result = new ContentTypeDetectionResult { Extension = "crt", MimeType = "application/pkix-cert", Confidence = "Medium", Reason = "text:pem-cert" }; return true; }
            if (l.Contains("-----begin x509 certificate-----") || l.Contains("-----begin trusted certificate-----")) { result = new ContentTypeDetectionResult { Extension = "crt", MimeType = "application/pkix-cert", Confidence = "Low", Reason = "text:pem-cert-variant" }; return true; }
            if (l.Contains("-----begin certificate request-----") || l.Contains("-----begin new certificate request-----")) { result = new ContentTypeDetectionResult { Extension = "csr", MimeType = "application/pkcs10", Confidence = "Medium", Reason = "text:pem-csr" }; return true; }
            if (l.Contains("-----begin private key-----") || l.Contains("-----begin encrypted private key-----") || l.Contains("-----begin rsa private key-----") || l.Contains("-----begin ec private key-----")) { result = new ContentTypeDetectionResult { Extension = "key", MimeType = "application/x-pem-key", Confidence = "Medium", Reason = "text:pem-key" }; return true; }
            if (l.Contains("-----begin openssh private key-----")) { result = new ContentTypeDetectionResult { Extension = "key", MimeType = "application/x-openssh-key", Confidence = "Medium", Reason = "text:openssh-key" }; return true; }
        }

        // YAML (document start) or refined key:value heuristics — guarded to avoid PEM/PGP collisions handled above.
        // Do not classify as YAML if strong PowerShell cues are present or if the content looks like Windows Event Viewer text export keys.
        if (head.Length >= 3 && head[0] == (byte)'-' && head[1] == (byte)'-' && head[2] == (byte)'-') {
            if (!HasPowerShellCues(head, headStr, headLower)) {
                var winLogLike = IndexOfToken(head, "Log Name:") >= 0 || IndexOfToken(head, "Event ID:") >= 0 || IndexOfToken(head, "Source:") >= 0 || IndexOfToken(head, "Task Category:") >= 0 || IndexOfToken(head, "Level:") >= 0;
                if (!winLogLike) { result = new ContentTypeDetectionResult { Extension = "yml", MimeType = "application/x-yaml", Confidence = "Low", Reason = "text:yaml", ReasonDetails = "yaml:front-matter" }; return true; }
            }
        }
        {
            // Heuristic tightening: count only plausible YAML key lines near the start.
            // Reject keys that appear inside quoted strings (common in scripts, e.g., Write-Host "...:").
            int yamlish = 0; int scanned = 0; int startLine = 0;
            for (int i = 0; i < head.Length && scanned < 6; i++) {
                if (head[i] == (byte)'\n') {
                    var raw = head.Slice(startLine, i - startLine);
                    var line = TrimBytes(raw);
                    // Ignore classic PEM headers that look like YAML key:value
                    var lineLower = new string(System.Text.Encoding.ASCII.GetChars(line.ToArray())).ToLowerInvariant();
                    if (lineLower.StartsWith("proc-type:") || lineLower.StartsWith("dek-info:")) { scanned++; startLine = i + 1; continue; }
                    if (LooksYamlKeyValue(line)) yamlish++;
                    scanned++;
                    startLine = i + 1;
                }
            }
            if (yamlish >= 2) {
                if (!HasPowerShellCues(head, headStr, headLower)) {
                    var winLogLike = IndexOfToken(head, "Log Name:") >= 0 || IndexOfToken(head, "Event ID:") >= 0 || IndexOfToken(head, "Source:") >= 0 || IndexOfToken(head, "Task Category:") >= 0 || IndexOfToken(head, "Level:") >= 0;
                    if (!winLogLike) { result = new ContentTypeDetectionResult { Extension = "yml", MimeType = "application/x-yaml", Confidence = "Low", Reason = "text:yaml-keys", ReasonDetails = $"yaml:key-lines={yamlish}" }; return true; }
                }
            }
        }

        // TOML heuristic (tables + key=value). Guarded to avoid misclassifying INI/INF (common in Windows/GPO).
        {
            if (!declaredToml && (declaredIni || declaredInf))
            {
                // Skip: INI/INF can look extremely similar to TOML at the top of the file.
                // INI detection below will classify these correctly.
            }
            else
            {
                int keys = 0, tables = 0, dotted = 0;
                bool hasArrayTables = false;
                bool hasSemicolonComments = false; // strong INI/INF signal when not declared TOML
                int scanned = 0; int startLine2 = 0;
                for (int i = 0; i < head.Length && scanned < 20; i++)
                {
                    if (head[i] == (byte)'\n')
                    {
                        var raw = head.Slice(startLine2, i - startLine2);
                        var line = TrimBytes(raw);
                        if (line.Length > 0 && line[0] == (byte)'#') { scanned++; startLine2 = i + 1; continue; } // TOML comment
                        if (line.Length > 0 && line[0] == (byte)';') { hasSemicolonComments = true; scanned++; startLine2 = i + 1; continue; } // INI/INF-style comment
                        if (line.Length >= 3 && line[0] == (byte)'[')
                        {
                            // [table] or [[array.of.tables]]
                            if (line.Length >= 4 && line[1] == (byte)'[')
                            {
                                // array of tables
                                if (line.IndexOf("]]"u8) > 1) { tables++; hasArrayTables = true; }
                            }
                            else if (line.IndexOf((byte)']') > 1) { tables++; }
                        }
                        int eq = line.IndexOf((byte)'=');
                        if (eq > 0 && eq < line.Length - 1)
                        {
                            // left side must be bare/dotted identifier
                            bool ok = true; int dots = 0; for (int k = 0; k < eq; k++) { byte c = line[k]; if (!(char.IsLetterOrDigit((char)c) || c == (byte)'_' || c == (byte)'.')) { ok = false; break; } if (c == (byte)'.') dots++; }
                            if (ok) { dotted += dots > 0 ? 1 : 0; keys++; }
                        }
                        scanned++; startLine2 = i + 1;
                    }
                }
                bool tomlStrong = hasArrayTables || dotted >= 1;
                bool allowUndeclared = tomlStrong && !hasSemicolonComments;
                if ((declaredToml || allowUndeclared) && (tables >= 1 && keys >= 1))
                {
                    result = new ContentTypeDetectionResult { Extension = "toml", MimeType = "application/toml", Confidence = "Low", Reason = "text:toml" };
                    return true;
                }
                // Lenient fallback using string scan: look for bracketed tables and multiple key=value in first 2KB
                if (declaredToml)
                {
                    var hbToml = new byte[Math.Min(head.Length, 2048)]; head.Slice(0, hbToml.Length).CopyTo(new System.Span<byte>(hbToml));
                    var s = System.Text.Encoding.UTF8.GetString(hbToml);
                    int eqCount = 0; foreach (var ch in s) if (ch == '=') eqCount++;
                    bool hasTable = s.Contains("\n[") || s.StartsWith("[");
                    if (hasTable && eqCount >= 2)
                    {
                        result = new ContentTypeDetectionResult { Extension = "toml", MimeType = "application/toml", Confidence = "Low", Reason = "text:toml" };
                        return true;
                    }
                }
            }
        }

        // EML basics (check first two lines for typical headers)
        {
            int n1 = head.IndexOf((byte)'\n'); if (n1 < 0) n1 = head.Length;
            var l1 = head.Slice(0, n1);
            var rem = head.Slice(Math.Min(n1 + 1, head.Length));
            int n2 = rem.IndexOf((byte)'\n'); if (n2 < 0) n2 = rem.Length;
            var l2 = rem.Slice(0, n2);
            bool hasFrom = l1.StartsWith("From:"u8) || l2.StartsWith("From:"u8);
            bool hasSubj = l1.StartsWith("Subject:"u8) || l2.StartsWith("Subject:"u8);
            bool hasMimeVer = head.IndexOf("MIME-Version:"u8) >= 0;
            bool hasContentType = head.IndexOf("Content-Type:"u8) >= 0;
            if ((hasFrom && hasSubj) || (hasMimeVer && hasContentType)) { result = new ContentTypeDetectionResult { Extension = "eml", MimeType = "message/rfc822", Confidence = "Low", Reason = "text:eml" }; return true; }
        }

        // MSG basics (very weak text fallback)
        if (head.IndexOf("__substg1.0_"u8) >= 0) { result = new ContentTypeDetectionResult { Extension = "msg", MimeType = "application/vnd.ms-outlook", Confidence = "Low", Reason = "msg:marker" }; return true; }

        // Quick Windows DNS log check very early (before generic log heuristics)
        if (head.IndexOf("DNS Server Log File"u8) >= 0 || head.IndexOf("DNS Server Log"u8) >= 0)
        {
            result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:log-dns" };
            return true;
        }

        // Delimiter heuristics shared by CSV/TSV + log detection
        var span = head;
        int nl = head.IndexOf((byte)'\n'); if (nl < 0) nl = head.Length;
        var line1 = span.Slice(0, nl);
        var rest = span.Slice(Math.Min(nl + 1, span.Length));
        int nl2 = rest.IndexOf((byte)'\n'); if (nl2 < 0) nl2 = rest.Length;
        var line2 = rest.Slice(0, nl2);

        // LOG heuristic (timestamps/levels) promoted ahead of CSV/Markdown to avoid mislabels
        static bool LooksLikeTimestamp(ReadOnlySpan<byte> l) {
            if (l.Length < 10) return false;
            bool y = IsDigit(l[0]) && IsDigit(l[1]) && IsDigit(l[2]) && IsDigit(l[3]);
            bool sep1 = l[4] == (byte)'-' || l[4] == (byte)'/';
            bool m = IsDigit(l[5]) && IsDigit(l[6]);
            bool sep2 = l[7] == (byte)'-' || l[7] == (byte)'/';
            bool d = IsDigit(l[8]) && IsDigit(l[9]);
            return y && sep1 && m && sep2 && d;
        }
        static bool StartsWithToken(ReadOnlySpan<byte> l, string token) {
            var tb = System.Text.Encoding.ASCII.GetBytes(token);
            if (l.Length < tb.Length) return false;
            for (int i = 0; i < tb.Length; i++) if (char.ToUpperInvariant((char)l[i]) != char.ToUpperInvariant((char)tb[i])) return false;
            return true;
        }

        bool logCues = LooksLikeTimestamp(line1) || LooksLikeTimestamp(line2) || StartsWithLevelToken(line1) || StartsWithLevelToken(line2);

        if (LooksLikeTimestamp(line1) && LooksLikeTimestamp(line2)) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Low", Reason = "text:log", ReasonDetails = "log:timestamps-2" }; return true; }

        int levelCount = 0;
        if (StartsWithLevelToken(line1)) levelCount++;
        if (StartsWithLevelToken(line2)) levelCount++;
        // include up to two more lines
        var rest2 = rest.Slice(Math.Min(nl2 + 1, rest.Length));
        int nl3 = rest2.IndexOf((byte)'\n'); if (nl3 < 0) nl3 = rest2.Length; var line3 = rest2.Slice(0, nl3);
        var rest3 = rest2.Slice(Math.Min(nl3 + 1, rest2.Length));
        int nl4 = rest3.IndexOf((byte)'\n'); if (nl4 < 0) nl4 = rest3.Length; var line4 = rest3.Slice(0, nl4);
        if (StartsWithLevelToken(line3)) levelCount++;
        if (StartsWithLevelToken(line4)) levelCount++;
        int tsCount = 0; if (LooksLikeTimestamp(line1)) tsCount++; if (LooksLikeTimestamp(line2)) tsCount++; if (LooksLikeTimestamp(line3)) tsCount++; if (LooksLikeTimestamp(line4)) tsCount++;
        if (tsCount >= 2) {
            result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Low", Reason = "text:log", ReasonDetails = "log:timestamps-multi" }; return true;
        }
        if (levelCount >= 2 || ((LooksLikeTimestamp(line1) || LooksLikeTimestamp(line2)) && levelCount >= 1)) {
            // Boost confidence when we have both timestamps and levels across lines
            var conf = levelCount >= 2 && (LooksLikeTimestamp(line1) || LooksLikeTimestamp(line2)) ? "Medium" : "Low";
            result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = conf, Reason = "text:log-levels", ReasonDetails = levelCount >= 2 ? $"log:levels-{levelCount}" : "log:timestamp+level" }; return true;
        }
        if (levelCount > 0) logCues = true;
        if (declaredLog && logCues) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Low", Reason = "text:log", ReasonDetails = "log:declared" }; return true; }

        // CSV/TSV/Delimited heuristics (look at first two lines) — also handle Excel 'sep=' directive and single-line CSV/TSV
        // Excel separator directive (first non-whitespace line like `sep=,` or `sep=;` or `sep=\t`)
        {
            string s = headStr.TrimStart('\ufeff', ' ', '\t', '\r', '\n');
            if (s.StartsWith("sep=", System.StringComparison.OrdinalIgnoreCase))
            {
                if (!logCues)
                {
                    bool isTab = s.StartsWith("sep=\\t", System.StringComparison.OrdinalIgnoreCase) || (s.Length > 4 && s[4] == '\t');
                    if (isTab) { result = new ContentTypeDetectionResult { Extension = "tsv", MimeType = "text/tab-separated-values", Confidence = "Low", Reason = "text:tsv", ReasonDetails = "tsv:sep-directive" }; return true; }
                    else { result = new ContentTypeDetectionResult { Extension = "csv", MimeType = "text/csv", Confidence = "Low", Reason = "text:csv", ReasonDetails = "csv:sep-directive" }; return true; }
                }
            }
        }

        int commas1 = Count(line1, (byte)','); int commas2 = Count(line2, (byte)',');
        int semis1 = Count(line1, (byte)';'); int semis2 = Count(line2, (byte)';');
        int pipes1 = Count(line1, (byte)'|'); int pipes2 = Count(line2, (byte)'|');
        int tabs1 = Count(line1, (byte)'\t'); int tabs2 = Count(line2, (byte)'\t');
        if (!logCues) {
            if ((commas1 >= 1 && commas2 >= 1 && Math.Abs(commas1 - commas2) <= 2) || (semis1 >= 1 && semis2 >= 1 && Math.Abs(semis1 - semis2) <= 2) || (pipes1 >= 1 && pipes2 >= 1 && Math.Abs(pipes1 - pipes2) <= 2)) { result = new ContentTypeDetectionResult { Extension = "csv", MimeType = "text/csv", Confidence = "Low", Reason = "text:csv", ReasonDetails = "csv:delimiter-repeat-2lines" }; return true; }
            if (tabs1 >= 1 && tabs2 >= 1 && Math.Abs(tabs1 - tabs2) <= 2) { result = new ContentTypeDetectionResult { Extension = "tsv", MimeType = "text/tab-separated-values", Confidence = "Low", Reason = "text:tsv", ReasonDetails = "tsv:tabs-2lines" }; return true; }
            if (line2.Length == 0 || (line2.Length == 0 && rest.Length == 0)) {
                static int TokenCount(ReadOnlySpan<byte> l, byte sep) {
                    if (l.Length == 0) return 0;
                    int tokens = 1; for (int i = 0; i < l.Length; i++) if (l[i] == sep) tokens++; return tokens;
                }
                if (commas1 >= 2 && TokenCount(line1, (byte)',') >= 3) { result = new ContentTypeDetectionResult { Extension = "csv", MimeType = "text/csv", Confidence = "Low", Reason = "text:csv", ReasonDetails = "csv:single-line" }; return true; }
                if (semis1 >= 2 && TokenCount(line1, (byte)';') >= 3) { result = new ContentTypeDetectionResult { Extension = "csv", MimeType = "text/csv", Confidence = "Low", Reason = "text:csv", ReasonDetails = "csv:single-line" }; return true; }
                if (tabs1 >= 2 && TokenCount(line1, (byte)'\t') >= 3) { result = new ContentTypeDetectionResult { Extension = "tsv", MimeType = "text/tab-separated-values", Confidence = "Low", Reason = "text:tsv", ReasonDetails = "tsv:single-line" }; return true; }
            }
        }

        // INI/INF heuristic (guarded against PowerShell/type-accelerator patterns)
        {
            bool hasPsCues = HasPowerShellCues(head, headStr, headLower) || HasVerbNounCmdlet(headStr);
            if (!hasPsCues)
            {
                bool hasSection = false;
                bool hasEquals = false;

                // Look for [Section] and key=value within the first few meaningful lines.
                // This avoids false positives when an INI file starts with comments/blank lines.
                int meaningfulLines = 0;
                int lineStart = 0;
                for (int i = 0; i < head.Length && meaningfulLines < 8; i++)
                {
                    if (head[i] == (byte)'\n' || i == head.Length - 1)
                    {
                        int end = head[i] == (byte)'\n' ? i : i + 1;
                        var raw = head.Slice(lineStart, Math.Max(0, end - lineStart));
                        lineStart = i + 1;
                        var line = TrimBytes(raw);
                        if (line.Length == 0) continue;

                        // Skip comment-only lines
                        if (line[0] == (byte)';' || line[0] == (byte)'#') continue;

                        if (!hasSection && LooksIniSectionLine(line)) hasSection = true;
                        if (!hasEquals)
                        {
                            int eq = line.IndexOf((byte)'=');
                            if (eq > 0) hasEquals = true;
                        }

                        meaningfulLines++;
                        if (hasSection && hasEquals) break;
                    }
                }

                if (hasSection && hasEquals)
                {
                    var ext = declaredInf ? "inf" : "ini";
                    result = new ContentTypeDetectionResult { Extension = ext, MimeType = "text/plain", Confidence = "Low", Reason = "text:ini", ReasonDetails = ext == "inf" ? "inf:section+equals" : "ini:section+equals" };
                    return true;
                }
            }
        }

        // Markdown quick cues (guarded to avoid scripts/logs; allow when declared .md)
        {
            var s = headStr; var sl = headLower;
            bool looksMd = sl.StartsWith("# ") || sl.Contains("\n# ") || sl.Contains("```") || sl.Contains("](");
            int mdCues = 0;
            if (sl.StartsWith("# ") || sl.Contains("\n# ")) mdCues++;
            if (sl.Contains("```")) mdCues++;
            if (sl.Contains("](")) mdCues++;
            if (sl.Contains("\n- ") || sl.StartsWith("- ") || sl.Contains("\n* ") || sl.StartsWith("* ")) mdCues++; // bullet list hint
            // Treat presence of a heading plus any additional non-empty line as another weak cue (without needing link/fence)
            if (mdCues == 1) {
                var lines = headStr.Split('\n');
                if (lines.Length >= 2 && lines[1].Trim().Length > 0) mdCues++;
            }
            if (looksMd)
            {
                // Do not classify as Markdown if strong PowerShell cues or log cues are present
                var okByCues = declaredMd ? mdCues >= 1 : mdCues >= 2;
                if (okByCues && (!HasPowerShellCues(head, headStr, headLower) && !logCues)) { result = new ContentTypeDetectionResult { Extension = "md", MimeType = "text/markdown", Confidence = "Low", Reason = "text:md" }; return true; }
            }
        }

        // PowerShell heuristic (uses cached headStr/headLower)

        // Windows well-known text logs: DNS, Firewall, Netlogon, Event Viewer text export
        if (headLower.Contains("dns server log") || headLower.Contains("dns server log file")) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:log-dns" }; return true; }
        if ((headLower.Contains("microsoft windows firewall") || headLower.Contains("windows firewall")) && headLower.Contains("fields:")) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:log-firewall" }; return true; }
        // Netlogon logs often include repeated "netlogon" and secure channel messages
        {
            int netCount = 0; int idx = 0; while ((idx = headLower.IndexOf("netlogon", idx, System.StringComparison.Ordinal)) >= 0) { netCount++; idx += 8; if (netCount > 3) break; }
            if (netCount >= 2 || headLower.Contains("secure channel") || headLower.Contains("netrlogon")) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:log-netlogon" }; return true; }
        }
        if ((headLower.Contains("log name:") && headLower.Contains("event id:")) || (headLower.Contains("source:") && headLower.Contains("task category:") && headLower.Contains("level:"))) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:event-txt" }; return true; }

        // Microsoft DHCP Server audit logs (similar to IIS/Firewall headers)
        if (headLower.Contains("#software: microsoft dhcp server") && headLower.Contains("#fields:")) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:log-dhcp" }; return true; }

        // Microsoft Exchange Message Tracking logs
        if (headLower.Contains("message tracking log file") || headLower.Contains("#software: microsoft exchange")) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:log-exchange" }; return true; }

        // Windows Defender textual logs (MpCmdRun outputs or Event Viewer text exports mentioning Defender)
        if (headLower.Contains("windows defender") || headLower.Contains("microsoft defender") || headLower.Contains("mpcmdrun")) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Low", Reason = "text:log-defender" }; return true; }

        // SQL Server ERRORLOG text
        if ((headLower.Contains("sql server is starting") || headLower.Contains("sql server") || headLower.Contains("errorlog")) && headLower.Contains("spid")) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:log-sql-errorlog" }; return true; }

        // NPS / RADIUS (IAS/NPS) text logs
        if ((headLower.Contains("#software: microsoft internet authentication service") || headLower.Contains("#software: microsoft network policy server")) && headLower.Contains("#fields:")) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:log-nps" }; return true; }

        // SQL Server Agent logs (SQLAgent.out / text snippets)
        if (headLower.Contains("sqlserveragent") || headLower.Contains("sql server agent")) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Low", Reason = "text:log-sqlagent" }; return true; }

        // PEM/PGP ASCII-armored blocks (detect before script heuristics)
        {
            if (headLower.Contains("-----begin pgp public key block-----")) { result = new ContentTypeDetectionResult { Extension = "asc", MimeType = "application/pgp-keys", Confidence = "Medium", Reason = "text:pgp-public-key" }; return true; }
            if (headLower.Contains("-----begin pgp private key block-----")) { result = new ContentTypeDetectionResult { Extension = "asc", MimeType = "application/pgp-keys", Confidence = "Medium", Reason = "text:pgp-private-key" }; return true; }
            if (headLower.Contains("-----begin pgp message-----")) { result = new ContentTypeDetectionResult { Extension = "asc", MimeType = "application/pgp-encrypted", Confidence = "Medium", Reason = "text:pgp-message" }; return true; }
            if (headLower.Contains("-----begin pgp signature-----")) { result = new ContentTypeDetectionResult { Extension = "asc", MimeType = "application/pgp-signature", Confidence = "Medium", Reason = "text:pgp-signature" }; return true; }

            if (headLower.Contains("-----begin certificate request-----") || headLower.Contains("-----begin new certificate request-----")) { result = new ContentTypeDetectionResult { Extension = "csr", MimeType = "application/pkcs10", Confidence = "Medium", Reason = "text:pkcs10" }; return true; }
            if (headLower.Contains("-----begin certificate-----")) { result = new ContentTypeDetectionResult { Extension = "crt", MimeType = "application/pkix-cert", Confidence = "Medium", Reason = "text:pem-cert" }; return true; }
            if (headLower.Contains("-----begin public key-----")) { result = new ContentTypeDetectionResult { Extension = "pub", MimeType = "application/x-pem-key", Confidence = "Low", Reason = "text:pem-pubkey" }; return true; }
            if (headLower.Contains("-----begin openssh private key-----") || headLower.Contains("openssh private key")) { result = new ContentTypeDetectionResult { Extension = "key", MimeType = "application/x-openssh-key", Confidence = "Medium", Reason = "text:openssh-key" }; return true; }
            if (headLower.Contains("-----begin private key-----") || headLower.Contains("-----begin rsa private key-----") || headLower.Contains("-----begin dsa private key-----") || headLower.Contains("-----begin ec private key-----")) { result = new ContentTypeDetectionResult { Extension = "key", MimeType = "application/x-pem-key", Confidence = "Medium", Reason = "text:pem-key" }; return true; }
        }
        // PowerShell heuristic — includes pwsh/powershell shebang, cmdlet verb-noun/pipeline/attribute cues, and module/data hints
        {
            if (declaredMd) { /* allow markdown with fenced PS examples */ }
            bool psShebang = headLower.Contains("#!/usr/bin/env pwsh") || headLower.Contains("#!/usr/bin/pwsh") ||
                             headLower.Contains("#!/usr/bin/env powershell") || headLower.Contains("#!/usr/bin/powershell");
            if (psShebang)
            {
                result = new ContentTypeDetectionResult { Extension = "ps1", MimeType = "text/x-powershell", Confidence = "Medium", Reason = "text:ps1-shebang", ReasonDetails = "ps1:shebang" };
                return true;
            }
            bool declaredPsm1 = decl == "psm1";
            bool declaredPsd1 = decl == "psd1";
            bool hasVerbNoun = HasVerbNounCmdlet(headStr);
            bool hasPipeline = (headStr.IndexOf("| Where-Object", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
                                headStr.IndexOf("| ForEach-Object", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
                                headStr.IndexOf("| Select-Object", System.StringComparison.OrdinalIgnoreCase) >= 0) &&
                               headStr.IndexOf("$", System.StringComparison.Ordinal) >= 0;
            bool hasModuleExport = headStr.IndexOf("Export-ModuleMember", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
                                   headStr.IndexOf("FunctionsToExport", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
                                   headStr.IndexOf("RootModule", System.StringComparison.OrdinalIgnoreCase) >= 0;
            bool psd1Hashtable = declaredPsd1 && headStr.TrimStart().StartsWith("@{");

            int cues = 0;
            int strong = 0;
            if (headLower.Contains("[cmdletbinding]")) cues++;
            if (headLower.Contains("#requires")) cues++;
            if (headLower.Contains("param(")) { cues++; strong++; }
            if (headLower.Contains("begin{")) { cues++; strong++; }
            if (headLower.Contains("process{")) { cues++; strong++; }
            if (headLower.Contains("end{")) { cues++; strong++; }
            if (headLower.Contains("[parameter(")) { cues++; strong++; }
            if (headLower.Contains("[validate")) { cues++; strong++; }
            if (headStr.IndexOf("Write-Host", System.StringComparison.Ordinal) >= 0) cues++;
            if (headStr.IndexOf("Import-Module", System.StringComparison.Ordinal) >= 0) cues++;
            if (headStr.IndexOf("New-Object", System.StringComparison.Ordinal) >= 0) cues++;
            // Count Get-/Set- as a mild cue only when combined with another cue
            bool hasGetSet = headStr.IndexOf("Get-", System.StringComparison.Ordinal) >= 0 || headStr.IndexOf("Set-", System.StringComparison.Ordinal) >= 0;
            if (hasGetSet) cues++;
            if (hasVerbNoun) { cues++; strong++; }
            if (hasPipeline) { cues++; strong++; }

            // Module/data file special-cases
            if (declaredPsm1 && (hasModuleExport || hasVerbNoun))
            {
                result = new ContentTypeDetectionResult { Extension = "psm1", MimeType = "text/x-powershell", Confidence = "Medium", Reason = "text:psm1", ReasonDetails = "psm1:module-cues" }; return true;
            }
            if (declaredPsd1 && (psd1Hashtable || hasModuleExport))
            {
                result = new ContentTypeDetectionResult { Extension = "psd1", MimeType = "text/x-powershell", Confidence = "Low", Reason = "text:psd1", ReasonDetails = psd1Hashtable ? "psd1:hashtable" : "psd1:module-keys" }; return true;
            }

            if (cues >= 2 || (cues >= 1 && strong >= 1)) {
                var conf = cues >= 3 ? "Medium" : "Low";
                var details = cues >= 3 ? "ps1:multi-cues" : (strong >= 1 && cues == 1 ? "ps1:single-strong-cue" : "ps1:common-cmdlets");
                result = new ContentTypeDetectionResult { Extension = "ps1", MimeType = "text/x-powershell", Confidence = conf, Reason = "text:ps1", ReasonDetails = details }; return true;
            }
        }

        // Local helper to guard YAML against PowerShell-looking content
        static bool HasPowerShellCues(ReadOnlySpan<byte> headSpan, string s, string sl)
        {
            int cues = 0;
            int strong = 0;

            if (sl.Contains("[cmdletbinding]")) { cues++; strong++; }
            if (sl.Contains("#requires")) { cues++; strong++; }
            if (sl.Contains("param(")) { cues++; strong++; }
            if (sl.Contains("begin{")) { cues++; strong++; }
            if (sl.Contains("process{")) { cues++; strong++; }
            if (sl.Contains("end{")) { cues++; strong++; }
            if (sl.Contains("[parameter(")) { cues++; strong++; }
            if (sl.Contains("[validate")) { cues++; strong++; }

            // Type accelerators / casts used in PowerShell: [int]$x, [string] $name, etc.
            if (sl.Contains("]$") || sl.Contains("] $")) { cues++; strong++; }
            // Common PowerShell literals / constructs
            if (sl.Contains("$true") || sl.Contains("$false") || sl.Contains("$null")) { cues++; strong++; }
            if (sl.Contains("@{") || sl.Contains("@(") || sl.Contains("$(") || sl.Contains("${")) { cues++; }
            if (sl.Contains("[pscustomobject]@{")) { cues++; strong++; }

            // PowerShell operators (avoid matching "-in" inside other words by checking token-ish boundaries)
            static bool HasOp(string text, string op)
            {
                int idx = 0;
                while ((idx = text.IndexOf(op, idx, System.StringComparison.Ordinal)) >= 0)
                {
                    bool leftOk = idx == 0 || char.IsWhiteSpace(text[idx - 1]) || text[idx - 1] == '(' || text[idx - 1] == '{' || text[idx - 1] == ';';
                    int end = idx + op.Length;
                    bool rightOk = end >= text.Length || char.IsWhiteSpace(text[end]) || text[end] == ')' || text[end] == '}' || text[end] == ';';
                    if (leftOk && rightOk) return true;
                    idx = end;
                }
                return false;
            }

            if (HasOp(sl, "-eq") || HasOp(sl, "-ne") || HasOp(sl, "-like") || HasOp(sl, "-notlike") || HasOp(sl, "-match") ||
                HasOp(sl, "-contains") || HasOp(sl, "-notcontains") || HasOp(sl, "-in") || HasOp(sl, "-notin") ||
                HasOp(sl, "-is") || HasOp(sl, "-isnot") || HasOp(sl, "-as"))
            {
                cues++; strong++;
            }

            if (s.IndexOf("Write-Host", System.StringComparison.OrdinalIgnoreCase) >= 0) { cues++; strong++; }
            if (s.IndexOf("Import-Module", System.StringComparison.OrdinalIgnoreCase) >= 0) cues++;
            if (s.IndexOf("New-Object", System.StringComparison.OrdinalIgnoreCase) >= 0) cues++;
            if (s.IndexOf("Get-", System.StringComparison.OrdinalIgnoreCase) >= 0 || s.IndexOf("Set-", System.StringComparison.OrdinalIgnoreCase) >= 0) cues++;

            return strong >= 1 || cues >= 2;
        }

        // VBScript heuristic
        if (headLower.Contains("wscript.") || headLower.Contains("createobject(") || headLower.Contains("vbscript") || headLower.Contains("dim ") || headLower.Contains("end sub") || headLower.Contains("option explicit") || headLower.Contains("on error resume next")) {
            var conf = (headLower.Contains("option explicit") || headLower.Contains("on error resume next") || headLower.Contains("createobject(")) ? "Medium" : "Low";
            result = new ContentTypeDetectionResult { Extension = "vbs", MimeType = "text/vbscript", Confidence = conf, Reason = "text:vbs", ReasonDetails = conf=="Medium"?"vbs:explicit+error|createobject":"vbs:wscript+dim" }; return true;
        }

        // Shell script heuristic
        if (headLower.Contains("#!/bin/sh") || headLower.Contains("#!/usr/bin/env sh") || headLower.Contains("#!/usr/bin/env bash") || headLower.Contains("#!/bin/bash") || headLower.Contains("#!/usr/bin/env zsh") || headLower.Contains("#!/bin/zsh")) {
            result = new ContentTypeDetectionResult { Extension = "sh", MimeType = "text/x-shellscript", Confidence = "Medium", Reason = "text:sh-shebang", ReasonDetails = "sh:shebang" }; return true;
        }
        // Node.js shebang
        if (headLower.Contains("#!/usr/bin/env node") || headLower.Contains("#!/usr/bin/node")) { result = new ContentTypeDetectionResult { Extension = "js", MimeType = "application/javascript", Confidence = "Medium", Reason = "text:node-shebang", ReasonDetails = "js:shebang" }; return true; }
        // JavaScript heuristic (non-minified). Avoid misclassifying Lua where "local function" is common.
        if ((headLower.Contains("const ") || headLower.Contains("let ") || headLower.Contains("var ") || headLower.Contains("=>")) ||
            (headLower.Contains("function ") && !headLower.Contains("local function"))) {
            if (!(head.Length > 0 && (head[0] == (byte)'{' || head[0] == (byte)'[')))
                { result = new ContentTypeDetectionResult { Extension = "js", MimeType = "application/javascript", Confidence = "Low", Reason = "text:js-heur" }; return true; }
        }
        // Weak shell cues when no shebang
        if ((headLower.Contains("set -e") || headLower.Contains("set -u") || headLower.Contains("export ") || headLower.Contains("[[") || headLower.Contains("]]")) &&
            (headLower.Contains(" fi\n") || headLower.Contains(" esac\n") || headLower.Contains(" && ") || headLower.Contains(" case ") || headLower.Contains(" do\n"))) {
            result = new ContentTypeDetectionResult { Extension = "sh", MimeType = "text/x-shellscript", Confidence = "Low", Reason = "text:sh-heur", ReasonDetails = "sh:set|export+fi|esac|case|&&|do" }; return true;
        }

        // Windows batch (.bat/.cmd) heuristic
        if (headLower.Contains("@echo off") || headLower.Contains("setlocal") || headLower.Contains("endlocal") ||
            headLower.Contains("\ngoto ") || headLower.Contains("\r\ngoto ") || headLower.Contains(" goto ") ||
            headLower.StartsWith("rem ") || headLower.Contains("\nrem ") || headLower.Contains("\r\nrem ") || headLower.Contains(":end")) {
            var ext = declaredCmd ? "cmd" : "bat";
            result = new ContentTypeDetectionResult { Extension = ext, MimeType = "text/x-batch", Confidence = "Medium", Reason = ext == "cmd" ? "text:cmd" : "text:bat", ReasonDetails = "bat:echo|setlocal|goto|rem" };
            return true;
        }

        // Python heuristic (shebang and cues)
        if (headLower.Contains("#!/usr/bin/env python") || headLower.Contains("#!/usr/bin/python")) { result = new ContentTypeDetectionResult { Extension = "py", MimeType = "text/x-python", Confidence = "Medium", Reason = "text:py-shebang", ReasonDetails = "py:shebang" }; return true; }
        {
            int pyCues = 0;
            if (IndexOfToken(head, "import ") >= 0) pyCues++;
            if (IndexOfToken(head, "def ") >= 0 && head.IndexOf((byte)':') >= 0) pyCues++;
            if (IndexOfToken(head, "class ") >= 0 && head.IndexOf((byte)':') >= 0) pyCues++;
            if (IndexOfToken(head, "if __name__ == '__main__':") >= 0) pyCues += 2;
            if (pyCues >= 2) { result = new ContentTypeDetectionResult { Extension = "py", MimeType = "text/x-python", Confidence = "Low", Reason = "text:py-heur", ReasonDetails = $"py:cues-{pyCues}" }; return true; }
        }

        // Ruby heuristic
        if (headLower.Contains("#!/usr/bin/env ruby") || headLower.Contains("#!/usr/bin/ruby")) { result = new ContentTypeDetectionResult { Extension = "rb", MimeType = "text/x-ruby", Confidence = "Medium", Reason = "text:rb-shebang", ReasonDetails = "rb:shebang" }; return true; }
        {
            int rbCues = 0;
            if (IndexOfToken(head, "require ") >= 0) rbCues++;
            if (IndexOfToken(head, "def ") >= 0 && IndexOfToken(head, " end") >= 0) rbCues += 2;
            if (IndexOfToken(head, "class ") >= 0 && IndexOfToken(head, " end") >= 0) rbCues += 2;
            if (IndexOfToken(head, "module ") >= 0 && IndexOfToken(head, " end") >= 0) rbCues += 2;
            if (IndexOfToken(head, "puts ") >= 0) rbCues++;
            if (rbCues >= 2) { result = new ContentTypeDetectionResult { Extension = "rb", MimeType = "text/x-ruby", Confidence = "Low", Reason = "text:rb-heur", ReasonDetails = $"rb:cues-{rbCues}" }; return true; }
        }

        // Lua heuristic (placed after JS guard that ignores "local function" cases)
        if (headLower.Contains("#!/usr/bin/env lua") || headLower.Contains("#!/usr/bin/lua")) { result = new ContentTypeDetectionResult { Extension = "lua", MimeType = "text/x-lua", Confidence = "Medium", Reason = "text:lua-shebang", ReasonDetails = "lua:shebang" }; return true; }
        {
            int luaCues = 0;
            if (IndexOfToken(head, "local function ") >= 0) luaCues += 2;
            if (IndexOfToken(head, "function ") >= 0 && IndexOfToken(head, " end") >= 0) luaCues += 2;
            if (IndexOfToken(head, "require(") >= 0 || IndexOfToken(head, "require ") >= 0) luaCues++;
            if (IndexOfToken(head, " then") >= 0 && IndexOfToken(head, " end") >= 0) luaCues++;
            if (luaCues >= 2) { result = new ContentTypeDetectionResult { Extension = "lua", MimeType = "text/x-lua", Confidence = "Low", Reason = "text:lua-heur", ReasonDetails = $"lua:cues-{luaCues}" }; return true; }
        }

        // Fallback: treat as plain text if mostly printable. Include BOM charset when known.
        int printable = 0; int sample = Math.Min(1024, data.Length);
        for (int i = 0; i < sample; i++) { byte b = data[i]; if (b == 9 || b == 10 || b == 13 || (b >= 32 && b < 127)) printable++; }
        if ((double)printable / sample > 0.95) {
            var mime = "text/plain";
            if (!string.IsNullOrEmpty(bomCharset)) mime += "; charset=" + bomCharset;
            result = new ContentTypeDetectionResult { Extension = "txt", MimeType = mime, Confidence = "Low", Reason = string.IsNullOrEmpty(bomCharset) ? "text:plain" : "bom:text-plain" };
            return true;
        }
        return false;

        static int Count(ReadOnlySpan<byte> l, byte ch) { int c = 0; for (int i = 0; i < l.Length; i++) if (l[i] == ch) c++; return c; }
        static bool IsDigit(byte b) => b >= (byte)'0' && b <= (byte)'9';
        static ReadOnlySpan<byte> TrimBytes(ReadOnlySpan<byte> s) {
            int a = 0; int b = s.Length - 1;
            while (a <= b && (s[a] == (byte)' ' || s[a] == (byte)'\t' || s[a] == (byte)'\r')) a++;
            while (b >= a && (s[b] == (byte)' ' || s[b] == (byte)'\t' || s[b] == (byte)'\r')) b--;
            return a <= b ? s.Slice(a, b - a + 1) : ReadOnlySpan<byte>.Empty;
        }
        static bool LooksIniSectionLine(ReadOnlySpan<byte> line)
        {
            // INI/INF sections are typically "[Section Name]" as the full (non-comment) line.
            // Avoid false positives from PowerShell type accelerators/attributes like "[int]$x" or "[ValidateSet(...)]".
            if (line.Length < 3) return false;
            int start = 0;
            while (start < line.Length && (line[start] == (byte)' ' || line[start] == (byte)'\t')) start++;
            if (start >= line.Length || line[start] != (byte)'[') return false;

            int closeRel = line.Slice(start + 1).IndexOf((byte)']');
            if (closeRel < 0) return false;
            int close = start + 1 + closeRel;
            if (close <= start + 1) return false;

            // Require the section token to be "simple": allow letters/digits/space/._- but not ()=@{} etc.
            for (int i = start + 1; i < close; i++)
            {
                byte c = line[i];
                if (c == (byte)'(' || c == (byte)')' || c == (byte)'=' || c == (byte)'@' || c == (byte)'{' || c == (byte)'}') return false;
                if (!(char.IsLetterOrDigit((char)c) || c == (byte)' ' || c == (byte)'_' || c == (byte)'-' || c == (byte)'.')) return false;
            }

            // After the closing bracket, allow only whitespace or a comment delimiter.
            int after = close + 1;
            while (after < line.Length && (line[after] == (byte)' ' || line[after] == (byte)'\t')) after++;
            if (after >= line.Length) return true;
            return line[after] == (byte)';' || line[after] == (byte)'#';
        }
        static bool HasQuotedKeyColon(ReadOnlySpan<byte> s) {
            for (int i = 0; i + 3 < s.Length; i++) {
                if (s[i] == (byte)'"') {
                    int j = i + 1; while (j < s.Length && s[j] != (byte)'"' && s[j] != (byte)'\n' && s[j] != (byte)'\r') j++;
                    if (j < s.Length && s[j] == (byte)'"') {
                        int k = j + 1; while (k < s.Length && char.IsWhiteSpace((char)s[k])) k++;
                        if (k < s.Length && s[k] == (byte)':') return true;
                    }
                }
            }
            return false;
        }
        static bool LooksYamlKeyValue(ReadOnlySpan<byte> l) {
            if (l.Length == 0) return false;
            // Ignore common log tokens
            if (StartsWithToken(l, "[INFO]") || StartsWithToken(l, "[WARN]") || StartsWithToken(l, "[ERROR]") || StartsWithToken(l, "[DEBUG]")) return false;
            if (StartsWithToken(l, "INFO:") || StartsWithToken(l, "WARN:") || StartsWithToken(l, "ERROR:") || StartsWithToken(l, "DEBUG:")) return false;
            int cpos = l.IndexOf((byte)':'); if (cpos <= 0 || cpos > Math.Min(80, l.Length - 1)) return false;
            // If there is any quote before ':', do not treat as YAML key (likely part of a quoted string)
            for (int i = 0; i < cpos; i++) { if (l[i] == (byte)'"' || l[i] == (byte)'\'') return false; }
            // Ignore URI-like key:/value
            if (cpos + 1 < l.Length && l[cpos + 1] == (byte)'/') return false;
            int p = 0; while (p < l.Length && (l[p] == (byte)' ' || l[p] == (byte)'\t' || l[p] == (byte)'-')) p++;
            if (p >= l.Length || p >= cpos) return false;
            // Require key segment without whitespace to reduce false positives like "Data being exported:"
            for (int i = p; i < cpos; i++) { if (l[i] == (byte)' ' || l[i] == (byte)'\t') return false; }
            // Start token must look like an identifier (letter or underscore)
            if (!(char.IsLetter((char)l[p]) || l[p] == (byte)'_')) return false;
            return true;
        }
        static bool StartsWithLevelToken(ReadOnlySpan<byte> l) {
            return StartsWithToken(l, "INFO") || StartsWithToken(l, "WARN") || StartsWithToken(l, "ERROR") || StartsWithToken(l, "DEBUG") || StartsWithToken(l, "TRACE") || StartsWithToken(l, "FATAL") || StartsWithToken(l, "CRITICAL") || StartsWithToken(l, "ALERT") || StartsWithToken(l, "[INFO]") || StartsWithToken(l, "[WARN]") || StartsWithToken(l, "[ERROR]") || StartsWithToken(l, "[DEBUG]") || StartsWithToken(l, "[CRITICAL]") || StartsWithToken(l, "[ALERT]");
        }
        static int IndexOfToken(ReadOnlySpan<byte> hay, string token) {
            var tb = System.Text.Encoding.ASCII.GetBytes(token);
            for (int i = 0; i + tb.Length <= hay.Length; i++) {
                bool m = true; for (int j = 0; j < tb.Length; j++) { if (char.ToLowerInvariant((char)hay[i + j]) != char.ToLowerInvariant((char)tb[j])) { m = false; break; } }
                if (m) return i;
            }
            return -1;
        }

        static bool HasVerbNounCmdlet(string s)
        {
            // quick token scan to avoid regex
            var separators = new[] { ' ', '\t', '\r', '\n', ';', '(', '{' };
            foreach (var part in s.Split(separators, StringSplitOptions.RemoveEmptyEntries))
            {
                int dash = part.IndexOf('-');
                if (dash <= 1 || dash >= part.Length - 1) continue;
                char a = part[0];
                if (!char.IsUpper(a)) continue;
                if (!char.IsLetter(part[dash + 1])) continue;
                return true;
            }
            return false;
        }
    }

    internal static bool TryMatchMsg(string path, out ContentTypeDetectionResult? result) {
        result = null;
        try {
            using var fs = File.OpenRead(path);
            var header = new byte[8];
            if (fs.Read(header, 0, 8) != 8) return false;
            byte[] ole = new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
            for (int i = 0; i < 8; i++) if (header[i] != ole[i]) return false;
            var buf = new byte[64 * 1024];
            fs.Seek(0, SeekOrigin.Begin);
            int read = fs.Read(buf, 0, buf.Length);
            var span = new ReadOnlySpan<byte>(buf, 0, read);
            if (span.IndexOf("__substg1.0_"u8) >= 0 || span.IndexOf("__properties_version1.0"u8) >= 0) {
                result = new ContentTypeDetectionResult { Extension = "msg", MimeType = "application/vnd.ms-outlook", Confidence = "Medium", Reason = "msg:ole" };
                return true;
            }
        } catch { }
        return false;
    }
}
