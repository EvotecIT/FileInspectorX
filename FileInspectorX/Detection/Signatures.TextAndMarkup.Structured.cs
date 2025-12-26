namespace FileInspectorX;

internal static partial class Signatures
{
    private static bool TryDetectStructuredText(in TextContext ctx, out ContentTypeDetectionResult? result)
    {
        result = null;
        var head = ctx.Head;
        var headStr = ctx.HeadStr;
        var headLower = ctx.HeadLower;
        bool declaredIni = ctx.DeclaredIni;
        bool declaredInf = ctx.DeclaredInf;
        bool declaredToml = ctx.DeclaredToml;
        bool declaredAdmx = ctx.DeclaredAdmx;
        bool declaredAdml = ctx.DeclaredAdml;

        // NDJSON / JSON Lines (require at least two JSON-looking lines). Must come before single-object JSON check.
        {
            int ln1 = head.IndexOf((byte)'\n'); if (ln1 < 0) ln1 = head.Length;
            var l1 = TrimBytes(head.Slice(0, ln1));
            var rem = head.Slice(Math.Min(ln1 + 1, head.Length));
            int ln2 = rem.IndexOf((byte)'\n'); if (ln2 < 0) ln2 = rem.Length;
            var l2 = TrimBytes(rem.Slice(0, ln2));
            static bool LooksJsonLine(ReadOnlySpan<byte> l)
            {
                if (l.Length < 2) return false;
                int i = 0; while (i < l.Length && (l[i] == (byte)' ' || l[i] == (byte)'\t')) i++;
                if (i >= l.Length || l[i] != (byte)'{') return false;
                int q = l.IndexOf((byte)'"'); if (q < 0) return false;
                int colon = l.IndexOf((byte)':'); if (colon < 0) return false;
                int end = l.LastIndexOf((byte)'}'); if (end < 0) return false;
                // light structure check: braces balanced (depth==0), at least one colon outside quotes
                int depth = 0; bool inQ = false; bool colonOut = false;
                for (int k = 0; k < l.Length; k++)
                {
                    byte c = l[k];
                    if (c == (byte)'"') { inQ = !inQ; }
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
            bool j1 = LooksJsonLine(l1); bool j2 = LooksJsonLine(l2);
            if (j1 && j2)
            {
                // Confidence: Medium if a third line also looks like JSON; Low otherwise
                var rem2 = rem.Slice(Math.Min(ln2 + 1, rem.Length));
                int ln3 = rem2.IndexOf((byte)'\n'); if (ln3 < 0) ln3 = rem2.Length;
                var l3 = TrimBytes(rem2.Slice(0, ln3));
                string conf = LooksJsonLine(l3) ? "Medium" : "Low";
                result = new ContentTypeDetectionResult { Extension = "ndjson", MimeType = "application/x-ndjson", Confidence = conf, Reason = "text:ndjson" };
                return true;
            }
        }

        // JSON (tighter heuristics)
        if (head.Length > 0 && (head[0] == (byte)'{' || head[0] == (byte)'['))
        {
            int jln1 = head.IndexOf((byte)'\n'); if (jln1 < 0) jln1 = head.Length;
            var jsonLine1 = TrimBytes(head.Slice(0, jln1));
            bool jsonLooksLikeLog = LooksLikeTimestamp(jsonLine1) || StartsWithLevelToken(jsonLine1);
            if (!jsonLooksLikeLog)
            {
                int len = Math.Min(JSON_DETECTION_SCAN_LIMIT, head.Length);
                var slice = head.Slice(0, len);
                bool looksObject = slice[0] == (byte)'{';
                bool looksArray = slice[0] == (byte)'[';

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
                            result = new ContentTypeDetectionResult { Extension = "json", MimeType = "application/json", Confidence = hasObjectItem ? "Medium" : "Low", Reason = "text:json", ReasonDetails = hasObjectItem ? "json:array-of-objects" : "json:array-of-primitives" };
                            return true;
                        }
                    }
                }

                if (looksObject)
                {
                    bool hasQuotedColon = HasQuotedKeyColon(slice);
                    bool hasClose = slice.IndexOf((byte)'}') >= 0;
                    if (hasQuotedColon && hasClose)
                    {
                        result = new ContentTypeDetectionResult { Extension = "json", MimeType = "application/json", Confidence = "Medium", Reason = "text:json", ReasonDetails = "json:object-key-colon" };
                        return true;
                    }
                }
            }
        }

        // XML / HTML
        if (head.Length >= 5 && head[0] == (byte)'<')
        {
            var root = TryGetXmlRootName(headStr);
            if (root != null && root.Length > 0)
            {
                var rootLower = root.ToLowerInvariant();
                int colon = rootLower.IndexOf(':');
                if (colon >= 0 && colon < rootLower.Length - 1)
                    rootLower = rootLower.Substring(colon + 1);
                if (rootLower == "policydefinitions")
                {
                    int admxCues = CountAdmxCues(headLower, out bool admxStrong);
                    bool admxHigh = admxStrong || declaredAdmx || admxCues >= 5;
                    string details = admxStrong ? "xml:policydefinitions+strong" :
                        (admxCues >= 3 ? $"xml:policydefinitions+cues-{admxCues}" :
                        (declaredAdmx ? "xml:policydefinitions+decl" : "xml:policydefinitions"));
                    result = new ContentTypeDetectionResult { Extension = "admx", MimeType = "application/xml", Confidence = admxHigh ? "High" : "Medium", Reason = "text:admx", ReasonDetails = details };
                    return true;
                }
                if (rootLower == "policydefinitionresources")
                {
                    int admlCues = CountAdmlCues(headLower, out bool admlStrong);
                    bool admlHigh = admlStrong || declaredAdml || admlCues >= 4;
                    string details = admlStrong ? "xml:policydefinitionresources+strong" :
                        (admlCues >= 3 ? $"xml:policydefinitionresources+cues-{admlCues}" :
                        (declaredAdml ? "xml:policydefinitionresources+decl" : "xml:policydefinitionresources"));
                    result = new ContentTypeDetectionResult { Extension = "adml", MimeType = "application/xml", Confidence = admlHigh ? "High" : "Medium", Reason = "text:adml", ReasonDetails = details };
                    return true;
                }
            }
            if (head.Length >= 5 && head.Slice(0, 5).SequenceEqual("<?xml"u8))
            {
                var ext = declaredAdmx ? "admx" : (declaredAdml ? "adml" : "xml");
                result = new ContentTypeDetectionResult { Extension = ext, MimeType = "application/xml", Confidence = "Medium", Reason = "text:xml", ReasonDetails = ext == "xml" ? null : $"xml:decl-{ext}" };
                return true;
            }
            if (head.IndexOf("<!DOCTYPE html"u8) >= 0 || head.IndexOf("<html"u8) >= 0)
            {
                result = new ContentTypeDetectionResult { Extension = "html", MimeType = "text/html", Confidence = "Medium", Reason = "text:html" };
                return true;
            }
        }

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
        // Do not classify as YAML if strong PowerShell cues are present unless YAML structure is strong.
        {
            CountYamlStructure(head, 8, out int yamlKeys, out int yamlLists);
            bool yamlStrong = yamlKeys >= 2 || (yamlKeys >= 1 && yamlLists >= 1) || yamlLists >= 3;
            bool allowYaml = yamlStrong || !HasPowerShellCues(head, headStr, headLower);
            bool yamlFrontHasStructure = yamlKeys > 0 || yamlLists > 0;
            bool winLogLike = IndexOfToken(head, "Log Name:") >= 0 || IndexOfToken(head, "Event ID:") >= 0 || IndexOfToken(head, "Source:") >= 0 || IndexOfToken(head, "Task Category:") >= 0 || IndexOfToken(head, "Level:") >= 0;

            if (head.Length >= 3 && head[0] == (byte)'-' && head[1] == (byte)'-' && head[2] == (byte)'-')
            {
                if (allowYaml && !winLogLike && yamlFrontHasStructure)
                {
                    result = new ContentTypeDetectionResult { Extension = "yml", MimeType = "application/x-yaml", Confidence = "Low", Reason = "text:yaml", ReasonDetails = "yaml:front-matter" };
                    return true;
                }
            }
            else if ((yamlKeys >= 2 || yamlLists >= 2) && allowYaml && !winLogLike)
            {
                var details = yamlKeys >= 1 ? $"yaml:key-lines={yamlKeys}" : $"yaml:list-lines={yamlLists}";
                result = new ContentTypeDetectionResult { Extension = "yml", MimeType = "application/x-yaml", Confidence = "Low", Reason = "text:yaml-keys", ReasonDetails = details };
                return true;
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
                bool hasIniStyleComments = false; // strong INI/INF signal when not declared TOML
                int scanned = 0; int startLine2 = 0;
                for (int i = 0; i < head.Length && scanned < 20; i++)
                {
                    if (head[i] == (byte)'\n')
                    {
                        var raw = head.Slice(startLine2, i - startLine2);
                        var line = TrimBytes(raw);
                        if (line.Length > 0 && line[0] == (byte)'#') { scanned++; startLine2 = i + 1; continue; } // TOML comment
                        if (line.Length > 0 && line[0] == (byte)';') { hasIniStyleComments = true; scanned++; startLine2 = i + 1; continue; } // INI/INF-style comment
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
                            bool ok = true; int dots = 0;
                            for (int k = 0; k < eq; k++)
                            {
                                byte c = line[k];
                                if (!(char.IsLetterOrDigit((char)c) || c == (byte)'_' || c == (byte)'.')) { ok = false; break; }
                                if (c == (byte)'.') dots++;
                            }
                            if (ok) { dotted += dots > 0 ? 1 : 0; keys++; }
                        }
                        scanned++; startLine2 = i + 1;
                    }
                }
                bool tomlStrong = hasArrayTables || dotted >= 1;
                bool allowUndeclared = tomlStrong && !hasIniStyleComments;
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
            if ((hasFrom && hasSubj) || (hasMimeVer && hasContentType))
            {
                result = new ContentTypeDetectionResult { Extension = "eml", MimeType = "message/rfc822", Confidence = "Low", Reason = "text:eml" };
                return true;
            }
        }

        // MSG basics (very weak text fallback)
        if (head.IndexOf("__substg1.0_"u8) >= 0)
        {
            result = new ContentTypeDetectionResult { Extension = "msg", MimeType = "application/vnd.ms-outlook", Confidence = "Low", Reason = "msg:marker" };
            return true;
        }

        return false;
    }
}
