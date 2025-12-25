namespace FileInspectorX;

/// <summary>
/// Text and markup format detection (JSON, XML/HTML, YAML, EML, CSV/TSV/INI/LOG) and Outlook MSG hints.
/// </summary>
internal static partial class Signatures {
    private const int BINARY_SCAN_LIMIT = 2048; // 2 KB: doubled from 1024 to reduce UTF-16 false negatives
    private const int HEADER_BYTES = 4096; // align with default Settings.HeaderReadBytes for deeper text heuristics
    // see FileInspectorX.Settings for configurable thresholds

internal static bool TryMatchText(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result, string? declaredExtension = null) {
        result = null;
        if (src.Length == 0) return false;

        // Note: we may transcode UTF-16/UTF-32 text to UTF-8 bytes for downstream heuristics.
        // Keep the original BOM charset for MIME/Reason hints.
        ReadOnlySpan<byte> data = src;

        // BOMs: record and continue refining instead of early-returning as plain text.
        // This allows CSV/TSV/JSON/XML detection to work on UTF-8/UTF-16 files exported with BOMs.
        int bomSkip = 0;
        string? bomCharset = null;
        string? textCharset = null;
        bool bomDetected = false;
        if (src.Length >= 3 && src[0] == 0xEF && src[1] == 0xBB && src[2] == 0xBF) { bomSkip = 3; bomCharset = "utf-8"; }
        else if (src.Length >= 4 && src[0] == 0xFF && src[1] == 0xFE && src[2] == 0x00 && src[3] == 0x00) { bomSkip = 4; bomCharset = "utf-32le"; }
        else if (src.Length >= 4 && src[0] == 0x00 && src[1] == 0x00 && src[2] == 0xFE && src[3] == 0xFF) { bomSkip = 4; bomCharset = "utf-32be"; }
        else if (src.Length >= 2 && src[0] == 0xFF && src[1] == 0xFE) { bomSkip = 2; bomCharset = "utf-16le"; }
        else if (src.Length >= 2 && src[0] == 0xFE && src[1] == 0xFF) { bomSkip = 2; bomCharset = "utf-16be"; }
        if (bomCharset != null)
        {
            textCharset = bomCharset;
            bomDetected = true;
        }

        // Try to detect UTF-16/UTF-32 without BOM when NULs are present; otherwise treat as binary.
        System.Text.Encoding? transcodeEnc = null;
        int transcodeBytesPerChar = 0;
        if (bomCharset == null)
        {
            int scan = Math.Min(BINARY_SCAN_LIMIT, data.Length);
            int nulTotal = 0;
            int nulEven = 0;
            int nulOdd = 0;
            int[] nulPos4 = new int[4];
            int[] nonNullPos4 = new int[4];
            for (int i = 0; i < scan; i++)
            {
                byte b = data[i];
                if (b == 0x00)
                {
                    nulTotal++;
                    if ((i & 1) == 0) nulEven++; else nulOdd++;
                    nulPos4[i & 3]++;
                }
                else
                {
                    nonNullPos4[i & 3]++;
                }
            }
            if (nulTotal > 0)
            {
                double nulRatio = (double)nulTotal / Math.Max(1, scan);
                if (nulRatio >= 0.2)
                {
                    if (nulOdd > nulEven * 4)
                    {
                        transcodeEnc = System.Text.Encoding.Unicode;
                        transcodeBytesPerChar = 2;
                        textCharset = "utf-16le";
                    }
                    else if (nulEven > nulOdd * 4)
                    {
                        transcodeEnc = System.Text.Encoding.BigEndianUnicode;
                        transcodeBytesPerChar = 2;
                        textCharset = "utf-16be";
                    }
                    else if (nulRatio >= 0.6)
                    {
                        int nonNullTotal = nonNullPos4[0] + nonNullPos4[1] + nonNullPos4[2] + nonNullPos4[3];
                        int maxPos = 0;
                        for (int i = 1; i < 4; i++) if (nonNullPos4[i] > nonNullPos4[maxPos]) maxPos = i;
                        if (nonNullTotal > 0 && nonNullPos4[maxPos] >= (int)(nonNullTotal * 0.7))
                        {
                            if (maxPos == 0)
                            {
                                transcodeEnc = new System.Text.UTF32Encoding(false, true);
                                transcodeBytesPerChar = 4;
                                textCharset = "utf-32le";
                            }
                            else if (maxPos == 3)
                            {
                                transcodeEnc = new System.Text.UTF32Encoding(true, true);
                                transcodeBytesPerChar = 4;
                                textCharset = "utf-32be";
                            }
                        }
                    }
                }
                if (transcodeEnc == null && bomCharset == null)
                    return false;
            }
        }

        // UTF-16/UTF-32 text contains NUL bytes. Transcode to UTF-8 bytes so the existing heuristics work.
        if (bomCharset == "utf-16le" || bomCharset == "utf-16be" || bomCharset == "utf-32le" || bomCharset == "utf-32be" || transcodeEnc != null)
        {
            try
            {
                System.Text.Encoding enc;
                int bytesPerChar;
                if (bomCharset == "utf-16le") { enc = System.Text.Encoding.Unicode; bytesPerChar = 2; }
                else if (bomCharset == "utf-16be") { enc = System.Text.Encoding.BigEndianUnicode; bytesPerChar = 2; }
                else if (bomCharset == "utf-32le") { enc = new System.Text.UTF32Encoding(false, true); bytesPerChar = 4; }
                else if (bomCharset == "utf-32be") { enc = new System.Text.UTF32Encoding(true, true); bytesPerChar = 4; }
                else { enc = transcodeEnc!; bytesPerChar = transcodeBytesPerChar; }

                int decodeBudget = HEADER_BYTES * bytesPerChar;
                int remaining = src.Length - bomSkip;
                int maxBytes = Math.Min(remaining, decodeBudget);
                if (maxBytes <= bytesPerChar) return false;
                int mod = maxBytes % bytesPerChar;
                if (mod != 0) maxBytes -= mod;

                var rented = ArrayPool<byte>.Shared.Rent(maxBytes);
                try
                {
                    src.Slice(bomSkip, maxBytes).CopyTo(rented);
                    data = System.Text.Encoding.Convert(enc, System.Text.Encoding.UTF8, rented, 0, maxBytes);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(rented, clearArray: true);
                }
                bomSkip = 0;
            }
            catch
            {
                return false;
            }
        }

        // Binary heuristic: NUL in head implies not text (quick bail-out)
        int nulScan = Math.Min(BINARY_SCAN_LIMIT, data.Length);
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
        bool looksMarkup = head.IndexOf((byte)'<') >= 0 && head.IndexOf((byte)'>') >= 0;
        static bool LooksLikeTimestamp(ReadOnlySpan<byte> l) {
            int i = 0;
            while (i < l.Length && char.IsWhiteSpace((char)l[i])) i++;
            if (i < l.Length && l[i] == (byte)'[') {
                i++;
                while (i < l.Length && char.IsWhiteSpace((char)l[i])) i++;
            }
            if (l.Length - i < 10) return false;
            bool y = IsDigit(l[i + 0]) && IsDigit(l[i + 1]) && IsDigit(l[i + 2]) && IsDigit(l[i + 3]);
            bool sep1 = l[i + 4] == (byte)'-' || l[i + 4] == (byte)'/';
            bool m = IsDigit(l[i + 5]) && IsDigit(l[i + 6]);
            bool sep2 = l[i + 7] == (byte)'-' || l[i + 7] == (byte)'/';
            bool d = IsDigit(l[i + 8]) && IsDigit(l[i + 9]);
            return y && sep1 && m && sep2 && d;
        }
        static bool StartsWithToken(ReadOnlySpan<byte> l, string token) {
            var tb = System.Text.Encoding.ASCII.GetBytes(token);
            if (l.Length < tb.Length) return false;
            for (int i = 0; i < tb.Length; i++) if (char.ToUpperInvariant((char)l[i]) != char.ToUpperInvariant((char)tb[i])) return false;
            return true;
        }

        bool psCues = HasPowerShellCues(head, headStr, headLower) || HasVerbNounCmdlet(headStr);
        bool vbsCues = LooksLikeVbsScript(headLower);
        bool jsCues = LooksLikeJavaScript(headStr, headLower);
        bool shShebang = headLower.Contains("#!/bin/sh") || headLower.Contains("#!/usr/bin/env sh") || headLower.Contains("#!/usr/bin/env bash") || headLower.Contains("#!/bin/bash") || headLower.Contains("#!/usr/bin/env zsh") || headLower.Contains("#!/bin/zsh");
        bool batCues = headLower.Contains("@echo off") || headLower.Contains("setlocal") || headLower.Contains("endlocal") ||
                       headLower.Contains("\ngoto ") || headLower.Contains("\r\ngoto ") || headLower.Contains(" goto ") ||
                       headLower.StartsWith("rem ") || headLower.Contains("\nrem ") || headLower.Contains("\r\nrem ") || headLower.Contains(":end");
        bool scriptCues = psCues || vbsCues || jsCues || shShebang || batCues;


        // RTF (respect BOM/whitespace trimming)
        if (head.Length >= 5 && head[0] == '{' && head[1] == '\\' && head[2] == 'r' && head[3] == 't' && head[4] == 'f') { result = new ContentTypeDetectionResult { Extension = "rtf", MimeType = "application/rtf", Confidence = "Medium", Reason = "text:rtf" }; goto finalize; }

        // PEM and PGP ASCII-armored blocks are handled later with specific types (asc/crt/key/csr).

        // ASCII85 / Base85 with Adobe markers <~ ... ~>
        {
            int a = headStr.IndexOf("<~", StringComparison.Ordinal);
            int b = a >= 0 ? headStr.IndexOf("~>", a + 2, StringComparison.Ordinal) : -1;
            if (a >= 0 && b > a + 2)
            {
                result = new ContentTypeDetectionResult { Extension = "b85", MimeType = "application/base85", Confidence = "Low", Reason = "text:ascii85" };
                goto finalize;
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
                    goto finalize;
                }
            }
        }

        // Raw/Base64-heavy text (no explicit armor) — look for long runs of base64 charset
        {
            // Skip when PEM/PGP armor headers are present; those are handled later with specific types.
            if (scriptCues) { }
            else if (looksMarkup) { }
            else if (headLower.Contains("-----begin ")) { }
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
                    goto finalize;
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
                    if (!ws) { if (hx) { hex++; contigHex++; } else { other++; if (contigHex > maxContigHex) maxContigHex = contigHex; contigHex = 0; } }
                }
                if (contigHex > maxContigHex) maxContigHex = contigHex;
                if (hex >= Settings.EncodedHexMinChars && maxContigHex >= Settings.EncodedHexMinChars && hex > other * 4)
                {
                    result = new ContentTypeDetectionResult { Extension = "hex", MimeType = "text/plain", Confidence = "Low", Reason = "text:hex" };
                    goto finalize;
                }
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
                result = new ContentTypeDetectionResult { Extension = "ndjson", MimeType = "application/x-ndjson", Confidence = conf, Reason = "text:ndjson" }; goto finalize;
            }
        }

        // JSON (tighter heuristics)
        if (head.Length > 0 && (head[0] == (byte)'{' || head[0] == (byte)'[')) {
            int jln1 = head.IndexOf((byte)'\n'); if (jln1 < 0) jln1 = head.Length;
            var jsonLine1 = TrimBytes(head.Slice(0, jln1));
            bool jsonLooksLikeLog = LooksLikeTimestamp(jsonLine1) || StartsWithLevelToken(jsonLine1);
            if (jsonLooksLikeLog) { }
            else {
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
                        result = new ContentTypeDetectionResult { Extension = "json", MimeType = "application/json", Confidence = hasObjectItem ? "Medium" : "Low", Reason = "text:json", ReasonDetails = hasObjectItem ? "json:array-of-objects" : "json:array-of-primitives" }; goto finalize;
                    }
                }
            }

            if (looksObject) {
                bool hasQuotedColon = HasQuotedKeyColon(slice);
                bool hasClose = slice.IndexOf((byte)'}') >= 0;
                if (hasQuotedColon && hasClose) { result = new ContentTypeDetectionResult { Extension = "json", MimeType = "application/json", Confidence = "Medium", Reason = "text:json", ReasonDetails = "json:object-key-colon" }; goto finalize; }
            }
            }
        }
        // XML / HTML
        if (head.Length >= 5 && head[0] == (byte)'<') {
            var root = TryGetXmlRootName(headStr);
            if (root != null && root.Length > 0)
            {
                var rootLower = root.ToLowerInvariant();
                int colon = rootLower.IndexOf(':');
                if (colon >= 0 && colon < rootLower.Length - 1)
                    rootLower = rootLower.Substring(colon + 1);
                if (rootLower == "policydefinitions")
                {
                    bool admxCues = LooksLikeAdmxXml(headLower);
                    bool admxStrong = admxCues || declaredAdmx;
                    var details = admxCues ? "xml:policydefinitions+schema" : (declaredAdmx ? "xml:policydefinitions+decl" : "xml:policydefinitions");
                    result = new ContentTypeDetectionResult { Extension = "admx", MimeType = "application/xml", Confidence = admxStrong ? "High" : "Medium", Reason = "text:admx", ReasonDetails = details };
                    goto finalize;
                }
                if (rootLower == "policydefinitionresources")
                {
                    bool admlCues = LooksLikeAdmlXml(headLower);
                    bool admlStrong = admlCues || declaredAdml;
                    var details = admlCues ? "xml:policydefinitionresources+schema" : (declaredAdml ? "xml:policydefinitionresources+decl" : "xml:policydefinitionresources");
                    result = new ContentTypeDetectionResult { Extension = "adml", MimeType = "application/xml", Confidence = admlStrong ? "High" : "Medium", Reason = "text:adml", ReasonDetails = details };
                    goto finalize;
                }
            }
            if (head.Length >= 5 && head.Slice(0, 5).SequenceEqual("<?xml"u8)) {
                var ext = declaredAdmx ? "admx" : (declaredAdml ? "adml" : "xml");
                result = new ContentTypeDetectionResult { Extension = ext, MimeType = "application/xml", Confidence = "Medium", Reason = "text:xml", ReasonDetails = ext == "xml" ? null : $"xml:decl-{ext}" };
                goto finalize;
            }
            if (head.IndexOf("<!DOCTYPE html"u8) >= 0 || head.IndexOf("<html"u8) >= 0) { result = new ContentTypeDetectionResult { Extension = "html", MimeType = "text/html", Confidence = "Medium", Reason = "text:html" }; goto finalize; }
        }

        // (moved NDJSON block earlier)

        // Quick PGP ASCII-armored blocks (place before YAML '---' to avoid front-matter collision)
        {
            if (headLower.Contains("-----begin pgp message-----")) { result = new ContentTypeDetectionResult { Extension = "asc", MimeType = "application/pgp-encrypted", Confidence = "Medium", Reason = "text:pgp-message" }; goto finalize; }
            if (headLower.Contains("-----begin pgp public key block-----")) { result = new ContentTypeDetectionResult { Extension = "asc", MimeType = "application/pgp-keys", Confidence = "Medium", Reason = "text:pgp-public-key" }; goto finalize; }
            if (headLower.Contains("-----begin pgp signature-----")) { result = new ContentTypeDetectionResult { Extension = "asc", MimeType = "application/pgp-signature", Confidence = "Medium", Reason = "text:pgp-signature" }; goto finalize; }
            if (headLower.Contains("-----begin pgp private key block-----")) { result = new ContentTypeDetectionResult { Extension = "asc", MimeType = "application/pgp-keys", Confidence = "Medium", Reason = "text:pgp-private-key" }; goto finalize; }
        }

        // PEM family (certificate / CSR / private keys) and OpenSSH key — must come before YAML
        // to avoid false positives from lines like "Proc-Type:" / "DEK-Info:".
        {
            var l = headLower;
            if (l.Contains("-----begin certificate-----")) { result = new ContentTypeDetectionResult { Extension = "crt", MimeType = "application/pkix-cert", Confidence = "Medium", Reason = "text:pem-cert" }; goto finalize; }
            if (l.Contains("-----begin x509 certificate-----") || l.Contains("-----begin trusted certificate-----")) { result = new ContentTypeDetectionResult { Extension = "crt", MimeType = "application/pkix-cert", Confidence = "Low", Reason = "text:pem-cert-variant" }; goto finalize; }
            if (l.Contains("-----begin certificate request-----") || l.Contains("-----begin new certificate request-----")) { result = new ContentTypeDetectionResult { Extension = "csr", MimeType = "application/pkcs10", Confidence = "Medium", Reason = "text:pem-csr" }; goto finalize; }
            if (l.Contains("-----begin private key-----") || l.Contains("-----begin encrypted private key-----") || l.Contains("-----begin rsa private key-----") || l.Contains("-----begin ec private key-----")) { result = new ContentTypeDetectionResult { Extension = "key", MimeType = "application/x-pem-key", Confidence = "Medium", Reason = "text:pem-key" }; goto finalize; }
            if (l.Contains("-----begin openssh private key-----")) { result = new ContentTypeDetectionResult { Extension = "key", MimeType = "application/x-openssh-key", Confidence = "Medium", Reason = "text:openssh-key" }; goto finalize; }
        }

        // YAML (document start) or refined key:value heuristics — guarded to avoid PEM/PGP collisions handled above.
        // Do not classify as YAML if strong PowerShell cues are present or if the content looks like Windows Event Viewer text export keys.
        if (head.Length >= 3 && head[0] == (byte)'-' && head[1] == (byte)'-' && head[2] == (byte)'-') {
            if (!HasPowerShellCues(head, headStr, headLower)) {
                var winLogLike = IndexOfToken(head, "Log Name:") >= 0 || IndexOfToken(head, "Event ID:") >= 0 || IndexOfToken(head, "Source:") >= 0 || IndexOfToken(head, "Task Category:") >= 0 || IndexOfToken(head, "Level:") >= 0;
                if (!winLogLike) { result = new ContentTypeDetectionResult { Extension = "yml", MimeType = "application/x-yaml", Confidence = "Low", Reason = "text:yaml", ReasonDetails = "yaml:front-matter" }; goto finalize; }
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
                    if (!winLogLike) { result = new ContentTypeDetectionResult { Extension = "yml", MimeType = "application/x-yaml", Confidence = "Low", Reason = "text:yaml-keys", ReasonDetails = $"yaml:key-lines={yamlish}" }; goto finalize; }
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
                            bool ok = true; int dots = 0; for (int k = 0; k < eq; k++) { byte c = line[k]; if (!(char.IsLetterOrDigit((char)c) || c == (byte)'_' || c == (byte)'.')) { ok = false; break; } if (c == (byte)'.') dots++; }
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
                    goto finalize;
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
                        goto finalize;
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
            if ((hasFrom && hasSubj) || (hasMimeVer && hasContentType)) { result = new ContentTypeDetectionResult { Extension = "eml", MimeType = "message/rfc822", Confidence = "Low", Reason = "text:eml" }; goto finalize; }
        }

        // MSG basics (very weak text fallback)
        if (head.IndexOf("__substg1.0_"u8) >= 0) { result = new ContentTypeDetectionResult { Extension = "msg", MimeType = "application/vnd.ms-outlook", Confidence = "Low", Reason = "msg:marker" }; goto finalize; }

        // Quick Windows DNS log check very early (before generic log heuristics)
        if (LogHeuristics.LooksLikeDnsLog(headLower))
        {
            result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:log-dns" };
            goto finalize;
        }

        // Delimiter heuristics shared by CSV/TSV + log detection
        var span = head;
        int nl = head.IndexOf((byte)'\n'); if (nl < 0) nl = head.Length;
        var line1 = span.Slice(0, nl);
        var rest = span.Slice(Math.Min(nl + 1, span.Length));
        int nl2 = rest.IndexOf((byte)'\n'); if (nl2 < 0) nl2 = rest.Length;
        var line2 = rest.Slice(0, nl2);

        // LOG heuristic (timestamps/levels) promoted ahead of CSV/Markdown to avoid mislabels
        bool logCues = LooksLikeTimestamp(line1) || LooksLikeTimestamp(line2) || StartsWithLevelToken(line1) || StartsWithLevelToken(line2);
        if (!scriptCues)
        {
            if (LooksLikeTimestamp(line1) && LooksLikeTimestamp(line2)) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Low", Reason = "text:log", ReasonDetails = "log:timestamps-2" }; goto finalize; }

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
                result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Low", Reason = "text:log", ReasonDetails = "log:timestamps-multi" }; goto finalize;
            }
            if (levelCount >= 2 || ((LooksLikeTimestamp(line1) || LooksLikeTimestamp(line2)) && levelCount >= 1)) {
                // Boost confidence when we have both timestamps and levels across lines
                var conf = levelCount >= 2 && (LooksLikeTimestamp(line1) || LooksLikeTimestamp(line2)) ? "Medium" : "Low";
                result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = conf, Reason = "text:log-levels", ReasonDetails = levelCount >= 2 ? $"log:levels-{levelCount}" : "log:timestamp+level" }; goto finalize;
            }
            if (levelCount > 0) logCues = true;
            if (declaredLog && logCues) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Low", Reason = "text:log", ReasonDetails = "log:declared" }; goto finalize; }
        }

        // CSV/TSV/Delimited heuristics (look at first two lines) — also handle Excel 'sep=' directive and single-line CSV/TSV
        // Excel separator directive (first non-whitespace line like `sep=,` or `sep=;` or `sep=\t`)
        {
            string s = headStr.TrimStart('\ufeff', ' ', '\t', '\r', '\n');
            if (s.StartsWith("sep=", System.StringComparison.OrdinalIgnoreCase))
            {
                if (!logCues && !scriptCues)
                {
                    bool isTab = s.StartsWith("sep=\\t", System.StringComparison.OrdinalIgnoreCase) || (s.Length > 4 && s[4] == '\t');
                    if (isTab) { result = new ContentTypeDetectionResult { Extension = "tsv", MimeType = "text/tab-separated-values", Confidence = "Low", Reason = "text:tsv", ReasonDetails = "tsv:sep-directive" }; goto finalize; }
                    else { result = new ContentTypeDetectionResult { Extension = "csv", MimeType = "text/csv", Confidence = "Low", Reason = "text:csv", ReasonDetails = "csv:sep-directive" }; goto finalize; }
                }
            }
        }

        int commas1 = Count(line1, (byte)','); int commas2 = Count(line2, (byte)',');
        int semis1 = Count(line1, (byte)';'); int semis2 = Count(line2, (byte)';');
        int pipes1 = Count(line1, (byte)'|'); int pipes2 = Count(line2, (byte)'|');
        int tabs1 = Count(line1, (byte)'\t'); int tabs2 = Count(line2, (byte)'\t');
        if (!logCues && !scriptCues) {
            if ((commas1 >= 1 && commas2 >= 1 && Math.Abs(commas1 - commas2) <= 2) || (semis1 >= 1 && semis2 >= 1 && Math.Abs(semis1 - semis2) <= 2) || (pipes1 >= 1 && pipes2 >= 1 && Math.Abs(pipes1 - pipes2) <= 2)) { result = new ContentTypeDetectionResult { Extension = "csv", MimeType = "text/csv", Confidence = "Low", Reason = "text:csv", ReasonDetails = "csv:delimiter-repeat-2lines" }; goto finalize; }
            if (tabs1 >= 1 && tabs2 >= 1 && Math.Abs(tabs1 - tabs2) <= 2) { result = new ContentTypeDetectionResult { Extension = "tsv", MimeType = "text/tab-separated-values", Confidence = "Low", Reason = "text:tsv", ReasonDetails = "tsv:tabs-2lines" }; goto finalize; }
            if (line2.Length == 0 || (line2.Length == 0 && rest.Length == 0)) {
                static int TokenCount(ReadOnlySpan<byte> l, byte sep) {
                    if (l.Length == 0) return 0;
                    int tokens = 1; for (int i = 0; i < l.Length; i++) if (l[i] == sep) tokens++; return tokens;
                }
                if (commas1 >= 2 && TokenCount(line1, (byte)',') >= 3) { result = new ContentTypeDetectionResult { Extension = "csv", MimeType = "text/csv", Confidence = "Low", Reason = "text:csv", ReasonDetails = "csv:single-line" }; goto finalize; }
                if (semis1 >= 2 && TokenCount(line1, (byte)';') >= 3) { result = new ContentTypeDetectionResult { Extension = "csv", MimeType = "text/csv", Confidence = "Low", Reason = "text:csv", ReasonDetails = "csv:single-line" }; goto finalize; }
                if (tabs1 >= 2 && TokenCount(line1, (byte)'\t') >= 3) { result = new ContentTypeDetectionResult { Extension = "tsv", MimeType = "text/tab-separated-values", Confidence = "Low", Reason = "text:tsv", ReasonDetails = "tsv:single-line" }; goto finalize; }
            }
        }

        // INI/INF heuristic (guarded against PowerShell/type-accelerator patterns)
        {
            bool hasPsCues = HasPowerShellCues(head, headStr, headLower) || HasVerbNounCmdlet(headStr);
            if (!hasPsCues && !jsCues && !shShebang && !batCues)
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
                    goto finalize;
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
                bool hasFence = sl.Contains("```");
                bool hasHeading = sl.StartsWith("# ") || sl.Contains("\n# ");
                bool mdStructural = hasFence || hasHeading;
                if (okByCues && !logCues && (!scriptCues || declaredMd || mdStructural)) { result = new ContentTypeDetectionResult { Extension = "md", MimeType = "text/markdown", Confidence = "Low", Reason = "text:md" }; goto finalize; }
            }
        }

        // PowerShell heuristic (uses cached headStr/headLower)

        // Windows well-known text logs: Firewall, Netlogon, Event Viewer text export
        if (!scriptCues)
        {
            if (LogHeuristics.LooksLikeFirewallLog(headLower)) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:log-firewall" }; goto finalize; }
            if (LogHeuristics.LooksLikeNetlogonLog(headLower, logCues)) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:log-netlogon" }; goto finalize; }
            if (LogHeuristics.LooksLikeEventViewerTextExport(headLower)) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:event-txt" }; goto finalize; }

            // Microsoft DHCP Server audit logs (similar to IIS/Firewall headers)
            if (LogHeuristics.LooksLikeDhcpLog(headLower)) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:log-dhcp" }; goto finalize; }

            // Microsoft Exchange Message Tracking logs
            if (LogHeuristics.LooksLikeExchangeMessageTrackingLog(headLower)) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:log-exchange" }; goto finalize; }

            // Windows Defender textual logs (MpCmdRun outputs or Event Viewer text exports mentioning Defender)
            if (LogHeuristics.LooksLikeDefenderTextLog(headLower, logCues)) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Low", Reason = "text:log-defender" }; goto finalize; }

            // SQL Server ERRORLOG text
            if (LogHeuristics.LooksLikeSqlErrorLog(headLower, logCues)) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:log-sql-errorlog" }; goto finalize; }

            // NPS / RADIUS (IAS/NPS) text logs
            if (LogHeuristics.LooksLikeNpsRadiusLog(headLower)) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:log-nps" }; goto finalize; }

            // SQL Server Agent logs (SQLAgent.out / text snippets)
            if (LogHeuristics.LooksLikeSqlAgentLog(headLower, logCues)) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Low", Reason = "text:log-sqlagent" }; goto finalize; }
        }

        // PEM/PGP ASCII-armored blocks (detect before script heuristics)
        {
            if (headLower.Contains("-----begin pgp public key block-----")) { result = new ContentTypeDetectionResult { Extension = "asc", MimeType = "application/pgp-keys", Confidence = "Medium", Reason = "text:pgp-public-key" }; goto finalize; }
            if (headLower.Contains("-----begin pgp private key block-----")) { result = new ContentTypeDetectionResult { Extension = "asc", MimeType = "application/pgp-keys", Confidence = "Medium", Reason = "text:pgp-private-key" }; goto finalize; }
            if (headLower.Contains("-----begin pgp message-----")) { result = new ContentTypeDetectionResult { Extension = "asc", MimeType = "application/pgp-encrypted", Confidence = "Medium", Reason = "text:pgp-message" }; goto finalize; }
            if (headLower.Contains("-----begin pgp signature-----")) { result = new ContentTypeDetectionResult { Extension = "asc", MimeType = "application/pgp-signature", Confidence = "Medium", Reason = "text:pgp-signature" }; goto finalize; }

            if (headLower.Contains("-----begin certificate request-----") || headLower.Contains("-----begin new certificate request-----")) { result = new ContentTypeDetectionResult { Extension = "csr", MimeType = "application/pkcs10", Confidence = "Medium", Reason = "text:pkcs10" }; goto finalize; }
            if (headLower.Contains("-----begin certificate-----")) { result = new ContentTypeDetectionResult { Extension = "crt", MimeType = "application/pkix-cert", Confidence = "Medium", Reason = "text:pem-cert" }; goto finalize; }
            if (headLower.Contains("-----begin public key-----")) { result = new ContentTypeDetectionResult { Extension = "pub", MimeType = "application/x-pem-key", Confidence = "Low", Reason = "text:pem-pubkey" }; goto finalize; }
            if (headLower.Contains("-----begin openssh private key-----") || headLower.Contains("openssh private key")) { result = new ContentTypeDetectionResult { Extension = "key", MimeType = "application/x-openssh-key", Confidence = "Medium", Reason = "text:openssh-key" }; goto finalize; }
            if (headLower.Contains("-----begin private key-----") || headLower.Contains("-----begin rsa private key-----") || headLower.Contains("-----begin dsa private key-----") || headLower.Contains("-----begin ec private key-----")) { result = new ContentTypeDetectionResult { Extension = "key", MimeType = "application/x-pem-key", Confidence = "Medium", Reason = "text:pem-key" }; goto finalize; }
        }
        // PowerShell heuristic — includes pwsh/powershell shebang, cmdlet verb-noun/pipeline/attribute cues, and module/data hints
        {
            if (declaredMd) { /* allow markdown with fenced PS examples */ }
            bool psShebang = headLower.Contains("#!/usr/bin/env pwsh") || headLower.Contains("#!/usr/bin/pwsh") ||
                             headLower.Contains("#!/usr/bin/env powershell") || headLower.Contains("#!/usr/bin/powershell");
            if (psShebang)
            {
                result = new ContentTypeDetectionResult { Extension = "ps1", MimeType = "text/x-powershell", Confidence = "Medium", Reason = "text:ps1-shebang", ReasonDetails = "ps1:shebang" };
                goto finalize;
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
            bool hasGetSet = headStr.IndexOf("Get-", System.StringComparison.OrdinalIgnoreCase) >= 0 || headStr.IndexOf("Set-", System.StringComparison.OrdinalIgnoreCase) >= 0;
            if (hasGetSet) cues++;
            if (hasVerbNoun) { cues++; strong++; }
            if (hasPipeline) { cues++; strong++; }

            // Module/data file special-cases
            if (declaredPsm1 && (hasModuleExport || hasVerbNoun))
            {
                result = new ContentTypeDetectionResult { Extension = "psm1", MimeType = "text/x-powershell", Confidence = "Medium", Reason = "text:psm1", ReasonDetails = "psm1:module-cues" }; goto finalize;
            }
            if (declaredPsd1 && (psd1Hashtable || hasModuleExport))
            {
                result = new ContentTypeDetectionResult { Extension = "psd1", MimeType = "text/x-powershell", Confidence = "Low", Reason = "text:psd1", ReasonDetails = psd1Hashtable ? "psd1:hashtable" : "psd1:module-keys" }; goto finalize;
            }

            if (cues >= 2 || (cues >= 1 && strong >= 1)) {
                var conf = cues >= 3 ? "Medium" : "Low";
                var details = cues >= 3 ? "ps1:multi-cues" : (strong >= 1 && cues == 1 ? "ps1:single-strong-cue" : "ps1:common-cmdlets");
                result = new ContentTypeDetectionResult { Extension = "ps1", MimeType = "text/x-powershell", Confidence = conf, Reason = "text:ps1", ReasonDetails = details }; goto finalize;
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
            if (sl.Contains("$env:")) { cues++; strong++; }
            if (sl.Contains("$psscriptroot") || sl.Contains("$pscommandpath") || sl.Contains("$pshome")) { cues++; strong++; }
            if (sl.Contains("$_")) { cues++; }
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
        if (LooksLikeVbsScript(headLower)) {
            var conf = (headLower.Contains("option explicit") || headLower.Contains("on error resume next") || headLower.Contains("createobject(") || headLower.Contains("wscript.")) ? "Medium" : "Low";
            result = new ContentTypeDetectionResult { Extension = "vbs", MimeType = "text/vbscript", Confidence = conf, Reason = "text:vbs", ReasonDetails = conf=="Medium"?"vbs:explicit+error|createobject":"vbs:wscript+dim|msgbox" }; goto finalize;
        }

        // Shell script heuristic
        if (headLower.Contains("#!/bin/sh") || headLower.Contains("#!/usr/bin/env sh") || headLower.Contains("#!/usr/bin/env bash") || headLower.Contains("#!/bin/bash") || headLower.Contains("#!/usr/bin/env zsh") || headLower.Contains("#!/bin/zsh")) {
            result = new ContentTypeDetectionResult { Extension = "sh", MimeType = "text/x-shellscript", Confidence = "Medium", Reason = "text:sh-shebang", ReasonDetails = "sh:shebang" }; goto finalize;
        }
        // Node.js shebang
        if (headLower.Contains("#!/usr/bin/env node") || headLower.Contains("#!/usr/bin/node")) { result = new ContentTypeDetectionResult { Extension = "js", MimeType = "application/javascript", Confidence = "Medium", Reason = "text:node-shebang", ReasonDetails = "js:shebang" }; goto finalize; }
        // JavaScript heuristic (non-minified). Avoid misclassifying Lua where "local function" is common.
        if (LooksLikeJavaScript(headStr, headLower)) {
            if (!(head.Length > 0 && (head[0] == (byte)'{' || head[0] == (byte)'[')))
                { result = new ContentTypeDetectionResult { Extension = "js", MimeType = "application/javascript", Confidence = "Low", Reason = "text:js-heur" }; goto finalize; }
        }
        // Weak shell cues when no shebang
        if ((headLower.Contains("set -e") || headLower.Contains("set -u") || headLower.Contains("export ") || headLower.Contains("[[") || headLower.Contains("]]")) &&
            (headLower.Contains(" fi\n") || headLower.Contains(" esac\n") || headLower.Contains(" && ") || headLower.Contains(" case ") || headLower.Contains(" do\n"))) {
            result = new ContentTypeDetectionResult { Extension = "sh", MimeType = "text/x-shellscript", Confidence = "Low", Reason = "text:sh-heur", ReasonDetails = "sh:set|export+fi|esac|case|&&|do" }; goto finalize;
        }

        // Windows batch (.bat/.cmd) heuristic
        if (headLower.Contains("@echo off") || headLower.Contains("setlocal") || headLower.Contains("endlocal") ||
            headLower.Contains("\ngoto ") || headLower.Contains("\r\ngoto ") || headLower.Contains(" goto ") ||
            headLower.StartsWith("rem ") || headLower.Contains("\nrem ") || headLower.Contains("\r\nrem ") || headLower.Contains(":end")) {
            var ext = declaredCmd ? "cmd" : "bat";
            result = new ContentTypeDetectionResult { Extension = ext, MimeType = "text/x-batch", Confidence = "Medium", Reason = ext == "cmd" ? "text:cmd" : "text:bat", ReasonDetails = "bat:echo|setlocal|goto|rem" };
            goto finalize;
        }

        // Python heuristic (shebang and cues)
        if (headLower.Contains("#!/usr/bin/env python") || headLower.Contains("#!/usr/bin/python")) { result = new ContentTypeDetectionResult { Extension = "py", MimeType = "text/x-python", Confidence = "Medium", Reason = "text:py-shebang", ReasonDetails = "py:shebang" }; goto finalize; }
        {
            int pyCues = 0;
            if (IndexOfToken(head, "import ") >= 0) pyCues++;
            if (IndexOfToken(head, "def ") >= 0 && head.IndexOf((byte)':') >= 0) pyCues++;
            if (IndexOfToken(head, "class ") >= 0 && head.IndexOf((byte)':') >= 0) pyCues++;
            if (IndexOfToken(head, "if __name__ == '__main__':") >= 0) pyCues += 2;
            if (pyCues >= 2) { result = new ContentTypeDetectionResult { Extension = "py", MimeType = "text/x-python", Confidence = "Low", Reason = "text:py-heur", ReasonDetails = $"py:cues-{pyCues}" }; goto finalize; }
        }

        // Ruby heuristic
        if (headLower.Contains("#!/usr/bin/env ruby") || headLower.Contains("#!/usr/bin/ruby")) { result = new ContentTypeDetectionResult { Extension = "rb", MimeType = "text/x-ruby", Confidence = "Medium", Reason = "text:rb-shebang", ReasonDetails = "rb:shebang" }; goto finalize; }
        {
            int rbCues = 0;
            if (IndexOfToken(head, "require ") >= 0) rbCues++;
            if (IndexOfToken(head, "def ") >= 0 && IndexOfToken(head, " end") >= 0) rbCues += 2;
            if (IndexOfToken(head, "class ") >= 0 && IndexOfToken(head, " end") >= 0) rbCues += 2;
            if (IndexOfToken(head, "module ") >= 0 && IndexOfToken(head, " end") >= 0) rbCues += 2;
            if (IndexOfToken(head, "puts ") >= 0) rbCues++;
            if (rbCues >= 2) { result = new ContentTypeDetectionResult { Extension = "rb", MimeType = "text/x-ruby", Confidence = "Low", Reason = "text:rb-heur", ReasonDetails = $"rb:cues-{rbCues}" }; goto finalize; }
        }

        // Lua heuristic (placed after JS guard that ignores "local function" cases)
        if (headLower.Contains("#!/usr/bin/env lua") || headLower.Contains("#!/usr/bin/lua")) { result = new ContentTypeDetectionResult { Extension = "lua", MimeType = "text/x-lua", Confidence = "Medium", Reason = "text:lua-shebang", ReasonDetails = "lua:shebang" }; goto finalize; }
        {
            int luaCues = 0;
            if (IndexOfToken(head, "local function ") >= 0) luaCues += 2;
            if (IndexOfToken(head, "function ") >= 0 && IndexOfToken(head, " end") >= 0) luaCues += 2;
            if (IndexOfToken(head, "require(") >= 0 || IndexOfToken(head, "require ") >= 0) luaCues++;
            if (IndexOfToken(head, " then") >= 0 && IndexOfToken(head, " end") >= 0) luaCues++;
            if (luaCues >= 2) { result = new ContentTypeDetectionResult { Extension = "lua", MimeType = "text/x-lua", Confidence = "Low", Reason = "text:lua-heur", ReasonDetails = $"lua:cues-{luaCues}" }; goto finalize; }
        }

        // Fallback: treat as plain text if mostly printable. Include BOM charset when known.
        int printable = 0; int sample = Math.Min(1024, data.Length);
        for (int i = 0; i < sample; i++) { byte b = data[i]; if (b == 9 || b == 10 || b == 13 || (b >= 32 && b < 127)) printable++; }
        if ((double)printable / sample > 0.95) {
            var mime = "text/plain";
            if (!string.IsNullOrEmpty(textCharset)) mime += "; charset=" + textCharset;
            var reason = bomDetected ? "bom:text-plain" : "text:plain";
            result = new ContentTypeDetectionResult { Extension = "txt", MimeType = mime, Confidence = "Low", Reason = reason };
            goto finalize;
        }
        goto finalize;

        finalize:
        if (result != null)
        {
            result = AttachAlternatives(result, head, headStr, headLower, decl);
            return true;
        }
        return false;

        static ContentTypeDetectionResult AttachAlternatives(ContentTypeDetectionResult det, ReadOnlySpan<byte> head, string headStr, string headLower, string decl)
        {
            if (!det.Score.HasValue) det.Score = ScoreFromConfidence(det.Confidence);
            if (!IsAltEligibleExtension(det.Extension))
            {
                det.IsDangerous = DangerousExtensions.IsDangerous(det.Extension);
                return det;
            }

            var all = CollectCandidates(head, headStr, headLower, decl);
            if (all.Count == 0) return det;

            var primaryExt = det.Extension ?? string.Empty;
            ContentTypeDetectionCandidate? primary = null;
            if (!string.IsNullOrWhiteSpace(primaryExt))
            {
                foreach (var c in all)
                {
                    if (string.Equals(c.Extension, primaryExt, StringComparison.OrdinalIgnoreCase))
                    {
                        primary = c;
                        break;
                    }
                }
            }
            ContentTypeDetectionCandidate? declaredCandidate = null;
            if (!string.IsNullOrWhiteSpace(decl))
            {
                foreach (var c in all)
                {
                    if (string.Equals(c.Extension, decl, StringComparison.OrdinalIgnoreCase))
                    {
                        declaredCandidate = c;
                        break;
                    }
                }
            }
            ContentTypeDetectionCandidate? best = null;
            foreach (var c in all)
            {
                if (best == null || c.Score > best.Score) best = c;
            }
            if (primary != null)
            {
                det.Score = primary.Score;
                det.IsDangerous = primary.IsDangerous;
                bool allowUpgrade = det.Reason == null ||
                                    (!det.Reason.Contains("malformed", StringComparison.OrdinalIgnoreCase) &&
                                     !det.Reason.Contains("validation-error", StringComparison.OrdinalIgnoreCase));
                if (allowUpgrade && ConfidenceRank(primary.Confidence) > ConfidenceRank(det.Confidence))
                    det.Confidence = primary.Confidence;
            }
            else
            {
                det.IsDangerous = DangerousExtensions.IsDangerous(det.Extension);
            }

            int scoreMargin = Math.Max(0, Settings.DetectionPrimaryScoreMargin);
            int tieMargin = Math.Max(0, Settings.DetectionDeclaredTieBreakerMargin);
            bool allowReplace = det.Reason == null ||
                                (!det.Reason.Contains("malformed", StringComparison.OrdinalIgnoreCase) &&
                                 !det.Reason.Contains("validation-error", StringComparison.OrdinalIgnoreCase));
            bool replaced = false;
            if (allowReplace && primary != null && best != null &&
                !string.Equals(best.Extension, primaryExt, StringComparison.OrdinalIgnoreCase) &&
                best.Score >= primary.Score + scoreMargin)
            {
                ApplyPrimaryCandidate(best, "primary:score");
                primaryExt = best.Extension;
                primary = best;
                replaced = true;
            }
            if (!replaced && declaredCandidate != null &&
                !string.Equals(declaredCandidate.Extension, primaryExt, StringComparison.OrdinalIgnoreCase))
            {
                int topScore = best?.Score ?? primary?.Score ?? det.Score ?? 0;
                if (topScore - declaredCandidate.Score <= tieMargin)
                {
                    ApplyPrimaryCandidate(declaredCandidate, "primary:declared");
                    primaryExt = declaredCandidate.Extension;
                    primary = declaredCandidate;
                }
            }

            var alternatives = new List<ContentTypeDetectionCandidate>();
            foreach (var c in all)
            {
                if (!string.Equals(c.Extension, primaryExt, StringComparison.OrdinalIgnoreCase))
                    alternatives.Add(c);
            }
            if (alternatives.Count > 0)
            {
                alternatives.Sort((a, b) => b.Score.CompareTo(a.Score));
                int maxAlt = Math.Max(0, Settings.DetectionMaxAlternatives);
                if (maxAlt == 0) alternatives.Clear();
                else if (alternatives.Count > maxAlt) alternatives.RemoveRange(maxAlt, alternatives.Count - maxAlt);
                if (alternatives.Count > 0) det.Alternatives = alternatives;
            }
            if (Settings.DetectionLogCandidates)
            {
                var sb = new System.Text.StringBuilder();
                sb.Append("detect:text primary=").Append(det.Extension)
                  .Append(" score=").Append(det.Score ?? 0)
                  .Append(" conf=").Append(det.Confidence ?? string.Empty);
                if (det.Alternatives != null && det.Alternatives.Count > 0)
                {
                    sb.Append(" alts=[");
                    for (int i = 0; i < det.Alternatives.Count; i++)
                    {
                        var a = det.Alternatives[i];
                        if (i > 0) sb.Append(", ");
                        sb.Append(a.Extension).Append(":").Append(a.Score);
                    }
                    sb.Append(']');
                }
                Settings.Logger.WriteDebug(sb.ToString());
            }
            return det;

            void ApplyPrimaryCandidate(ContentTypeDetectionCandidate candidate, string tag)
            {
                det.Extension = candidate.Extension;
                det.MimeType = candidate.MimeType;
                det.Confidence = candidate.Confidence;
                det.Reason = AppendReason(candidate.Reason, tag);
                det.ReasonDetails = candidate.ReasonDetails;
                det.Score = candidate.Score;
                det.IsDangerous = candidate.IsDangerous;
            }

            static string AppendReason(string? reason, string tag)
                => string.IsNullOrEmpty(reason) ? tag : (reason + ";" + tag);
        }

        static List<ContentTypeDetectionCandidate> CollectCandidates(ReadOnlySpan<byte> head, string headStr, string headLower, string decl)
        {
            var byExt = new Dictionary<string, ContentTypeDetectionCandidate>(StringComparer.OrdinalIgnoreCase);
            void AddCandidate(string ext, string mime, string confidence, string reason, string? details = null, int scoreAdjust = 0, bool? dangerousOverride = null)
            {
                if (string.IsNullOrWhiteSpace(ext)) return;
                int adjust = scoreAdjust + GetScoreAdjustment(ext, reason, details);
                if (!string.IsNullOrWhiteSpace(decl) && string.Equals(ext, decl, StringComparison.OrdinalIgnoreCase))
                    adjust += 3;
                int score = ClampScore(ScoreFromConfidence(confidence) + adjust, confidence);
                bool dangerous = dangerousOverride ?? DangerousExtensions.IsDangerous(ext);
                var c = new ContentTypeDetectionCandidate { Extension = ext, MimeType = mime, Confidence = confidence, Reason = reason, ReasonDetails = details, Score = score, IsDangerous = dangerous };
                if (byExt.TryGetValue(ext, out var existing))
                {
                    if (c.Score > existing.Score) byExt[ext] = c;
                }
                else
                {
                    byExt.Add(ext, c);
                }
            }

            static bool ContainsToken(string text, string token)
            {
                if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(token)) return false;
                int idx = 0;
                while ((idx = text.IndexOf(token, idx, StringComparison.OrdinalIgnoreCase)) >= 0)
                {
                    bool leftOk = idx == 0 || !char.IsLetterOrDigit(text[idx - 1]);
                    int end = idx + token.Length;
                    bool rightOk = end >= text.Length || !char.IsLetterOrDigit(text[end]);
                    if (leftOk && rightOk) return true;
                    idx = end;
                }
                return false;
            }

            bool declaredMd = decl == "md" || decl == "markdown";
            bool declaredLog = decl == "log";
            bool declaredIni = decl == "ini";
            bool declaredInf = decl == "inf";
            bool declaredToml = decl == "toml";
            bool declaredAdmx = decl == "admx";
            bool declaredAdml = decl == "adml";
            bool declaredCmd = decl == "cmd";

            bool psCues = HasPowerShellCues(head, headStr, headLower) || HasVerbNounCmdlet(headStr);
            bool vbsCues = LooksLikeVbsScript(headLower);
            bool jsCues = LooksLikeJavaScript(headStr, headLower);
            bool shShebang = headLower.Contains("#!/bin/sh") || headLower.Contains("#!/usr/bin/env sh") || headLower.Contains("#!/usr/bin/env bash") || headLower.Contains("#!/bin/bash") || headLower.Contains("#!/usr/bin/env zsh") || headLower.Contains("#!/bin/zsh");
            bool batCues = headLower.Contains("@echo off") || headLower.Contains("setlocal") || headLower.Contains("endlocal") ||
                           headLower.Contains("\ngoto ") || headLower.Contains("\r\ngoto ") || headLower.Contains(" goto ") ||
                           headLower.StartsWith("rem ") || headLower.Contains("\nrem ") || headLower.Contains("\r\nrem ") || headLower.Contains(":end");
            bool scriptCues = psCues || vbsCues || jsCues || shShebang || batCues;

            int mdCuesLocal = 0;
            bool mdStructuralLocal = false;
            if (headLower.Contains("```")) { mdCuesLocal += 2; mdStructuralLocal = true; }
            if (headLower.StartsWith("# ") || headLower.Contains("\n# ")) mdCuesLocal++;
            if (headLower.Contains("](")) mdCuesLocal++;
            if (headLower.Contains("\n- ") || headLower.Contains("\n* ") || headLower.Contains("\n1. ")) mdCuesLocal++;
            bool mdLikely = mdStructuralLocal || mdCuesLocal >= 2 || (declaredMd && mdCuesLocal >= 1);
            int scriptPenaltyFromMarkdown = mdLikely ? (declaredMd ? -8 : -6) : 0;

            var span = head;
            if (span.Length == 0) return new List<ContentTypeDetectionCandidate>();

            int nl = span.IndexOf((byte)'\n'); if (nl < 0) nl = span.Length;
            var line1 = span.Slice(0, nl);
            var rest = span.Slice(Math.Min(nl + 1, span.Length));
            int nl2 = rest.IndexOf((byte)'\n'); if (nl2 < 0) nl2 = rest.Length;
            var line2 = rest.Slice(0, nl2);
            var rest2 = rest.Slice(Math.Min(nl2 + 1, rest.Length));
            int nl3 = rest2.IndexOf((byte)'\n'); if (nl3 < 0) nl3 = rest2.Length;
            var line3 = rest2.Slice(0, nl3);
            var rest3 = rest2.Slice(Math.Min(nl3 + 1, rest2.Length));
            int nl4 = rest3.IndexOf((byte)'\n'); if (nl4 < 0) nl4 = rest3.Length;
            var line4 = rest3.Slice(0, nl4);

            bool jsonComplete = LooksLikeCompleteJson(headStr);
            bool jsonValid = jsonComplete && TryValidateJsonStructure(headStr);
            bool htmlHasScript = headLower.Contains("<script") || headLower.Contains("javascript:") || headLower.Contains("onerror=") || headLower.Contains("onload=");

            bool logCuesLocal = LooksLikeTimestamp(line1) || LooksLikeTimestamp(line2) || StartsWithLevelToken(line1) || StartsWithLevelToken(line2);
            int logPenaltyFromScript = scriptCues ? -8 : 0;
            int scriptPenaltyFromLog = logCuesLocal ? -8 : 0;
            int scriptPenalty = scriptPenaltyFromLog + scriptPenaltyFromMarkdown;
            int yamlPenalty = (logCuesLocal ? -6 : 0) + (scriptCues ? -4 : 0);
            int logPenalty = logPenaltyFromScript + (mdLikely ? -4 : 0);
            int jsonPenalty = (scriptCues ? -4 : 0) + (logCuesLocal ? -4 : 0);
            if (!scriptCues)
            {
                if (LogHeuristics.LooksLikeDnsLog(headLower)) AddCandidate("log", "text/plain", "Medium", "text:log-dns", scoreAdjust: logPenalty);
                if (LogHeuristics.LooksLikeFirewallLog(headLower)) AddCandidate("log", "text/plain", "Medium", "text:log-firewall", scoreAdjust: logPenalty);
                if (LogHeuristics.LooksLikeNetlogonLog(headLower, logCuesLocal)) AddCandidate("log", "text/plain", "Medium", "text:log-netlogon", scoreAdjust: logPenalty);
                if (LogHeuristics.LooksLikeEventViewerTextExport(headLower)) AddCandidate("log", "text/plain", "Medium", "text:event-txt", scoreAdjust: logPenalty);
                if (LogHeuristics.LooksLikeDhcpLog(headLower)) AddCandidate("log", "text/plain", "Medium", "text:log-dhcp", scoreAdjust: logPenalty);
                if (LogHeuristics.LooksLikeExchangeMessageTrackingLog(headLower)) AddCandidate("log", "text/plain", "Medium", "text:log-exchange", scoreAdjust: logPenalty);
                if (LogHeuristics.LooksLikeDefenderTextLog(headLower, logCuesLocal)) AddCandidate("log", "text/plain", "Low", "text:log-defender", scoreAdjust: logPenalty);
                if (LogHeuristics.LooksLikeSqlErrorLog(headLower, logCuesLocal)) AddCandidate("log", "text/plain", "Medium", "text:log-sql-errorlog", scoreAdjust: logPenalty);
                if (LogHeuristics.LooksLikeNpsRadiusLog(headLower)) AddCandidate("log", "text/plain", "Medium", "text:log-nps", scoreAdjust: logPenalty);
                if (LogHeuristics.LooksLikeSqlAgentLog(headLower, logCuesLocal)) AddCandidate("log", "text/plain", "Low", "text:log-sqlagent", scoreAdjust: logPenalty);

                int levelCount = 0;
                if (StartsWithLevelToken(line1)) levelCount++;
                if (StartsWithLevelToken(line2)) levelCount++;
                if (StartsWithLevelToken(line3)) levelCount++;
                if (StartsWithLevelToken(line4)) levelCount++;
                int tsCount = 0;
                if (LooksLikeTimestamp(line1)) tsCount++;
                if (LooksLikeTimestamp(line2)) tsCount++;
                if (LooksLikeTimestamp(line3)) tsCount++;
                if (LooksLikeTimestamp(line4)) tsCount++;
                if (tsCount >= 2)
                    AddCandidate("log", "text/plain", "Low", "text:log", "log:timestamps-multi", scoreAdjust: logPenalty);
                if (levelCount >= 2 || ((LooksLikeTimestamp(line1) || LooksLikeTimestamp(line2)) && levelCount >= 1))
                {
                    var conf = levelCount >= 2 && (LooksLikeTimestamp(line1) || LooksLikeTimestamp(line2)) ? "Medium" : "Low";
                    AddCandidate("log", "text/plain", conf, "text:log-levels", levelCount >= 2 ? $"log:levels-{levelCount}" : "log:timestamp+level", scoreAdjust: logPenalty);
                }
                if (declaredLog && logCuesLocal)
                    AddCandidate("log", "text/plain", "Low", "text:log", "log:declared", scoreAdjust: logPenalty);
            }

            {
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
                if (j1 && j2)
                {
                    var l3 = TrimBytes(line3);
                    bool j3 = LooksJsonLine(l3);
                    string conf = j3 ? "High" : "Medium";
                    int boost = j3 ? 10 : 8;
                    AddCandidate("ndjson", "application/x-ndjson", conf, "text:ndjson", j3 ? "ndjson:lines-3" : "ndjson:lines-2", scoreAdjust: boost);
                }
            }

            if (head.Length > 0 && (head[0] == (byte)'{' || head[0] == (byte)'['))
            {
                bool jsonLooksLikeLog = LooksLikeTimestamp(TrimBytes(line1)) || StartsWithLevelToken(TrimBytes(line1));
                if (!jsonLooksLikeLog)
                {
                    int len = Math.Min(2048, head.Length);
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
                                AddCandidate("json", "application/json", hasObjectItem ? "Medium" : "Low", "text:json", hasObjectItem ? "json:array-of-objects" : "json:array-of-primitives", scoreAdjust: (jsonValid ? 6 : 0) + jsonPenalty);
                            }
                        }
                    }
                    if (looksObject)
                    {
                        bool hasQuotedColon = HasQuotedKeyColon(slice);
                        bool hasClose = slice.IndexOf((byte)'}') >= 0;
                        if (hasQuotedColon && hasClose)
                            AddCandidate("json", "application/json", "Medium", "text:json", "json:object-key-colon", scoreAdjust: (jsonValid ? 6 : 0) + jsonPenalty);
                    }
                }
            }

            if (head.Length >= 1 && head[0] == (byte)'<')
            {
                var root = TryGetXmlRootName(headStr);
                if (root != null && root.Length > 0)
                {
                    var rootLower = root.ToLowerInvariant();
                    int colon = rootLower.IndexOf(':');
                    if (colon >= 0 && colon < rootLower.Length - 1)
                        rootLower = rootLower.Substring(colon + 1);
                    bool xmlComplete = LooksLikeCompleteXml(headLower, rootLower);
                    bool xmlWellFormed = xmlComplete && TryXmlWellFormed(headStr, out _);
                    if (rootLower == "policydefinitions")
                    {
                        bool admxCues = LooksLikeAdmxXml(headLower);
                        bool admxStrong = admxCues || declaredAdmx;
                        var details = admxCues ? "xml:policydefinitions+schema" : (declaredAdmx ? "xml:policydefinitions+decl" : "xml:policydefinitions");
                        AddCandidate("admx", "application/xml", admxStrong ? "High" : "Medium", "text:admx", details, scoreAdjust: xmlWellFormed ? 6 : 0);
                    }
                    else if (rootLower == "policydefinitionresources")
                    {
                        bool admlCues = LooksLikeAdmlXml(headLower);
                        bool admlStrong = admlCues || declaredAdml;
                        var details = admlCues ? "xml:policydefinitionresources+schema" : (declaredAdml ? "xml:policydefinitionresources+decl" : "xml:policydefinitionresources");
                        AddCandidate("adml", "application/xml", admlStrong ? "High" : "Medium", "text:adml", details, scoreAdjust: xmlWellFormed ? 6 : 0);
                    }
                }
                if (head.Length >= 5 && head.Slice(0, 5).SequenceEqual("<?xml"u8))
                {
                    var ext = declaredAdmx ? "admx" : (declaredAdml ? "adml" : "xml");
                    bool xmlComplete = LooksLikeCompleteXml(headLower, null);
                    bool xmlWellFormed = xmlComplete && TryXmlWellFormed(headStr, out _);
                    AddCandidate(ext, "application/xml", "Medium", "text:xml", ext == "xml" ? null : $"xml:decl-{ext}", scoreAdjust: xmlWellFormed ? 6 : 0);
                }
                if (head.IndexOf("<!DOCTYPE html"u8) >= 0 || head.IndexOf("<html"u8) >= 0)
                    AddCandidate("html", "text/html", "Medium", "text:html", scoreAdjust: 0, dangerousOverride: htmlHasScript);
            }

            if (!scriptCues && !logCuesLocal)
            {
                bool yamlFront = false;
                string trimmed = headStr.TrimStart('\ufeff', ' ', '\t', '\r', '\n');
                if (trimmed.StartsWith("---", StringComparison.Ordinal))
                {
                    int idx = trimmed.IndexOf("\n---", StringComparison.Ordinal);
                    if (idx > 0) yamlFront = true;
                }
                if (yamlFront)
                {
                    AddCandidate("yml", "application/x-yaml", "Low", "text:yaml", "yaml:front-matter", scoreAdjust: yamlPenalty);
                }
                else
                {
                    int yamlish = 0;
                    int lineStart = 0;
                    for (int i = 0; i < head.Length && yamlish < 4; i++)
                    {
                        if (head[i] == (byte)'\n' || i == head.Length - 1)
                        {
                            int end = head[i] == (byte)'\n' ? i : i + 1;
                            var raw = head.Slice(lineStart, Math.Max(0, end - lineStart));
                            lineStart = i + 1;
                            var line = TrimBytes(raw);
                            if (line.Length == 0) continue;
                            if (LooksYamlKeyValue(line)) yamlish++;
                        }
                    }
                    if (yamlish >= 2) AddCandidate("yml", "application/x-yaml", "Low", "text:yaml-keys", $"yaml:key-lines={yamlish}", scoreAdjust: yamlPenalty);
                }
            }

            if (!scriptCues && !logCuesLocal)
            {
                int tomlTables = 0;
                int tomlEquals = 0;
                int lineStart = 0;
                int inspected = 0;
                for (int i = 0; i < head.Length && inspected < 8; i++)
                {
                    if (head[i] == (byte)'\n' || i == head.Length - 1)
                    {
                        int end = head[i] == (byte)'\n' ? i : i + 1;
                        var raw = head.Slice(lineStart, Math.Max(0, end - lineStart));
                        lineStart = i + 1;
                        var line = TrimBytes(raw);
                        if (line.Length == 0) continue;
                        inspected++;
                        if (line[0] == (byte)'[' && line[line.Length - 1] == (byte)']') tomlTables++;
                        if (line.IndexOf((byte)'=') > 0) tomlEquals++;
                    }
                }
                if (tomlTables >= 1 && tomlEquals >= 1)
                {
                    int tomlAdjust = tomlTables >= 1 && tomlEquals >= 2 ? 4 : 0;
                    AddCandidate("toml", "application/toml", "Low", "text:toml", scoreAdjust: tomlAdjust);
                }
            }

            {
                bool hasPsCues = HasPowerShellCues(head, headStr, headLower) || HasVerbNounCmdlet(headStr);
                if (!hasPsCues && !jsCues && !shShebang && !batCues)
                {
                    bool hasSection = false;
                    bool hasEquals = false;
                    int meaningfulLines = 0;
                    int lineStart2 = 0;
                    for (int i = 0; i < head.Length && meaningfulLines < 8; i++)
                    {
                        if (head[i] == (byte)'\n' || i == head.Length - 1)
                        {
                            int end = head[i] == (byte)'\n' ? i : i + 1;
                            var raw = head.Slice(lineStart2, Math.Max(0, end - lineStart2));
                            lineStart2 = i + 1;
                            var line = TrimBytes(raw);
                            if (line.Length == 0) continue;
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
                        int iniAdjust = 4;
                        AddCandidate(ext, "text/plain", "Low", "text:ini", ext == "inf" ? "inf:section+equals" : "ini:section+equals", scoreAdjust: iniAdjust);
                    }
                }
            }

            if (!logCuesLocal && !scriptCues)
            {
                int commas1 = Count(line1, (byte)','); int commas2 = Count(line2, (byte)',');
                int semis1 = Count(line1, (byte)';'); int semis2 = Count(line2, (byte)';');
                int pipes1 = Count(line1, (byte)'|'); int pipes2 = Count(line2, (byte)'|');
                int tabs1 = Count(line1, (byte)'\t'); int tabs2 = Count(line2, (byte)'\t');
                if ((commas1 >= 1 && commas2 >= 1 && Math.Abs(commas1 - commas2) <= 2) ||
                    (semis1 >= 1 && semis2 >= 1 && Math.Abs(semis1 - semis2) <= 2) ||
                    (pipes1 >= 1 && pipes2 >= 1 && Math.Abs(pipes1 - pipes2) <= 2))
                    AddCandidate("csv", "text/csv", "Low", "text:csv", "csv:delimiter-repeat-2lines");
                if (tabs1 >= 1 && tabs2 >= 1 && Math.Abs(tabs1 - tabs2) <= 2)
                    AddCandidate("tsv", "text/tab-separated-values", "Low", "text:tsv", "tsv:tabs-2lines");
                if (line2.Length == 0)
                {
                    static int TokenCount(ReadOnlySpan<byte> l, byte sep) { if (l.Length == 0) return 0; int tokens = 1; for (int i = 0; i < l.Length; i++) if (l[i] == sep) tokens++; return tokens; }
                    if (commas1 >= 2 && TokenCount(line1, (byte)',') >= 3) AddCandidate("csv", "text/csv", "Low", "text:csv", "csv:single-line");
                    if (semis1 >= 2 && TokenCount(line1, (byte)';') >= 3) AddCandidate("csv", "text/csv", "Low", "text:csv", "csv:single-line");
                    if (tabs1 >= 2 && TokenCount(line1, (byte)'\t') >= 3) AddCandidate("tsv", "text/tab-separated-values", "Low", "text:tsv", "tsv:single-line");
                }
            }

            {
                var sl = headLower;
                bool looksMd = sl.StartsWith("# ") || sl.Contains("\n# ") || sl.Contains("```") || sl.Contains("](");
                int mdCues = 0;
                if (sl.StartsWith("# ") || sl.Contains("\n# ")) mdCues++;
                if (sl.Contains("```")) mdCues++;
                if (sl.Contains("](")) mdCues++;
                if (sl.Contains("\n- ") || sl.StartsWith("- ") || sl.Contains("\n* ") || sl.StartsWith("* ")) mdCues++;
                if (mdCues == 1)
                {
                    var lines = headStr.Split('\n');
                    if (lines.Length >= 2 && lines[1].Trim().Length > 0) mdCues++;
                }
                if (looksMd)
                {
                    var okByCues = declaredMd ? mdCues >= 1 : mdCues >= 2;
                    bool hasFence = sl.Contains("```");
                    bool hasHeading = sl.StartsWith("# ") || sl.Contains("\n# ");
                    bool mdStructural = hasFence || hasHeading;
                    if (okByCues && !logCuesLocal && (!scriptCues || declaredMd || mdStructural))
                        AddCandidate("md", "text/markdown", "Low", "text:md", null, mdStructural ? 4 : 0);
                }
            }

            {
                bool psShebang = headLower.Contains("#!/usr/bin/env pwsh") || headLower.Contains("#!/usr/bin/pwsh") ||
                                 headLower.Contains("#!/usr/bin/env powershell") || headLower.Contains("#!/usr/bin/powershell");
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
                if (headStr.IndexOf("Import-Module", System.StringComparison.OrdinalIgnoreCase) >= 0) cues++;
                if (headStr.IndexOf("New-Object", System.StringComparison.OrdinalIgnoreCase) >= 0) cues++;
                bool hasGetSet = headStr.IndexOf("Get-", System.StringComparison.OrdinalIgnoreCase) >= 0 || headStr.IndexOf("Set-", System.StringComparison.OrdinalIgnoreCase) >= 0;
                if (hasGetSet) cues++;
                if (hasVerbNoun) { cues++; strong++; }
                if (hasPipeline) { cues++; strong++; }

                if (declaredPsm1 && (hasModuleExport || hasVerbNoun))
                    AddCandidate("psm1", "text/x-powershell", "Medium", "text:psm1", "psm1:module-cues", scriptPenalty);

                if (declaredPsd1 && (psd1Hashtable || hasModuleExport))
                    AddCandidate("psd1", "text/x-powershell", "Low", "text:psd1", psd1Hashtable ? "psd1:hashtable" : "psd1:module-keys", scriptPenalty);

                if (psShebang || cues >= 2 || (cues >= 1 && strong >= 1))
                {
                    string conf = psShebang || cues >= 3 || strong >= 2 ? "High" : "Medium";
                    string details = psShebang ? "ps1:shebang" : (cues >= 3 ? "ps1:multi-cues" : (strong >= 1 && cues == 1 ? "ps1:single-strong-cue" : "ps1:common-cmdlets"));
                    AddCandidate("ps1", "text/x-powershell", conf, psShebang ? "text:ps1-shebang" : "text:ps1", details, scriptPenalty);
                }
            }

            if (LooksLikeVbsScript(headLower))
            {
                var conf = (headLower.Contains("option explicit") || headLower.Contains("on error resume next") || headLower.Contains("createobject(") || headLower.Contains("wscript.")) ? "Medium" : "Low";
                bool vbsBlock = headLower.Contains("end sub") || headLower.Contains("end function");
                bool vbsToken = vbsBlock && (ContainsToken(headLower, "sub") || ContainsToken(headLower, "function"));
                int vbsAdjust = scriptPenalty + (vbsToken ? 4 : 0);
                AddCandidate("vbs", "text/vbscript", conf, "text:vbs", conf == "Medium" ? "vbs:explicit+error|createobject" : "vbs:wscript+dim|msgbox", vbsAdjust);
            }

            if (shShebang)
                AddCandidate("sh", "text/x-shellscript", "Medium", "text:sh-shebang", "sh:shebang", scriptPenalty);
            if (!shShebang && !scriptCues && (headLower.Contains("set -e") || headLower.Contains("set -u") || headLower.Contains("export ") || headLower.Contains("[[") || headLower.Contains("]]")) &&
                (headLower.Contains(" fi\n") || headLower.Contains(" esac\n") || headLower.Contains(" && ") || headLower.Contains(" case ") || headLower.Contains(" do\n")))
                AddCandidate("sh", "text/x-shellscript", "Low", "text:sh-heur", "sh:set|export+fi|esac|case|&&|do", scriptPenalty);

            if (headLower.Contains("#!/usr/bin/env node") || headLower.Contains("#!/usr/bin/node"))
                AddCandidate("js", "application/javascript", "Medium", "text:node-shebang", "js:shebang", scriptPenalty);
            else if (LooksLikeJavaScript(headStr, headLower))
                AddCandidate("js", "application/javascript", "Low", "text:js-heur", scoreAdjust: scriptPenalty);

            if (batCues)
            {
                var ext = declaredCmd ? "cmd" : "bat";
                AddCandidate(ext, "text/x-batch", "Medium", ext == "cmd" ? "text:cmd" : "text:bat", "bat:echo|setlocal|goto|rem", scriptPenalty);
            }

            if (headLower.Contains("#!/usr/bin/env python") || headLower.Contains("#!/usr/bin/python"))
                AddCandidate("py", "text/x-python", "Medium", "text:py-shebang", "py:shebang", scriptPenalty);
            else
            {
                int pyCues = 0;
                if (IndexOfToken(head, "import ") >= 0) pyCues++;
                if (IndexOfToken(head, "def ") >= 0 && head.IndexOf((byte)':') >= 0) pyCues++;
                if (IndexOfToken(head, "class ") >= 0 && head.IndexOf((byte)':') >= 0) pyCues++;
                if (IndexOfToken(head, "if __name__ == '__main__':") >= 0) pyCues += 2;
                if (pyCues >= 2) AddCandidate("py", "text/x-python", "Low", "text:py-heur", $"py:cues-{pyCues}", scriptPenalty);
            }

            if (headLower.Contains("#!/usr/bin/env ruby") || headLower.Contains("#!/usr/bin/ruby"))
                AddCandidate("rb", "text/x-ruby", "Medium", "text:rb-shebang", "rb:shebang", scriptPenalty);
            else
            {
                int rbCues = 0;
                if (IndexOfToken(head, "require ") >= 0) rbCues++;
                if (IndexOfToken(head, "def ") >= 0 && IndexOfToken(head, " end") >= 0) rbCues += 2;
                if (IndexOfToken(head, "class ") >= 0 && IndexOfToken(head, " end") >= 0) rbCues += 2;
                if (IndexOfToken(head, "module ") >= 0 && IndexOfToken(head, " end") >= 0) rbCues += 2;
                if (IndexOfToken(head, "puts ") >= 0) rbCues++;
                if (rbCues >= 2) AddCandidate("rb", "text/x-ruby", "Low", "text:rb-heur", $"rb:cues-{rbCues}", scriptPenalty);
            }

            if (headLower.Contains("#!/usr/bin/env lua") || headLower.Contains("#!/usr/bin/lua"))
                AddCandidate("lua", "text/x-lua", "Medium", "text:lua-shebang", "lua:shebang", scriptPenalty);
            else
            {
                int luaCues = 0;
                if (IndexOfToken(head, "local function ") >= 0) luaCues += 2;
                if (IndexOfToken(head, "function ") >= 0 && IndexOfToken(head, " end") >= 0) luaCues += 2;
                if (IndexOfToken(head, "require(") >= 0 || IndexOfToken(head, "require ") >= 0) luaCues++;
                if (IndexOfToken(head, " then") >= 0 && IndexOfToken(head, " end") >= 0) luaCues++;
                if (luaCues >= 2) AddCandidate("lua", "text/x-lua", "Low", "text:lua-heur", $"lua:cues-{luaCues}", scriptPenalty);
            }

            var list = new List<ContentTypeDetectionCandidate>(byExt.Values);
            list.Sort((a, b) => b.Score.CompareTo(a.Score));
            return list;
        }

        static int ConfidenceRank(string? confidence)
        {
            if (string.Equals(confidence, "High", StringComparison.OrdinalIgnoreCase)) return 3;
            if (string.Equals(confidence, "Medium", StringComparison.OrdinalIgnoreCase)) return 2;
            if (string.Equals(confidence, "Low", StringComparison.OrdinalIgnoreCase)) return 1;
            return 0;
        }

        static int ScoreFromConfidence(string? confidence)
        {
            if (string.Equals(confidence, "High", StringComparison.OrdinalIgnoreCase)) return 90;
            if (string.Equals(confidence, "Medium", StringComparison.OrdinalIgnoreCase)) return 70;
            if (string.Equals(confidence, "Low", StringComparison.OrdinalIgnoreCase)) return 50;
            return 40;
        }

        static int ClampScore(int score, string? confidence)
        {
            int min = 40; int max = 100;
            if (string.Equals(confidence, "High", StringComparison.OrdinalIgnoreCase)) { min = 80; max = 100; }
            else if (string.Equals(confidence, "Medium", StringComparison.OrdinalIgnoreCase)) { min = 60; max = 79; }
            else if (string.Equals(confidence, "Low", StringComparison.OrdinalIgnoreCase)) { min = 40; max = 59; }
            if (score < min) return min;
            if (score > max) return max;
            return score;
        }

        static int GetScoreAdjustment(string ext, string reason, string? details)
        {
            var map = Settings.DetectionScoreAdjustments;
            if (map == null || map.Count == 0) return 0;
            int adjust = 0;
            if (!string.IsNullOrEmpty(ext))
            {
                if (map.TryGetValue(ext, out var v)) adjust += v;
                if (map.TryGetValue("ext:" + ext, out var vExt)) adjust += vExt;
            }
            if (!string.IsNullOrEmpty(reason))
            {
                if (map.TryGetValue(reason, out var v)) adjust += v;
                if (map.TryGetValue("reason:" + reason, out var vReason)) adjust += vReason;
            }
            if (!string.IsNullOrEmpty(details))
            {
                var detailKey = details!;
                if (map.TryGetValue(detailKey, out var v)) adjust += v;
                if (map.TryGetValue("detail:" + detailKey, out var vDetail)) adjust += vDetail;
            }
            return adjust;
        }

        static bool LooksLikeCompleteJson(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return false;
            var t = s.Trim();
            if (t.Length < 2) return false;
            char first = t[0];
            char last = t[t.Length - 1];
            return (first == '{' || first == '[') && (last == '}' || last == ']');
        }

        static bool TryValidateJsonStructure(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return false;
            var span = s.AsSpan().Trim();
            if (span.Length < 2) return false;
            char first = span[0];
            char last = span[span.Length - 1];
            if (!((first == '{' || first == '[') && (last == '}' || last == ']'))) return false;
            int depthObj = 0;
            int depthArr = 0;
            bool inString = false;
            bool escape = false;
            for (int i = 0; i < span.Length; i++)
            {
                char c = span[i];
                if (inString)
                {
                    if (escape) { escape = false; continue; }
                    if (c == '\\') { escape = true; continue; }
                    if (c == '"') inString = false;
                    continue;
                }
                if (c == '"') { inString = true; continue; }
                if (c == '{') depthObj++;
                else if (c == '}') { depthObj--; if (depthObj < 0) return false; }
                else if (c == '[') depthArr++;
                else if (c == ']') { depthArr--; if (depthArr < 0) return false; }
            }
            return !inString && depthObj == 0 && depthArr == 0;
        }

        static bool LooksLikeCompleteXml(string lower, string? rootLower)
        {
            if (string.IsNullOrWhiteSpace(lower)) return false;
            if (!lower.Contains("</")) return false;
            if (!lower.TrimEnd().EndsWith(">")) return false;
            if (!string.IsNullOrEmpty(rootLower))
                return lower.Contains("</" + rootLower);
            return true;
        }

        static bool TryXmlWellFormed(string xml, out string? rootName)
        {
            rootName = null;
            if (string.IsNullOrWhiteSpace(xml)) return false;
            try
            {
                var settings = new System.Xml.XmlReaderSettings
                {
                    DtdProcessing = System.Xml.DtdProcessing.Prohibit,
                    XmlResolver = null
                };
                using var reader = System.Xml.XmlReader.Create(new System.IO.StringReader(xml), settings);
                while (reader.Read())
                {
                    if (reader.NodeType == System.Xml.XmlNodeType.Element)
                    {
                        rootName = reader.Name;
                        break;
                    }
                }
                return !string.IsNullOrEmpty(rootName);
            }
            catch
            {
                return false;
            }
        }

        static bool IsAltEligibleExtension(string? ext)
        {
            var normalized = (ext ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(normalized)) return false;
            switch (normalized)
            {
                case "txt":
                case "text":
                case "log":
                case "md":
                case "markdown":
                case "ps1":
                case "psm1":
                case "psd1":
                case "vbs":
                case "js":
                case "sh":
                case "bat":
                case "cmd":
                case "py":
                case "rb":
                case "lua":
                case "xml":
                case "admx":
                case "adml":
                case "html":
                case "json":
                case "ndjson":
                case "csv":
                case "tsv":
                case "ini":
                case "inf":
                case "toml":
                case "yml":
                case "yaml":
                    return true;
                default:
                    return false;
            }
        }

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
            const string DisallowedIniSectionChars = "()=@{}";
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
                    if (DisallowedIniSectionChars.IndexOf((char)c) >= 0) return false;
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
        static bool LooksLikeVbsScript(string lower)
        {
            return lower.Contains("wscript.") || lower.Contains("wscript.echo") ||
                   lower.Contains("createobject(") || lower.Contains("vbscript") ||
                   lower.Contains("dim ") || lower.Contains("end sub") ||
                   lower.Contains("option explicit") || lower.Contains("on error resume next") ||
                   lower.Contains("msgbox");
        }
        static bool LooksLikeJavaScript(string s, string sl)
        {
            // Strong cues: shebang, function/arrow, module exports, or call-pattern like obj.method(
            if (sl.Contains("#!/usr/bin/env node") || sl.Contains("#!/usr/bin/node")) return true;
            if (sl.Contains("local function")) return false; // Lua-specific guard
            int cues = 0;
            bool strong = false;
            if (sl.Contains("function(") || sl.Contains("function ")) { cues++; strong = true; }
            if (sl.Contains("=>")) { cues++; strong = true; }
            if (sl.Contains("module.exports") || sl.Contains("exports.")) { cues++; strong = true; }
            if (sl.Contains("import ") || sl.Contains("export ")) cues++;
            if (sl.Contains("require(")) cues++;
            if (sl.Contains("document.") || sl.Contains("window.")) cues++;
            if (sl.Contains("class ")) cues++;
            if (sl.Contains("const ") || sl.Contains("let ") || sl.Contains("var "))
            {
                cues++;
                if (sl.Contains("=")) strong = true;
            }
            if (LooksLikeJsCallPrefix(s)) { cues++; strong = true; }
            return (strong && cues >= 1) || cues >= 2;
        }
        static bool LooksLikeJsCallPrefix(string s)
        {
            if (string.IsNullOrEmpty(s)) return false;
            int i = 0;
            while (i < s.Length && char.IsWhiteSpace(s[i])) i++;
            if (i < s.Length && s[i] == '(') i++; // IIFE or grouped expression
            if (i >= s.Length || !IsIdentStart(s[i])) return false;
            i++;
            while (i < s.Length && IsIdentPart(s[i])) i++;
            if (i >= s.Length || s[i] != '.') return false;
            i++;
            if (i >= s.Length || !IsIdentStart(s[i])) return false;
            i++;
            while (i < s.Length && IsIdentPart(s[i])) i++;
            while (i < s.Length && char.IsWhiteSpace(s[i])) i++;
            return i < s.Length && s[i] == '(';
        }
        static bool IsIdentStart(char c) => char.IsLetter(c) || c == '_' || c == '$';
        static bool IsIdentPart(char c) => char.IsLetterOrDigit(c) || c == '_' || c == '$';
        static bool LooksLikeAdmxXml(string lower)
        {
            int cues = 0;
            if (lower.Contains("schemas.microsoft.com/grouppolicy/2006/07/policydefinitions")) cues++;
            if (lower.Contains("<policynamespaces")) cues++;
            if (lower.Contains("<policies")) cues++;
            if (lower.Contains("<categories")) cues++;
            if (lower.Contains("<resources")) cues++;
            if (lower.Contains("schemaversion")) cues++;
            if (lower.Contains("revision=\"")) cues++;
            return cues >= 2;
        }
        static bool LooksLikeAdmlXml(string lower)
        {
            int cues = 0;
            if (lower.Contains("schemas.microsoft.com/grouppolicy/2006/07/policydefinitions")) cues++;
            if (lower.Contains("<resources")) cues++;
            if (lower.Contains("<stringtable")) cues++;
            if (lower.Contains("<presentationtable")) cues++;
            if (lower.Contains("schemaversion")) cues++;
            if (lower.Contains("revision=\"")) cues++;
            return cues >= 2;
        }
        static string? TryGetXmlRootName(string s)
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
        static bool StartsWithLevelToken(ReadOnlySpan<byte> l) {
            if (StartsWithToken(l, "INFO") || StartsWithToken(l, "WARN") || StartsWithToken(l, "ERROR") || StartsWithToken(l, "DEBUG") || StartsWithToken(l, "TRACE") || StartsWithToken(l, "FATAL") || StartsWithToken(l, "CRITICAL") || StartsWithToken(l, "ALERT") || StartsWithToken(l, "[INFO]") || StartsWithToken(l, "[WARN]") || StartsWithToken(l, "[ERROR]") || StartsWithToken(l, "[DEBUG]") || StartsWithToken(l, "[CRITICAL]") || StartsWithToken(l, "[ALERT]"))
                return true;
            // Allow bracketed levels like "[Info -", "[ERROR  -", "[Warn ]"
            if (l.Length > 2 && l[0] == (byte)'[')
            {
                int i = 1;
                while (i < l.Length && char.IsWhiteSpace((char)l[i])) i++;
                int start = i;
                while (i < l.Length && char.IsLetter((char)l[i])) i++;
                int len = i - start;
                if (len >= 3 && IsLevelToken(l.Slice(start, len)))
                {
                    if (i >= l.Length) return true;
                    byte next = l[i];
                    if (next == (byte)']' || next == (byte)'-' || next == (byte)' ' || next == (byte)'\t') return true;
                }
            }
            return false;
        }
        static bool IsLevelToken(ReadOnlySpan<byte> token)
        {
            return (token.Length == 4 && StartsWithToken(token, "INFO")) ||
                   (token.Length == 4 && StartsWithToken(token, "WARN")) ||
                   (token.Length == 5 && StartsWithToken(token, "ERROR")) ||
                   (token.Length == 5 && StartsWithToken(token, "DEBUG")) ||
                   (token.Length == 5 && StartsWithToken(token, "TRACE")) ||
                   (token.Length == 5 && StartsWithToken(token, "FATAL")) ||
                   (token.Length == 5 && StartsWithToken(token, "ALERT")) ||
                   (token.Length == 8 && StartsWithToken(token, "CRITICAL"));
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
            // quick token scan to avoid regex and allocations
            var span = s.AsSpan();
            int i = 0;
            while (i < span.Length) {
                while (i < span.Length && IsSep(span[i])) i++;
                int start = i;
                while (i < span.Length && !IsSep(span[i])) i++;
                int len = i - start;
                if (len > 3) {
                    var token = span.Slice(start, len);
                    int dash = token.IndexOf('-');
                    if (dash > 0 && dash < token.Length - 1) {
                        var verb = token.Slice(0, dash);
                        var noun = token.Slice(dash + 1);
                        if (noun.Length >= 2 && IsCommonPsVerb(verb)) return true;
                    }
                }
            }
            return false;

            static bool IsCommonPsVerb(ReadOnlySpan<char> verb)
            {
                if (verb.Length < 3 || verb.Length > 12) return false;
                return verb.Equals("get", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("set", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("new", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("add", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("remove", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("clear", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("copy", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("move", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("rename", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("test", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("invoke", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("start", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("stop", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("enable", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("disable", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("import", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("export", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("select", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("convert", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("write", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("read", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("update", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("connect", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("disconnect", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("format", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("register", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("unregister", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("resolve", StringComparison.OrdinalIgnoreCase) ||
                       verb.Equals("find", StringComparison.OrdinalIgnoreCase);
            }

            static bool IsSep(char c) => c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ';' || c == '(' || c == '{';
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
