namespace FileInspectorX;

/// <summary>
/// Text and markup format detection (JSON, XML/HTML, YAML, EML, CSV/TSV/INI/LOG) and Outlook MSG hints.
/// </summary>
internal static partial class Signatures {
    internal static bool TryMatchText(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length == 0) return false;

        // BOMs
        if (src.Length >= 3 && src[0] == 0xEF && src[1] == 0xBB && src[2] == 0xBF) { result = new ContentTypeDetectionResult { Extension = "txt", MimeType = "text/plain; charset=utf-8", Confidence = "Medium", Reason = "bom:utf8" }; return true; }
        if (src.Length >= 2 && src[0] == 0xFF && src[1] == 0xFE) { result = new ContentTypeDetectionResult { Extension = "txt", MimeType = "text/plain; charset=utf-16le", Confidence = "Medium", Reason = "bom:utf16le" }; return true; }
        if (src.Length >= 2 && src[0] == 0xFE && src[1] == 0xFF) { result = new ContentTypeDetectionResult { Extension = "txt", MimeType = "text/plain; charset=utf-16be", Confidence = "Medium", Reason = "bom:utf16be" }; return true; }

        // Binary heuristic: NUL in head implies not text
        for (int i = 0; i < src.Length && i < 1024; i++) if (src[i] == 0x00) return false;

        // Trim leading whitespace for structure checks
        int start = 0; while (start < src.Length && char.IsWhiteSpace((char)src[start])) start++;
        var head = src.Slice(start, Math.Min(2048, src.Length - start));

        // RTF
        if (src.Length >= 5 && src[0] == '{' && src[1] == '\\' && src[2] == 'r' && src[3] == 't' && src[4] == 'f') { result = new ContentTypeDetectionResult { Extension = "rtf", MimeType = "application/rtf", Confidence = "Medium", Reason = "text:rtf" }; return true; }

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
            if (head.Length >= 5 && head.Slice(0, 5).SequenceEqual("<?xml"u8)) { result = new ContentTypeDetectionResult { Extension = "xml", MimeType = "application/xml", Confidence = "Medium", Reason = "text:xml" }; return true; }
            if (head.IndexOf("<!DOCTYPE html"u8) >= 0 || head.IndexOf("<html"u8) >= 0) { result = new ContentTypeDetectionResult { Extension = "html", MimeType = "text/html", Confidence = "Medium", Reason = "text:html" }; return true; }
        }

        // YAML (document start) or refined key:value heuristics
        if (head.Length >= 3 && head[0] == (byte)'-' && head[1] == (byte)'-' && head[2] == (byte)'-') { result = new ContentTypeDetectionResult { Extension = "yml", MimeType = "application/x-yaml", Confidence = "Low", Reason = "text:yaml", ReasonDetails = "yaml:front-matter" }; return true; }
        {
            int yamlish = 0; int scanned = 0; int startLine = 0;
            for (int i = 0; i < head.Length && scanned < 6; i++) {
                if (head[i] == (byte)'\n') {
                    var raw = head.Slice(startLine, i - startLine);
                    var line = TrimBytes(raw);
                    if (LooksYamlKeyValue(line)) yamlish++;
                    scanned++;
                    startLine = i + 1;
                }
            }
            if (yamlish >= 2) { result = new ContentTypeDetectionResult { Extension = "yml", MimeType = "application/x-yaml", Confidence = "Low", Reason = "text:yaml-keys", ReasonDetails = $"yaml:key-lines={yamlish}" }; return true; }
        }

        // Markdown quick cues
        {
            var hb2 = new byte[Math.Min(head.Length, 2048)]; head.Slice(0, hb2.Length).CopyTo(new System.Span<byte>(hb2));
            var s = System.Text.Encoding.UTF8.GetString(hb2);
            var sl = s.ToLowerInvariant();
            if (sl.StartsWith("# ") || sl.Contains("\n# ") || sl.Contains("```") || (sl.Contains("[")) && sl.Contains("](") ) {
                result = new ContentTypeDetectionResult { Extension = "md", MimeType = "text/markdown", Confidence = "Low", Reason = "text:md" }; return true;
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

        // CSV/TSV/Delimited heuristics (look at first two lines)
        var span = head;
        int nl = head.IndexOf((byte)'\n'); if (nl < 0) nl = head.Length;
        var line1 = span.Slice(0, nl);
        var rest = span.Slice(Math.Min(nl + 1, span.Length));
        int nl2 = rest.IndexOf((byte)'\n'); if (nl2 < 0) nl2 = rest.Length;
        var line2 = rest.Slice(0, nl2);

        int commas1 = Count(line1, (byte)','); int commas2 = Count(line2, (byte)',');
        int semis1 = Count(line1, (byte)';'); int semis2 = Count(line2, (byte)';');
        int pipes1 = Count(line1, (byte)'|'); int pipes2 = Count(line2, (byte)'|');
        int tabs1 = Count(line1, (byte)'\t'); int tabs2 = Count(line2, (byte)'\t');
        if ((commas1 >= 1 && commas2 >= 1 && Math.Abs(commas1 - commas2) <= 2) || (semis1 >= 1 && semis2 >= 1 && Math.Abs(semis1 - semis2) <= 2) || (pipes1 >= 1 && pipes2 >= 1 && Math.Abs(pipes1 - pipes2) <= 2)) { result = new ContentTypeDetectionResult { Extension = "csv", MimeType = "text/csv", Confidence = "Low", Reason = "text:csv", ReasonDetails = "csv:delimiter-repeat-2lines" }; return true; }
        if (tabs1 >= 1 && tabs2 >= 1 && Math.Abs(tabs1 - tabs2) <= 2) { result = new ContentTypeDetectionResult { Extension = "tsv", MimeType = "text/tab-separated-values", Confidence = "Low", Reason = "text:tsv", ReasonDetails = "tsv:tabs-2lines" }; return true; }

        // INI heuristic
        if (line1.IndexOf((byte)'=') > 0 || line2.IndexOf((byte)'=') > 0) {
            if (head.IndexOf((byte)'[') >= 0 && head.IndexOf((byte)']') > head.IndexOf((byte)'[')) { result = new ContentTypeDetectionResult { Extension = "ini", MimeType = "text/plain", Confidence = "Low", Reason = "text:ini", ReasonDetails = "ini:section+equals" }; return true; }
        }

        // LOG heuristic (timestamps at start of two lines)
        static bool LooksLikeTimestamp(ReadOnlySpan<byte> l) {
            if (l.Length < 10) return false;
            bool y = IsDigit(l[0]) && IsDigit(l[1]) && IsDigit(l[2]) && IsDigit(l[3]);
            bool sep1 = l[4] == (byte)'-' || l[4] == (byte)'/';
            bool m = IsDigit(l[5]) && IsDigit(l[6]);
            bool sep2 = l[7] == (byte)'-' || l[7] == (byte)'/';
            bool d = IsDigit(l[8]) && IsDigit(l[9]);
            return y && sep1 && m && sep2 && d;
        }
        if (LooksLikeTimestamp(line1) && LooksLikeTimestamp(line2)) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Low", Reason = "text:log", ReasonDetails = "log:timestamps-2" }; return true; }

        // Log heuristic by keywords at start of lines
        static bool StartsWithToken(ReadOnlySpan<byte> l, string token) {
            var tb = System.Text.Encoding.ASCII.GetBytes(token);
            if (l.Length < tb.Length) return false;
            for (int i = 0; i < tb.Length; i++) if (char.ToUpperInvariant((char)l[i]) != char.ToUpperInvariant((char)tb[i])) return false;
            return true;
        }
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
        if (levelCount >= 2 || ((LooksLikeTimestamp(line1) || LooksLikeTimestamp(line2)) && levelCount >= 1)) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Low", Reason = "text:log", ReasonDetails = levelCount >= 2 ? $"log:levels-{levelCount}" : "log:timestamp+level" }; return true; }

        // PowerShell heuristic
        var hb = new byte[head.Length]; head.CopyTo(new System.Span<byte>(hb));
        var headStr = System.Text.Encoding.UTF8.GetString(hb);
        string headLower = headStr.ToLowerInvariant();
        if (headLower.Contains("[cmdletbinding]") || headLower.Contains("#requires") || headLower.Contains("param(") || headStr.IndexOf("Get-", System.StringComparison.Ordinal) >= 0 || headStr.IndexOf("Set-", System.StringComparison.Ordinal) >= 0 || headStr.IndexOf("Write-Host", System.StringComparison.Ordinal) >= 0) {
            result = new ContentTypeDetectionResult { Extension = "ps1", MimeType = "text/x-powershell", Confidence = "Low", Reason = "text:ps1", ReasonDetails = "ps1:common-cmdlets" }; return true;
        }

        // VBScript heuristic
        if (headLower.Contains("wscript.") || headLower.Contains("createobject(") || headLower.Contains("vbscript") || headLower.Contains("dim ") || headLower.Contains("end sub")) {
            result = new ContentTypeDetectionResult { Extension = "vbs", MimeType = "text/vbscript", Confidence = "Low", Reason = "text:vbs", ReasonDetails = "vbs:wscript+createobject" }; return true;
        }

        // Shell script heuristic
        if (headLower.Contains("#!/bin/sh") || headLower.Contains("#!/usr/bin/env sh") || headLower.Contains("#!/usr/bin/env bash") || headLower.Contains("#!/bin/bash") || headLower.Contains("#!/usr/bin/env zsh") || headLower.Contains("#!/bin/zsh")) {
            result = new ContentTypeDetectionResult { Extension = "sh", MimeType = "text/x-shellscript", Confidence = "Medium", Reason = "text:sh-shebang", ReasonDetails = "sh:shebang" }; return true;
        }
        // Weak shell cues when no shebang
        if ((headLower.Contains("set -e") || headLower.Contains("set -u")) && (headLower.Contains(" fi\n") || headLower.Contains(" esac\n") || headLower.Contains(" && "))) {
            result = new ContentTypeDetectionResult { Extension = "sh", MimeType = "text/x-shellscript", Confidence = "Low", Reason = "text:sh-heur", ReasonDetails = "sh:set+fi|esac|&&" }; return true;
        }

        // Windows batch (.bat/.cmd) heuristic
        if (headLower.Contains("@echo off") || (headLower.Contains("rem ") && (headLower.Contains(" set ") || headLower.Contains(" goto ") || headLower.Contains(" if ")))) {
            result = new ContentTypeDetectionResult { Extension = "bat", MimeType = "text/x-batch", Confidence = "Low", Reason = "text:bat", ReasonDetails = "bat:@echo|rem+set|goto|if" }; return true;
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

        // Lua heuristic
        if (headLower.Contains("#!/usr/bin/env lua") || headLower.Contains("#!/usr/bin/lua")) { result = new ContentTypeDetectionResult { Extension = "lua", MimeType = "text/x-lua", Confidence = "Medium", Reason = "text:lua-shebang", ReasonDetails = "lua:shebang" }; return true; }
        {
            int luaCues = 0;
            if (IndexOfToken(head, "local function ") >= 0) luaCues += 2;
            if (IndexOfToken(head, "function ") >= 0 && IndexOfToken(head, " end") >= 0) luaCues += 2;
            if (IndexOfToken(head, "require(") >= 0 || IndexOfToken(head, "require ") >= 0) luaCues++;
            if (IndexOfToken(head, " then") >= 0 && IndexOfToken(head, " end") >= 0) luaCues++;
            if (luaCues >= 2) { result = new ContentTypeDetectionResult { Extension = "lua", MimeType = "text/x-lua", Confidence = "Low", Reason = "text:lua-heur", ReasonDetails = $"lua:cues-{luaCues}" }; return true; }
        }

        // Fallback: treat as plain text if mostly printable
        int printable = 0; int sample = Math.Min(1024, src.Length);
        for (int i = 0; i < sample; i++) { byte b = src[i]; if (b == 9 || b == 10 || b == 13 || (b >= 32 && b < 127)) printable++; }
        if ((double)printable / sample > 0.95) { result = new ContentTypeDetectionResult { Extension = "txt", MimeType = "text/plain", Confidence = "Low", Reason = "text:plain" }; return true; }
        return false;

        static int Count(ReadOnlySpan<byte> l, byte ch) { int c = 0; for (int i = 0; i < l.Length; i++) if (l[i] == ch) c++; return c; }
        static bool IsDigit(byte b) => b >= (byte)'0' && b <= (byte)'9';
        static ReadOnlySpan<byte> TrimBytes(ReadOnlySpan<byte> s) {
            int a = 0; int b = s.Length - 1;
            while (a <= b && (s[a] == (byte)' ' || s[a] == (byte)'\t' || s[a] == (byte)'\r')) a++;
            while (b >= a && (s[b] == (byte)' ' || s[b] == (byte)'\t' || s[b] == (byte)'\r')) b--;
            return a <= b ? s.Slice(a, b - a + 1) : ReadOnlySpan<byte>.Empty;
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
            if (StartsWithToken(l, "[INFO]") || StartsWithToken(l, "[WARN]") || StartsWithToken(l, "[ERROR]") || StartsWithToken(l, "[DEBUG]")) return false;
            if (StartsWithToken(l, "INFO:") || StartsWithToken(l, "WARN:") || StartsWithToken(l, "ERROR:") || StartsWithToken(l, "DEBUG:")) return false;
            int cpos = l.IndexOf((byte)':'); if (cpos <= 0 || cpos > Math.Min(48, l.Length - 2)) return false;
            if (cpos + 1 < l.Length && l[cpos + 1] == (byte)'/') return false;
            int p = 0; while (p < l.Length && (l[p] == (byte)' ' || l[p] == (byte)'\t' || l[p] == (byte)'-')) p++;
            if (p >= l.Length) return false;
            if (!char.IsLetter((char)l[p])) return false;
            return true;
        }
        static bool StartsWithLevelToken(ReadOnlySpan<byte> l) {
            return StartsWithToken(l, "INFO") || StartsWithToken(l, "WARN") || StartsWithToken(l, "ERROR") || StartsWithToken(l, "DEBUG") || StartsWithToken(l, "TRACE") || StartsWithToken(l, "FATAL") || StartsWithToken(l, "[INFO]") || StartsWithToken(l, "[WARN]") || StartsWithToken(l, "[ERROR]") || StartsWithToken(l, "[DEBUG]");
        }
        static int IndexOfToken(ReadOnlySpan<byte> hay, string token) {
            var tb = System.Text.Encoding.ASCII.GetBytes(token);
            for (int i = 0; i + tb.Length <= hay.Length; i++) {
                bool m = true; for (int j = 0; j < tb.Length; j++) { if (char.ToLowerInvariant((char)hay[i + j]) != char.ToLowerInvariant((char)tb[j])) { m = false; break; } }
                if (m) return i;
            }
            return -1;
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
