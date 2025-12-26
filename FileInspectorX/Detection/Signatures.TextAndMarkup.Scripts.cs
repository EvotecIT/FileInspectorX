namespace FileInspectorX;

internal static partial class Signatures
{
    private static bool TryDetectScriptsAndPlainText(
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> head,
        string headStr,
        string headLower,
        string decl,
        bool declaredMd,
        bool declaredCmd,
        bool bomDetected,
        string? textCharset,
        out ContentTypeDetectionResult? result)
    {
        result = null;

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
            bool hasGetSet = headStr.IndexOf("Get-", System.StringComparison.OrdinalIgnoreCase) >= 0 || headStr.IndexOf("Set-", System.StringComparison.OrdinalIgnoreCase) >= 0;
            if (hasGetSet) cues++;
            if (hasVerbNoun) { cues++; strong++; }
            if (hasPipeline) { cues++; strong++; }

            // Module/data file special-cases
            if (declaredPsm1 && (hasModuleExport || hasVerbNoun))
            {
                result = new ContentTypeDetectionResult { Extension = "psm1", MimeType = "text/x-powershell", Confidence = "Medium", Reason = "text:psm1", ReasonDetails = "psm1:module-cues" };
                return true;
            }
            if (declaredPsd1 && (psd1Hashtable || hasModuleExport))
            {
                result = new ContentTypeDetectionResult { Extension = "psd1", MimeType = "text/x-powershell", Confidence = "Low", Reason = "text:psd1", ReasonDetails = psd1Hashtable ? "psd1:hashtable" : "psd1:module-keys" };
                return true;
            }

            if (cues >= 2 || (cues >= 1 && strong >= 1)) {
                var conf = cues >= 3 ? "Medium" : "Low";
                var details = cues >= 3 ? "ps1:multi-cues" : (strong >= 1 && cues == 1 ? "ps1:single-strong-cue" : "ps1:common-cmdlets");
                result = new ContentTypeDetectionResult { Extension = "ps1", MimeType = "text/x-powershell", Confidence = conf, Reason = "text:ps1", ReasonDetails = details };
                return true;
            }
        }

        // VBScript heuristic
        if (LooksLikeVbsScript(headLower)) {
            var conf = (headLower.Contains("option explicit") || headLower.Contains("on error resume next") || headLower.Contains("createobject(") || headLower.Contains("wscript.")) ? "Medium" : "Low";
            result = new ContentTypeDetectionResult { Extension = "vbs", MimeType = "text/vbscript", Confidence = conf, Reason = "text:vbs", ReasonDetails = conf == "Medium" ? "vbs:explicit+error|createobject" : "vbs:wscript+dim|msgbox" };
            return true;
        }

        // Shell script heuristic
        if (headLower.Contains("#!/bin/sh") || headLower.Contains("#!/usr/bin/env sh") || headLower.Contains("#!/usr/bin/env bash") || headLower.Contains("#!/bin/bash") || headLower.Contains("#!/usr/bin/env zsh") || headLower.Contains("#!/bin/zsh")) {
            result = new ContentTypeDetectionResult { Extension = "sh", MimeType = "text/x-shellscript", Confidence = "Medium", Reason = "text:sh-shebang", ReasonDetails = "sh:shebang" };
            return true;
        }
        // Node.js shebang
        if (headLower.Contains("#!/usr/bin/env node") || headLower.Contains("#!/usr/bin/node")) { result = new ContentTypeDetectionResult { Extension = "js", MimeType = "application/javascript", Confidence = "Medium", Reason = "text:node-shhebang", ReasonDetails = "js:shebang" }; return true; }
        // JavaScript heuristic (non-minified). Avoid misclassifying Lua where "local function" is common.
        if (LooksLikeJavaScript(headStr, headLower)) {
            if (!(head.Length > 0 && (head[0] == (byte)'{' || head[0] == (byte)'[')))
                { result = new ContentTypeDetectionResult { Extension = "js", MimeType = "application/javascript", Confidence = "Low", Reason = "text:js-heur" }; }
            return result != null;
        }
        // Weak shell cues when no shebang
        if ((headLower.Contains("set -e") || headLower.Contains("set -u") || headLower.Contains("export ") || headLower.Contains("[[") || headLower.Contains("]]")) &&
            (headLower.Contains(" fi\n") || headLower.Contains(" esac\n") || headLower.Contains(" && ") || headLower.Contains(" case ") || headLower.Contains("  do\n"))) {
            result = new ContentTypeDetectionResult { Extension = "sh", MimeType = "text/x-shellscript", Confidence = "Low", Reason = "text:sh-heur", ReasonDetails = "sh:set|export+fi|esac|case|&&|do" };
            return true;
        }

        // Windows batch (.bat/.cmd) heuristic
        if (headLower.Contains("@echo off") || headLower.Contains("setlocal") || headLower.Contains("endlocal") ||
            headLower.Contains("\ngoto ") || headLower.Contains("\r\ngoto ") ||
            headLower.Contains(" goto ") ||
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
            if (!string.IsNullOrEmpty(textCharset)) mime += "; charset=" + textCharset;
            var reason = bomDetected ? "bom:text-plain" : "text:plain";
            result = new ContentTypeDetectionResult { Extension = "txt", MimeType = mime, Confidence = "Low", Reason = reason };
            return true;
        }

        return false;
    }

    private static bool HasPowerShellCues(ReadOnlySpan<byte> headSpan, string s, string sl)
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

    private static bool HasVerbNounCmdlet(string s)
    {
        // quick token scan to avoid regex and allocations
        var span = s.AsSpan();
        int i = 0;
        while (i < span.Length) {
            while (i < span.Length && IsSep(span[i])) i++;
            int start = i;
            while (i < span.Length && !IsSep(span[i])) i++;
            int len = i - start;
            if (len == 0)
            {
                if (i < span.Length) i++;
                continue;
            }
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

    private static bool LooksLikeVbsScript(string lower)
    {
        return lower.Contains("wscript.") || lower.Contains("wscript.echo") ||
               lower.Contains("createobject(") || lower.Contains("vbscript") ||
               lower.Contains("dim ") || lower.Contains("end sub") ||
               lower.Contains("option explicit") || lower.Contains("on error resume next") ||
               lower.Contains("msgbox");
    }

    private static bool LooksLikeJavaScript(string s, string sl)
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

    private static bool LooksLikeJsCallPrefix(string s)
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

    private static bool IsIdentStart(char c) => char.IsLetter(c) || c == '_' || c == '$';
    private static bool IsIdentPart(char c) => char.IsLetterOrDigit(c) || c == '_' || c == '$';
}
