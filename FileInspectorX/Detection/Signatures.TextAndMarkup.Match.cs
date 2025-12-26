namespace FileInspectorX;

internal static partial class Signatures
{
    private readonly ref struct TextContext
    {
        public readonly ReadOnlySpan<byte> Data;
        public readonly ReadOnlySpan<byte> Head;
        public readonly string HeadStr;
        public readonly string HeadLower;
        public readonly string Decl;
        public readonly bool DeclaredMd;
        public readonly bool DeclaredLog;
        public readonly bool DeclaredIni;
        public readonly bool DeclaredInf;
        public readonly bool DeclaredToml;
        public readonly bool DeclaredAdmx;
        public readonly bool DeclaredAdml;
        public readonly bool DeclaredCmd;
        public readonly bool BomDetected;
        public readonly string? TextCharset;
        public readonly bool LooksMarkup;
        public readonly bool PsCues;
        public readonly bool VbsCues;
        public readonly bool JsCues;
        public readonly bool ShShebang;
        public readonly bool BatCues;
        public readonly bool ScriptCues;

        public TextContext(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> head,
            string headStr,
            string headLower,
            string decl,
            bool declaredMd,
            bool declaredLog,
            bool declaredIni,
            bool declaredInf,
            bool declaredToml,
            bool declaredAdmx,
            bool declaredAdml,
            bool declaredCmd,
            bool bomDetected,
            string? textCharset,
            bool looksMarkup,
            bool psCues,
            bool vbsCues,
            bool jsCues,
            bool shShebang,
            bool batCues,
            bool scriptCues)
        {
            Data = data;
            Head = head;
            HeadStr = headStr;
            HeadLower = headLower;
            Decl = decl;
            DeclaredMd = declaredMd;
            DeclaredLog = declaredLog;
            DeclaredIni = declaredIni;
            DeclaredInf = declaredInf;
            DeclaredToml = declaredToml;
            DeclaredAdmx = declaredAdmx;
            DeclaredAdml = declaredAdml;
            DeclaredCmd = declaredCmd;
            BomDetected = bomDetected;
            TextCharset = textCharset;
            LooksMarkup = looksMarkup;
            PsCues = psCues;
            VbsCues = vbsCues;
            JsCues = jsCues;
            ShShebang = shShebang;
            BatCues = batCues;
            ScriptCues = scriptCues;
        }
    }

    internal static bool TryMatchText(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result, string? declaredExtension = null)
    {
        result = null;
        if (src.Length == 0) return false;
        byte[]? transcodeBytes = null;
        char[]? transcodeChars = null;
        try
        {
            if (!TryPrepareTextContext(src, declaredExtension, ref transcodeBytes, ref transcodeChars, out var ctx))
                return false;

            if (TryDetectRtf(in ctx, out result))
                return FinalizeResult(ref result, in ctx);

            if (TryDetectEncodedBlocks(in ctx, out result))
                return FinalizeResult(ref result, in ctx);

            if (TryDetectStructuredText(in ctx, out result))
                return FinalizeResult(ref result, in ctx);

            if (TryDetectLogAndDelimitedText(in ctx, out result))
                return FinalizeResult(ref result, in ctx);

            if (TryDetectScriptsAndPlainText(ctx.Data, ctx.Head, ctx.HeadStr, ctx.HeadLower, ctx.Decl, ctx.DeclaredMd, ctx.DeclaredCmd, ctx.BomDetected, ctx.TextCharset, out result))
                return FinalizeResult(ref result, in ctx);

            return FinalizeResult(ref result, in ctx);
        }
        finally
        {
            if (transcodeBytes != null) ArrayPool<byte>.Shared.Return(transcodeBytes, clearArray: true);
            if (transcodeChars != null) ArrayPool<char>.Shared.Return(transcodeChars, clearArray: true);
        }
    }

    private static bool TryPrepareTextContext(
        ReadOnlySpan<byte> src,
        string? declaredExtension,
        ref byte[]? transcodeBytes,
        ref char[]? transcodeChars,
        out TextContext ctx)
    {
        ctx = default;
        int headerBytes = GetHeaderBytes();

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
                if (nulRatio >= UTF_NUL_RATIO_MIN)
                {
                    if (nulOdd > nulEven * UTF16_NUL_DOMINANCE_FACTOR)
                    {
                        transcodeEnc = new System.Text.UnicodeEncoding(false, false, true);
                        transcodeBytesPerChar = 2;
                        textCharset = "utf-16le";
                    }
                    else if (nulEven > nulOdd * UTF16_NUL_DOMINANCE_FACTOR)
                    {
                        transcodeEnc = new System.Text.UnicodeEncoding(true, false, true);
                        transcodeBytesPerChar = 2;
                        textCharset = "utf-16be";
                    }
                    else if (nulRatio >= UTF32_NUL_RATIO_MIN)
                    {
                        int nonNullTotal = nonNullPos4[0] + nonNullPos4[1] + nonNullPos4[2] + nonNullPos4[3];
                        int maxPos = 0;
                        for (int i = 1; i < 4; i++) if (nonNullPos4[i] > nonNullPos4[maxPos]) maxPos = i;
                        if (nonNullTotal > 0 && nonNullPos4[maxPos] >= (int)(nonNullTotal * UTF32_NONNULL_POS_DOMINANCE))
                        {
                            if (maxPos == 0)
                            {
                                transcodeEnc = new System.Text.UTF32Encoding(false, false, true);
                                transcodeBytesPerChar = 4;
                                textCharset = "utf-32le";
                            }
                            else if (maxPos == 3)
                            {
                                transcodeEnc = new System.Text.UTF32Encoding(true, false, true);
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
                if (bomCharset == "utf-16le") { enc = new System.Text.UnicodeEncoding(false, true, true); bytesPerChar = 2; }
                else if (bomCharset == "utf-16be") { enc = new System.Text.UnicodeEncoding(true, true, true); bytesPerChar = 2; }
                else if (bomCharset == "utf-32le") { enc = new System.Text.UTF32Encoding(false, true, true); bytesPerChar = 4; }
                else if (bomCharset == "utf-32be") { enc = new System.Text.UTF32Encoding(true, true, true); bytesPerChar = 4; }
                else { enc = transcodeEnc!; bytesPerChar = transcodeBytesPerChar; }

                int decodeBudget = headerBytes * bytesPerChar;
                int remaining = src.Length - bomSkip;
                int maxBytes = Math.Min(remaining, decodeBudget);
                if (maxBytes <= bytesPerChar) return false;
                int mod = maxBytes % bytesPerChar;
                if (mod != 0) maxBytes -= mod;

                byte[]? rented = null;
                try
                {
                    rented = ArrayPool<byte>.Shared.Rent(maxBytes);
                    src.Slice(bomSkip, maxBytes).CopyTo(rented);
                    int charCount = enc.GetCharCount(rented, 0, maxBytes);
                    if (charCount <= 0) return false;
                    transcodeChars = ArrayPool<char>.Shared.Rent(charCount);
                    int charsDecoded = enc.GetChars(rented, 0, maxBytes, transcodeChars, 0);
                    if (charsDecoded <= 0) return false;
                    int utf8BytesNeeded = System.Text.Encoding.UTF8.GetByteCount(transcodeChars, 0, charsDecoded);
                    if (utf8BytesNeeded <= 0) return false;
                    transcodeBytes = ArrayPool<byte>.Shared.Rent(utf8BytesNeeded);
                    int bytesWritten = System.Text.Encoding.UTF8.GetBytes(transcodeChars, 0, charsDecoded, transcodeBytes, 0);
                    if (bytesWritten <= 0) return false;
                    data = transcodeBytes.AsSpan(0, bytesWritten);
                }
                finally
                {
                    if (rented != null) ArrayPool<byte>.Shared.Return(rented, clearArray: true);
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
        var head = data.Slice(start, Math.Min(headerBytes, data.Length - start));

        var headStr = Utf8(head);
        var headLower = headStr.ToLowerInvariant();
        bool looksMarkup = head.IndexOf((byte)'<') >= 0 && head.IndexOf((byte)'>') >= 0;

        bool psCues = HasPowerShellCues(head, headStr, headLower) || HasVerbNounCmdlet(headStr);
        bool vbsCues = LooksLikeVbsScript(headLower);
        bool jsCues = LooksLikeJavaScript(headStr, headLower);
        bool shShebang = headLower.Contains("#!/bin/sh") || headLower.Contains("#!/usr/bin/env sh") ||
                         headLower.Contains("#!/usr/bin/env bash") || headLower.Contains("#!/bin/bash") ||
                         headLower.Contains("#!/usr/bin/env zsh") || headLower.Contains("#!/bin/zsh");
        bool batCues = headLower.Contains("@echo off") || headLower.Contains("setlocal") || headLower.Contains("endlocal") ||
                       headLower.Contains("\ngoto ") || headLower.Contains("\r\ngoto ") || headLower.Contains(" goto ") ||
                       headLower.StartsWith("rem ") || headLower.Contains("\nrem ") || headLower.Contains("\r\nrem ") || headLower.Contains(":end");
        bool scriptCues = psCues || vbsCues || jsCues || shShebang || batCues;

        ctx = new TextContext(
            data,
            head,
            headStr,
            headLower,
            decl,
            declaredMd,
            declaredLog,
            declaredIni,
            declaredInf,
            declaredToml,
            declaredAdmx,
            declaredAdml,
            declaredCmd,
            bomDetected,
            textCharset,
            looksMarkup,
            psCues,
            vbsCues,
            jsCues,
            shShebang,
            batCues,
            scriptCues);

        return true;
    }

    private static bool FinalizeResult(ref ContentTypeDetectionResult? result, in TextContext ctx)
    {
        if (result == null) return false;
        result = AttachAlternatives(result, ctx.Head, ctx.HeadStr, ctx.HeadLower, ctx.Decl);
        return true;
    }
}
