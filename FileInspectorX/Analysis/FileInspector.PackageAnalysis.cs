using System.IO.Compression;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace FileInspectorX;

public static partial class FileInspector
{
    private static void TryPopulateAppxSignature(InspectionInput input, FileAnalysis res, DetectionOptions? options)
    {
        var path = input.Name;
#if NET8_0_OR_GREATER || NET472
        var budget = ArchiveInspectionBudget.FromSettings();
        try {
            using var fs = input.OpenRead();
            if (!budget.CheckCentralDirectory(fs, out _)) return;
            using var za = new ZipArchive(fs, ZipArchiveMode.Read, leaveOpen: true);
            var sigEntry = za.GetEntry("AppxSignature.p7x") ?? za.GetEntry("AppxSignature.p7s");
            if (sigEntry == null) return;
            var data = budget.ReadBytes(sigEntry);
            if (data == null || data.Length == 0) return;
            if (sigEntry.FullName.EndsWith(".p7x", StringComparison.OrdinalIgnoreCase))
            {
                // P7X wraps the DER SignedData in a four-byte package signature marker.
                if (data.Length <= 4 || data[0] != 'P' || data[1] != 'K' || data[2] != 'C' || data[3] != 'X')
                    throw new InvalidDataException("Invalid P7X signature marker.");
                var envelope = new byte[data.Length - 4];
                Buffer.BlockCopy(data, 4, envelope, 0, envelope.Length);
                data = envelope;
            }
            var cms = new System.Security.Cryptography.Pkcs.SignedCms();
            cms.Decode(data);
            if (cms.SignerInfos.Count == 0) throw new InvalidDataException("The package signature has no signer.");
            var ai = res.Authenticode ?? new AuthenticodeInfo();
            ai.Present = true;
            ai.VerificationNote = "Package signature envelope; package content digest not verified";
            var signer = cms.SignerInfos.Count > 0 ? cms.SignerInfos[0] : null;
            var cert = signer?.Certificate;
            if (cert != null)
            {
                ai.SignerSubject = cert.Subject; ai.SignerIssuer = cert.Issuer; ai.SignatureAlgorithm = cert.SignatureAlgorithm?.FriendlyName;
                ai.NotBefore = cert.NotBefore; ai.NotAfter = cert.NotAfter; ai.DigestAlgorithm = signer?.DigestAlgorithm?.FriendlyName;
                ai.SignerThumbprint = cert.Thumbprint; ai.SignerSerialHex = cert.SerialNumber; FillCertFields(cert, ai);
                ai.ChainValid = TryBuildCertificateChain(cert, options, res, out _);
                try { cms.CheckSignature(true); ai.EnvelopeSignatureValid = true; } catch { ai.EnvelopeSignatureValid = false; }
            }
            res.Authenticode = ai;
        } catch (OutOfMemoryException) { throw; }
        catch (Exception ex) when (ex is not OutOfMemoryException and not OperationCanceledException)
        { budget.AddIssue("archive:package-signature-unavailable"); }
        finally { ApplyArchiveInspectionBudget(res, budget); }
#endif
    }

    private static string ReadFirstLine(InspectionInput input, int max) {
        var path = input.Name;
        try {
            using var sr = new StreamReader(input.OpenRead());
            char[] buf = new char[Math.Max(2, max)];
            int n = sr.ReadBlock(buf, 0, buf.Length);
            var s = new string(buf, 0, n);
            int nl = s.IndexOf('\n');
            return nl >= 0 ? s.Substring(0, nl) : s;
        } catch { return string.Empty; }
    }

    private static string MapShebang(string line) {
        var tokens = line.Substring(2).Trim().Split(new[] { ' ', '\t', '\r' }, StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length == 0) return "unknown";
        int interpreterIndex = 0;
        if (System.IO.Path.GetFileName(tokens[0]) == "env")
        {
            interpreterIndex++;
            while (interpreterIndex < tokens.Length && (tokens[interpreterIndex].StartsWith("-", StringComparison.Ordinal) || tokens[interpreterIndex].IndexOf('=') >= 0))
                interpreterIndex++;
        }
        if (interpreterIndex >= tokens.Length) return "unknown";
        var interpreter = System.IO.Path.GetFileName(tokens[interpreterIndex]).ToLowerInvariant();
        if (interpreter is "pwsh" or "powershell") return "powershell";
        if (interpreter == "bash") return "bash";
        if (interpreter is "sh" or "zsh" or "ksh") return "sh";
        if (interpreter.StartsWith("python", StringComparison.Ordinal)) return "python";
        if (interpreter is "node" or "nodejs") return "javascript";
        if (interpreter == "perl") return "perl";
        if (interpreter == "ruby") return "ruby";
        return "unknown";
    }

    private static string? MapScriptLanguageFromExtension(string? ext)
    {
        if (string.IsNullOrWhiteSpace(ext)) return null;
        var e = ext!.Trim().TrimStart('.').ToLowerInvariant();
        return e switch
        {
            "ps1" or "psm1" or "psd1" => "powershell",
            "js" or "jse" or "mjs" or "cjs" => "javascript",
            "vbs" or "vbe" or "wsf" or "wsh" => "vbscript",
            "py" or "pyw" => "python",
            "rb" => "ruby",
            "lua" => "lua",
            "sh" or "bash" or "zsh" or "ksh" => "shell",
            "bat" or "cmd" => "batch",
            "pl" => "perl",
            _ => null
        };
    }

    private static bool LooksMinifiedJs(InspectionInput input, int cap, int minLen, int avgLineThreshold, double densityThreshold, string? headText = null) {
        var path = input.Name;
        try {
            var text = headText ?? ReadHeadText(input, Math.Min(cap, 512 * 1024));
            if (string.IsNullOrEmpty(text) || text.Length < minLen) return false;
            int lines = 1; for (int i = 0; i < text.Length; i++) if (text[i] == '\n') lines++;
            int nonWs = 0; for (int i = 0; i < text.Length; i++) { char c = text[i]; if (!char.IsWhiteSpace(c)) nonWs++; }
            double avgLineLen = (double)text.Length / Math.Max(1, lines);
            double density = (double)nonWs / text.Length; // closer to 1 => denser
            // Heuristic thresholds: long lines, few line breaks, high density
            return (avgLineLen > avgLineThreshold && lines < text.Length / 300 && density > densityThreshold);
        } catch { return false; }
    }

    private static int? EstimateLines(InspectionInput input, int cap) {
        var path = input.Name;
        try {
            using var fs = input.OpenRead();
            long len = Math.Min(fs.Length, cap);
            var buf = new byte[(int)len];
            int n = ReadAvailable(fs, buf, 0, buf.Length);
            if (n <= 0) return 0;
            int lines = 0; for (int i = 0; i < n; i++) if (buf[i] == (byte)'\n') lines++;
            if (fs.Length > n && n > 0) {
                double ratio = (double)fs.Length / n;
                lines = (int)Math.Round(lines * ratio);
            }
            return lines;
        } catch { return null; }
    }

}
