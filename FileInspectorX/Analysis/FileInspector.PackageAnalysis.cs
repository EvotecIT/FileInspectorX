using System.IO.Compression;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace FileInspectorX;

public static partial class FileInspector
{
    private static void TryPopulateAppxSignature(string path, FileAnalysis res)
    {
#if NET8_0_OR_GREATER || NET472
        var budget = ArchiveInspectionBudget.FromSettings();
        try {
            using var fs = OperationReadStream.Open(path);
            if (!budget.CheckCentralDirectory(fs, out _)) return;
            using var za = new ZipArchive(fs, ZipArchiveMode.Read, leaveOpen: true);
            var sigEntry = za.GetEntry("AppxSignature.p7x") ?? za.GetEntry("AppxSignature.p7s");
            if (sigEntry == null) return;
            var data = budget.ReadBytes(sigEntry);
            if (data == null || data.Length == 0) return;
            var cms = new System.Security.Cryptography.Pkcs.SignedCms();
            cms.Decode(data);
            var ai = res.Authenticode ?? new AuthenticodeInfo();
            ai.Present = true;
            ai.VerificationNote = "Package signature (AppxSignature)";
            var signer = cms.SignerInfos.Count > 0 ? cms.SignerInfos[0] : null;
            var cert = signer?.Certificate;
            if (cert != null)
            {
                ai.SignerSubject = cert.Subject; ai.SignerIssuer = cert.Issuer; ai.SignatureAlgorithm = cert.SignatureAlgorithm?.FriendlyName;
                ai.NotBefore = cert.NotBefore; ai.NotAfter = cert.NotAfter; ai.DigestAlgorithm = signer?.DigestAlgorithm?.FriendlyName;
                ai.SignerThumbprint = cert.Thumbprint; ai.SignerSerialHex = cert.SerialNumber; FillCertFields(cert, ai);
                try { var ch = new System.Security.Cryptography.X509Certificates.X509Chain(); ch.ChainPolicy.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck; ai.ChainValid = ch.Build(cert); } catch { }
                try { cms.CheckSignature(true); ai.EnvelopeSignatureValid = true; } catch { ai.EnvelopeSignatureValid = false; }
            }
            res.Authenticode = ai;
        } catch (OutOfMemoryException) { throw; }
        catch { }
        finally { ApplyArchiveInspectionBudget(res, budget); }
#endif
    }

    private static string ReadFirstLine(string path, int max) {
        try {
            using var sr = new StreamReader(OperationReadStream.Open(path));
            char[] buf = new char[Math.Max(2, max)];
            int n = sr.Read(buf, 0, buf.Length);
            var s = new string(buf, 0, n);
            int nl = s.IndexOf('\n');
            return nl >= 0 ? s.Substring(0, nl) : s;
        } catch { return string.Empty; }
    }

    private static string MapShebang(string line) {
        var l = line.ToLowerInvariant();
        if (l.Contains("bash")) return "bash";
        if (l.Contains("sh")) return "sh";
        if (l.Contains("python")) return "python";
        if (l.Contains("node")) return "javascript";
        if (l.Contains("pwsh") || l.Contains("powershell")) return "powershell";
        if (l.Contains("perl")) return "perl";
        if (l.Contains("ruby")) return "ruby";
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

    private static bool LooksMinifiedJs(string path, int cap, int minLen, int avgLineThreshold, double densityThreshold, string? headText = null) {
        try {
            var text = headText ?? ReadHeadText(path, Math.Min(cap, 512 * 1024));
            if (string.IsNullOrEmpty(text) || text.Length < minLen) return false;
            int lines = 1; for (int i = 0; i < text.Length; i++) if (text[i] == '\n') lines++;
            int nonWs = 0; for (int i = 0; i < text.Length; i++) { char c = text[i]; if (!char.IsWhiteSpace(c)) nonWs++; }
            double avgLineLen = (double)text.Length / Math.Max(1, lines);
            double density = (double)nonWs / text.Length; // closer to 1 => denser
            // Heuristic thresholds: long lines, few line breaks, high density
            return (avgLineLen > avgLineThreshold && lines < text.Length / 300 && density > densityThreshold);
        } catch { return false; }
    }

    private static int? EstimateLines(string path, int cap) {
        try {
            using var fs = OperationReadStream.Open(path);
            long len = Math.Min(fs.Length, cap);
            var buf = new byte[(int)len];
            int n = fs.Read(buf, 0, buf.Length);
            if (n <= 0) return 0;
            int lines = 0; for (int i = 0; i < n; i++) if (buf[i] == (byte)'\n') lines++;
            if (fs.Length > n && n > 0) {
                double ratio = (double)fs.Length / n;
                lines = (int)Math.Round(lines * ratio);
            }
            return lines;
        } catch { return null; }
    }

    private static bool ContainsIgnoreCase(string s, string needle) {
        if (string.IsNullOrEmpty(s) || string.IsNullOrEmpty(needle)) return false;
        return s.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static bool IsPe(string path, out string? machine, out string? subsystem, out bool hasClr, out bool hasSec) {
        machine = null; subsystem = null; hasClr = false; hasSec = false;
        try {
            using var fs = OperationReadStream.Open(path);
            var br = new BinaryReader(fs);
            if (fs.Length < 0x40) return false;
            if (br.ReadByte() != 0x4D || br.ReadByte() != 0x5A) return false; // MZ
            fs.Seek(0x3C, SeekOrigin.Begin);
            int e_lfanew = br.ReadInt32();
            if (e_lfanew <= 0 || e_lfanew > fs.Length - 256) return false;
            fs.Seek(e_lfanew, SeekOrigin.Begin);
            if (br.ReadByte() != (byte)'P' || br.ReadByte() != (byte)'E' || br.ReadByte() != 0 || br.ReadByte() != 0) return false;
            ushort mach = br.ReadUInt16();
            machine = mach switch { 0x014c => "x86", 0x8664 => "x86_64", 0x01c0 => "arm", 0xaa64 => "aarch64", _ => "unknown" };
            br.ReadUInt16(); // NumberOfSections
            br.ReadUInt32(); // TimeDateStamp
            br.ReadUInt32(); // PointerToSymbolTable
            br.ReadUInt32(); // NumberOfSymbols
            ushort sizeOptionalHeader = br.ReadUInt16();
            br.ReadUInt16(); // Characteristics
            long optStart = fs.Position;
            ushort magic = br.ReadUInt16();
            bool isPlus = magic == 0x20b;
            int subsysOffset = isPlus ? 0x5C : 0x44;
            fs.Seek(optStart + subsysOffset, SeekOrigin.Begin);
            ushort subsys = br.ReadUInt16();
            subsystem = subsys switch { 2 => "Windows GUI", 3 => "Windows CUI", 9 => "Windows CE", _ => "unknown" };
            int ddOffset = isPlus ? 0x70 : 0x60;
            fs.Seek(optStart + ddOffset, SeekOrigin.Begin);
            uint va, sz;
            for (int i = 0; i < 16; i++) {
                va = br.ReadUInt32(); sz = br.ReadUInt32();
                if (i == 4) hasSec = sz != 0; // Security
                if (i == 14) hasClr = sz != 0; // CLR
            }
            return true;
        } catch { return false; }
    }
}
