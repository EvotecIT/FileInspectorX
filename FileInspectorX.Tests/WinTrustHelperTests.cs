using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;
using FileInspectorX;
using Xunit;

namespace FileInspectorX.Tests;

public class WinTrustHelperTests
{
    private const int VerificationIterations = 50; // stress repeated interop calls without retaining trust decisions

    [Fact]
    public void VerifyFileSignature_UnsignedFile_NotTrusted_And_DoesNotThrow()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return;

        var temp = Path.GetTempFileName();
        try
        {
            // Write a small random file to ensure it's not signed
            File.WriteAllBytes(temp, new byte[] { 0x01, 0x02, 0x03, 0x04 });
            for (int i = 0; i < VerificationIterations; i++)
            {
                bool? trusted = FileInspector.VerifyAuthenticodePolicy(temp);
                // Unsigned files should not be trusted; API may return null (no signature) or false.
                Assert.False(trusted == true);
            }
        }
        finally
        {
            TestHelpers.SafeDelete(temp);
        }
    }

    [Fact]
    public void Inspect_SystemCatalogSigned_Binary_Is_Treated_As_Signed()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return;

        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
        if (!File.Exists(path))
            return;

        if (!IsValidAuthenticodeSample(path))
            return;

        var analysis = FileInspector.Inspect(path);
        var status = FileInspector.GetSignatureStatus(analysis);
        var assessment = analysis.Assessment ?? FileInspector.Assess(analysis);

        Assert.Equal("exe", analysis.Detection?.Extension);
        Assert.NotNull(analysis.Authenticode);
        Assert.True(analysis.Authenticode!.IsTrustedWindowsPolicy == true);
        Assert.True(status?.IsSigned == true);
        Assert.True(status?.IsValid == true);
        Assert.DoesNotContain("Sig.Absent", assessment.Codes);
    }

    [Fact]
    public void Inspect_SystemCatalogSigned_Binary_Respects_VerifyAuthenticodeWithWinTrust_Setting()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return;

        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
        if (!File.Exists(path))
            return;

        if (!IsValidAuthenticodeSample(path))
            return;

        var oldSetting = Settings.VerifyAuthenticodeWithWinTrust;
        try
        {
            Settings.VerifyAuthenticodeWithWinTrust = false;

            var analysis = FileInspector.Inspect(path);

            Assert.True(
                analysis.Authenticode == null ||
                (!analysis.Authenticode.IsTrustedWindowsPolicy.HasValue &&
                 (analysis.Authenticode.VerificationNote ?? string.Empty).IndexOf("WinTrust", StringComparison.OrdinalIgnoreCase) < 0));
        }
        finally
        {
            Settings.VerifyAuthenticodeWithWinTrust = oldSetting;
        }
    }

    [Fact]
    public void VerifyAuthenticodePolicy_DoesNotReuseTrust_AfterContentChanges()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return;

        var source = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
        if (!File.Exists(source) || !IsValidAuthenticodeSample(source))
            return;

        var temp = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".exe");
        try
        {
            File.Copy(source, temp);
            if (FileInspector.VerifyAuthenticodePolicy(temp) != true)
                return;

            var timestamp = File.GetLastWriteTimeUtc(temp);
            using (var stream = new FileStream(temp, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                var offset = Math.Min(1024L, Math.Max(0L, stream.Length - 1));
                stream.Position = offset;
                var value = stream.ReadByte();
                Assert.NotEqual(-1, value);
                stream.Position = offset;
                stream.WriteByte((byte)(value ^ 0x01));
            }
            File.SetLastWriteTimeUtc(temp, timestamp);

            Assert.False(FileInspector.VerifyAuthenticodePolicy(temp) == true);
        }
        finally
        {
            TestHelpers.SafeDelete(temp);
        }
    }

    private static bool IsValidAuthenticodeSample(string path)
    {
        var script = "(Get-AuthenticodeSignature -LiteralPath '" + path.Replace("'", "''") + "').Status";
        foreach (var shell in new[] { "pwsh", "powershell.exe" })
        {
            var fullScript = shell.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase)
                ? "Import-Module Microsoft.PowerShell.Security; " + script
                : script;
            var psi = new ProcessStartInfo
            {
                FileName = shell,
                Arguments = "-NoProfile -NonInteractive -Command \"" + fullScript + "\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            try
            {
                using var process = Process.Start(psi);
                if (process == null) continue;
                if (!process.WaitForExit(5000))
                {
                    try { process.Kill(); } catch { }
                    continue;
                }

                if (process.ExitCode != 0) continue;
                var output = process.StandardOutput.ReadToEnd().Trim();
                if (string.Equals(output, "Valid", StringComparison.OrdinalIgnoreCase)) return true;
            }
            catch
            {
                // Try the next shell.
            }
        }

        return false;
    }
}

