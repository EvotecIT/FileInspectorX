using Xunit;

namespace FileInspectorX.Tests;

public class NameAndTextDetectionRegressionTests
{
    [Fact]
    public void Analyze_PathErrorLog_Detects_Log_Not_Yaml()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".log");
        try
        {
            File.WriteAllText(p, """
                D:\Users\test.1: Access is denied.
                D:\Users\All Users\ntuser.pol: Access is denied.
                D:\Users\All Users\Packages: Access is denied.
                D:\Users\All Users\Application Data\*: Access is denied.
                """);

            var a = FileInspector.Analyze(p);

            Assert.Equal("log", a.DetectedExtension);
            Assert.Equal("log", a.TextSubtype);
            Assert.NotEqual("text:yaml-keys", a.DetectionReason);
            Assert.DoesNotContain("yaml", a.DetectionReason ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            try { File.Delete(p); } catch { }
        }
    }

    [Fact]
    public void Analyze_VersionedInstallerName_DoesNotFlagDoubleExtension()
    {
        var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var p = Path.Combine(dir, "Codex.Monitor_0.7.56_x64_en-US.msi");
        try
        {
            File.WriteAllBytes(p, new byte[] { 0xD0, 0xCF, 0x11, 0xE0 });

            var a = FileInspector.Analyze(p);

            Assert.Equal(NameIssues.None, a.NameIssues & NameIssues.DoubleExtension);
        }
        finally
        {
            try { File.Delete(p); } catch { }
            try { Directory.Delete(dir, false); } catch { }
        }
    }

    [Fact]
    public void Analyze_DisguisedExecutableName_StillFlagsDoubleExtension()
    {
        var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var p = Path.Combine(dir, "Quarterly.Report.pdf.exe");
        try
        {
            File.WriteAllBytes(p, new byte[] { 0x4D, 0x5A, 0x90, 0x00 });

            var a = FileInspector.Analyze(p);

            Assert.NotEqual(NameIssues.None, a.NameIssues & NameIssues.DoubleExtension);
        }
        finally
        {
            try { File.Delete(p); } catch { }
            try { Directory.Delete(dir, false); } catch { }
        }
    }
}
