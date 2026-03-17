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
    public void Analyze_EventViewerTextExport_WithSparseNuls_Detects_Log()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".log");
        try
        {
            File.WriteAllBytes(p, System.Text.Encoding.UTF8.GetBytes(
                "Event[0]\r\n" +
                "  Log Name: Application\r\n" +
                "  Source: Example.Service\r\n" +
                "  Date: 2026-03-17T09:03:12.7750000Z\r\n" +
                "  Event ID: 0\r\n" +
                "  Task: None\0\r\n" +
                "  Level: Error\0\r\n" +
                "  Opcode: Info\0\0\r\n" +
                "  Keyword: Classic,\0\r\n" +
                "  User: N/A\r\n" +
                "  Computer: HOST.example\r\n" +
                "  Description:\r\n" +
                "Example failure text\r\n"));

            var a = FileInspector.Analyze(p);

            Assert.Equal("log", a.DetectedExtension);
            Assert.Equal("log", a.TextSubtype);
            Assert.Equal("text:event-txt", a.DetectionReason);
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
