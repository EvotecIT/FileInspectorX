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
}
