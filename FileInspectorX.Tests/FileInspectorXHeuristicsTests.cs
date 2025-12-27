using System;
using System.IO;
using System.Text;
using FileInspectorX;

namespace FileInspectorX.Tests;

public class FileInspectorXHeuristicsTests
{
    [Xunit.Fact]
    public void PsScript_Detected_As_PowerShell_Not_Yaml()
    {
        var ps = """
Import-Module C:\\Support\\GitHub\\PSWriteOffice\\PSWriteOffice.psd1 -Force
$path = 'C:\\temp\\test-autosize2.xlsx'
$data = 1..2 | ForEach-Object { [PSCustomObject]@{ Name = "Row$_"; Value = "Some very long value $_" } }
Write-Host "Data being exported:"
$data | Format-Table
$data | Export-OfficeExcel -FilePath $path -WorksheetName 'Data' -AutoSize
""".Replace("\r\n", "\n");
        var tmp = WriteTemp(".ps1", ps);
        try
        {
            var det = FileInspector.Detect(tmp);
            Xunit.Assert.NotNull(det);
            Xunit.Assert.Equal("ps1", det!.Extension);
            Xunit.Assert.Equal("text/x-powershell", det.MimeType);
        }
        finally { TryDelete(tmp); }
    }

    [Xunit.Fact]
    public void PsScript_Populates_ScriptLanguage_And_Cmdlets()
    {
        var ps = """
New-ConfigurationManifest -ModuleVersion '1.0.0'
Get-ChildItem -Path . | Out-String
""".Replace("\r\n", "\n");
        var tmp = WriteTemp(".ps1", ps);
        try
        {
            var analysis = FileInspector.Inspect(tmp);
            Xunit.Assert.NotNull(analysis);
            Xunit.Assert.Equal("powershell", analysis!.ScriptLanguage);
            Xunit.Assert.NotNull(analysis.ScriptCmdlets);
            Xunit.Assert.Contains("new-configurationmanifest", analysis.ScriptCmdlets!);
            Xunit.Assert.Contains("get-childitem", analysis.ScriptCmdlets!);
        }
        finally { TryDelete(tmp); }
    }

    [Xunit.Fact]
    public void LogFile_Detected_As_Log()
    {
        var log = """
2025-10-19 14:00:06Z [DEBUG] File logging enabled: C:\\Temp\\TestimoX.run.log
2025-10-19 14:00:06Z [DEBUG] [ADDS] GetForest start current
2025-10-19 14:00:06Z [DEBUG] [ADDS] GetForest done ok=True
""".Replace("\r\n", "\n");
        var tmp = WriteTemp(".log", log);
        try
        {
            var det = FileInspector.Detect(tmp);
            Xunit.Assert.NotNull(det);
            Xunit.Assert.Equal("log", det!.Extension);
            Xunit.Assert.Equal("text/plain", det.MimeType);
        }
        finally { TryDelete(tmp); }
    }

    [Xunit.Fact]
    public void Config_Ambiguity_Matches_Xml_Json_Ini()
    {
        // XML
        var xml = "<?xml version=\"1.0\"?><configuration><appSettings><add key=\"A\" value=\"B\"/></appSettings></configuration>";
        var pXml = WriteTemp(".config", xml);
        // JSON
        var json = "{\"a\":1,\"b\":true}";
        var pJson = WriteTemp(".config", json);
        // INI
        var ini = "[section]\nkey=value\nflag=true\n";
        var pIni = WriteTemp(".config", ini);

        try
        {
            var dXml = FileInspector.Detect(pXml);
            var dJson = FileInspector.Detect(pJson);
            var dIni = FileInspector.Detect(pIni);
            var cmpXml = FileInspector.CompareDeclared("config", dXml);
            var cmpJson = FileInspector.CompareDeclared("config", dJson);
            var cmpIni = FileInspector.CompareDeclared("config", dIni);
            Xunit.Assert.False(cmpXml.Mismatch); // config ~ xml
            Xunit.Assert.False(cmpJson.Mismatch); // config ~ json
            Xunit.Assert.False(cmpIni.Mismatch); // config ~ ini/plain
        }
        finally { TryDelete(pXml); TryDelete(pJson); TryDelete(pIni); }
    }

    [Xunit.Fact]
    public void Conf_Ambiguity_Matches_Common_Formats()
    {
        // Various formats that often use .conf extension in the wild
        var xml = "<?xml version=\"1.0\"?><root><k v=\"1\"/></root>";
        var json = "{\"k\":1,\"b\":false}";
        var yaml = "k: v\narr:\n - a\n - b\n";
        var ini = "[s]\nk=v\n";

        var pXml = WriteTemp(".conf", xml);
        var pJson = WriteTemp(".conf", json);
        var pYaml = WriteTemp(".conf", yaml);
        var pIni = WriteTemp(".conf", ini);

        try
        {
            var dXml = FileInspector.Detect(pXml);
            var dJson = FileInspector.Detect(pJson);
            var dYaml = FileInspector.Detect(pYaml);
            var dIni = FileInspector.Detect(pIni);
            Xunit.Assert.False(FileInspector.CompareDeclared("conf", dXml).Mismatch);
            Xunit.Assert.False(FileInspector.CompareDeclared("conf", dJson).Mismatch);
            Xunit.Assert.False(FileInspector.CompareDeclared("conf", dYaml).Mismatch);
            Xunit.Assert.False(FileInspector.CompareDeclared("conf", dIni).Mismatch);
        }
        finally { TryDelete(pXml); TryDelete(pJson); TryDelete(pYaml); TryDelete(pIni); }
    }

    [Xunit.Fact]
    public void Config_With_PowerShell_Content_Is_Mismatch()
    {
        var ps = "Write-Host \"Hello: world\"\nGet-Process | Where-Object { $_.Name -like '*pwsh*' }\n";
        var p = WriteTemp(".config", ps);
        try
        {
            var det = FileInspector.Detect(p);
            Xunit.Assert.NotNull(det);
            // Detection likely ps1
            Xunit.Assert.Equal("ps1", det!.Extension);
            var cmp = FileInspector.CompareDeclared("config", det);
            Xunit.Assert.True(cmp.Mismatch); // not in config family
        }
        finally { TryDelete(p); }
    }

    [Xunit.Fact]
    public void CompareDeclared_Normalizes_DetectedLeadingDot()
    {
        var det = new ContentTypeDetectionResult
        {
            Extension = ".png",
            MimeType = "image/png",
            Confidence = "High",
            Reason = "magic:png"
        };

        var cmp = FileInspector.CompareDeclared("png", det);
        Xunit.Assert.False(cmp.Mismatch);
    }

    [Xunit.Fact]
    public void CompareDeclared_Uses_GuessedExtension_When_Missing()
    {
        var det = new ContentTypeDetectionResult
        {
            Extension = "",
            GuessedExtension = "docx",
            MimeType = "application/zip",
            Confidence = "Low",
            Reason = "magic:zip"
        };

        var cmp = FileInspector.CompareDeclared("docx", det);
        Xunit.Assert.False(cmp.Mismatch);
    }

    [Xunit.Fact]
    public void Detect_Span_Respects_DeclaredExtension_Bias()
    {
        var xml = "<?xml version=\"1.0\"?><policyDefinitions></policyDefinitions>";
        var data = System.Text.Encoding.UTF8.GetBytes(xml);
        var det = FileInspector.Detect(data, null, "admx");
        Xunit.Assert.NotNull(det);
        Xunit.Assert.Equal("admx", det!.Extension);
    }

    [Xunit.Fact]
    public void Detect_Span_Does_Not_Bias_Unknown_Binary()
    {
        var data = new byte[64];
        var det = FileInspector.Detect(data, new FileInspector.DetectionOptions { MagicHeaderBytes = 16 }, "ps1");
        Xunit.Assert.NotNull(det);
        Xunit.Assert.Equal(string.Empty, det!.Extension);
        Xunit.Assert.Equal("unknown", det.Reason);
    }

    [Xunit.Theory]
    [Xunit.InlineData("log", "Just a plain line.\nStill plain.")]
    [Xunit.InlineData("ps1", "Just a plain line.\nStill plain.")]
    public void Detect_Uses_Declared_Bias_For_Generic_Text_Across_Inputs(string declaredExt, string content)
    {
        AssertAcrossInputs(declaredExt, content, declaredExt);
    }

    [Xunit.Theory]
    [Xunit.InlineData("cmd", "@echo off\r\nsetlocal\r\necho hi\r\n")]
    [Xunit.InlineData("admx", "<?xml version=\"1.0\"?><policyDefinitions></policyDefinitions>")]
    [Xunit.InlineData("inf", "[Version]\nSignature=\"$Windows NT$\"\n")]
    public void Detect_Uses_Declared_Heuristics_Across_Inputs(string declaredExt, string content)
    {
        AssertAcrossInputs(declaredExt, content, declaredExt);
    }

    private static string WriteTemp(string ext, string content)
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ext);
        File.WriteAllText(path, content);
        return path;
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    private static void AssertAcrossInputs(string declaredExt, string content, string expectedExt)
    {
        var data = Encoding.UTF8.GetBytes(content);
        var path = WriteTemp("." + declaredExt, content);
        try
        {
            var detPath = FileInspector.Detect(path);
            Xunit.Assert.NotNull(detPath);
            Xunit.Assert.Equal(expectedExt, detPath!.Extension);

            using var ms = new MemoryStream(data, writable: false);
            var detStream = FileInspector.Detect(ms, null, declaredExt);
            Xunit.Assert.NotNull(detStream);
            Xunit.Assert.Equal(expectedExt, detStream!.Extension);

            var detSpan = FileInspector.Detect(data, null, declaredExt);
            Xunit.Assert.NotNull(detSpan);
            Xunit.Assert.Equal(expectedExt, detSpan!.Extension);
        }
        finally { TryDelete(path); }
    }
}
