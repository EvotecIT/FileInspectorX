using System.Linq;
using Xunit;

namespace FileInspectorX.Tests;

public class GroupPolicyDetectionsTests
{
    [Fact]
    public void Inf_Utf16Bom_Detected_As_Inf()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".inf");
        try
        {
            var content = "[Version]\r\nSignature=\"$CHICAGO$\"\r\n[Unicode]\r\nUnicode=yes\r\n[System Access]\r\nMinimumPasswordAge = 1\r\n";
            var bytes = System.Text.Encoding.Unicode.GetPreamble().Concat(System.Text.Encoding.Unicode.GetBytes(content)).ToArray();
            File.WriteAllBytes(p, bytes);

            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("inf", r!.Extension);
            Assert.Equal("text/plain", r.MimeType);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Inf_AsciiNoBom_Detected_As_Inf()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".inf");
        try
        {
            File.WriteAllText(p, "[Version]\r\nSignature=\"$CHICAGO$\"\r\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("inf", r!.Extension);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Ini_Not_Misclassified_As_Toml_When_Declared_Ini()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".ini");
        try
        {
            File.WriteAllText(p, "[General]\nfoo = bar\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("ini", r!.Extension);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Cmd_PlainText_Biased_To_Cmd()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".cmd");
        try
        {
            File.WriteAllText(p, "msiexec /i foo.msi /qn\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("cmd", r!.Extension);
            Assert.False(FileInspector.CompareDeclared("cmd", r).Mismatch);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Admx_Declared_Extension_Preserved()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".admx");
        try
        {
            File.WriteAllText(p, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<policyDefinitions />\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("admx", r!.Extension);
            Assert.False(FileInspector.CompareDeclared("admx", r).Mismatch);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Adml_Declared_Extension_Preserved()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".adml");
        try
        {
            File.WriteAllText(p, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<policyDefinitionResources />\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("adml", r!.Extension);
            Assert.False(FileInspector.CompareDeclared("adml", r).Mismatch);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Adml_Utf16_Detected_As_Adml()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".adml");
        try
        {
            var content = "<?xml version=\"1.0\" encoding=\"utf-16\"?>\r\n<policyDefinitionResources>\r\n  <displayName>Sample</displayName>\r\n</policyDefinitionResources>\r\n";
            var bytes = System.Text.Encoding.Unicode.GetPreamble().Concat(System.Text.Encoding.Unicode.GetBytes(content)).ToArray();
            File.WriteAllBytes(p, bytes);
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("adml", r!.Extension);
            Assert.Equal("High", r.Confidence);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Admx_MalformedXml_Flagged()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".admx");
        try
        {
            File.WriteAllText(p, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<policyDefinitions>\n  <categories>\n</policyDefinitions>\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("admx", r!.Extension);
            Assert.Equal("Low", r.Confidence);
            Assert.Contains("xml:malformed", r.Reason ?? string.Empty);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Adml_MalformedXml_Flagged()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".adml");
        try
        {
            File.WriteAllText(p, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<policyDefinitionResources>\n  <resources>\n</policyDefinitionResources>\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("adml", r!.Extension);
            Assert.Equal("Low", r.Confidence);
            Assert.Contains("xml:malformed", r.Reason ?? string.Empty);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Psd1_Hashtable_Detected_As_Psd1()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".psd1");
        try
        {
            File.WriteAllText(p, "@{\n    ModuleVersion = '1.0.0'\n    GUID = 'abc123'\n}\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("psd1", r!.Extension);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void RegistryPol_Detected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".pol");
        try
        {
            // "PReg" + DWORD version 1 (LE)
            var bytes = new byte[] { (byte)'P', (byte)'R', (byte)'e', (byte)'g', 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };
            File.WriteAllBytes(p, bytes);

            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("pol", r!.Extension);
            Assert.Equal("application/x-group-policy-registry-pol", r.MimeType);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void RegistryPol_InvalidVersion_Rejected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".pol");
        try
        {
            // "PReg" + DWORD version 999 (LE)
            var bytes = new byte[] { (byte)'P', (byte)'R', (byte)'e', (byte)'g', 0xE7, 0x03, 0x00, 0x00, 0x00, 0x00 };
            File.WriteAllBytes(p, bytes);

            var r = FileInspector.Detect(p);
            Assert.True(r is null || r.Extension != "pol");
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Ini_With_Leading_Comments_Detected_From_Txt()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try
        {
            File.WriteAllText(p, "# Comment line\n; Another comment\n\n[General]\nsetting=value\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("ini", r!.Extension);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Ini_EmptySection_DoesNotBreak_Detection()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try
        {
            File.WriteAllText(p, "[]\n[ValidSection]\nkey=value\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("ini", r!.Extension);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void PowerShell_TypeAccelerators_Not_Misclassified_As_Ini()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try
        {
            File.WriteAllText(p, "[int]$age = 25\nif ($age -eq 25) { $x = 1 }\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.NotEqual("ini", r!.Extension);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }
}
