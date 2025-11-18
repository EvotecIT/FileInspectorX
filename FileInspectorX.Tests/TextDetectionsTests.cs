using Xunit;

namespace FileInspectorX.Tests;

public class TextDetectionsTests {
    [Fact]
    public void Csv_Semicolon_Detected() {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            File.WriteAllText(p, "a;b;c\n1;2;3\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("csv", r!.Extension);
            Assert.Equal("text/csv", r.MimeType);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Csv_Utf8Bom_SingleLine_Detected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".csv");
        try
        {
            // Write UTF-8 BOM + header-only CSV
            var bom = new byte[] { 0xEF, 0xBB, 0xBF };
            using (var fs = File.Create(p))
            {
                fs.Write(bom, 0, bom.Length);
                var txt = System.Text.Encoding.UTF8.GetBytes("Col1,Col2,Col3\n");
                fs.Write(txt, 0, txt.Length);
            }
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("csv", r!.Extension);
            Assert.Equal("text/csv", r.MimeType);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Csv_Utf8Bom_TwoLines_Detected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".csv");
        try
        {
            var bom = new byte[] { 0xEF, 0xBB, 0xBF };
            using (var fs = File.Create(p))
            {
                fs.Write(bom, 0, bom.Length);
                var txt = System.Text.Encoding.UTF8.GetBytes("A,B,C\n1,2,3\n");
                fs.Write(txt, 0, txt.Length);
            }
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("csv", r!.Extension);
            Assert.Equal("text/csv", r.MimeType);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Tsv_SingleLine_Detected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".tsv");
        try
        {
            File.WriteAllText(p, "a\tb\tc\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("tsv", r!.Extension);
            Assert.Equal("text/tab-separated-values", r.MimeType);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Python_Heuristic_Detected() {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            File.WriteAllText(p, "import os\n\nif __name__ == '__main__':\n    print('hi')\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("py", r!.Extension);
            Assert.Equal("text/x-python", r.MimeType);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Ruby_Heuristic_Detected() {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            File.WriteAllText(p, "class Greeter\n  def hi\n    puts 'hi'\n  end\nend\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("rb", r!.Extension);
            Assert.Equal("text/x-ruby", r.MimeType);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Lua_Heuristic_Detected() {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            File.WriteAllText(p, "local function hi() end\nfunction test() end\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("lua", r!.Extension);
            Assert.Equal("text/x-lua", r.MimeType);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Bracketed_Levels_Not_Json() {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            File.WriteAllText(p, "[INFO] started\n[ERROR] failed\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.NotEqual("json", r!.Extension);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Colon_Heavy_Logs_Not_Yaml() {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            File.WriteAllText(p, "2025-10-11 12:34: INFO: started\n2025-10-11 12:35: WARN: next\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.NotEqual("yml", r!.Extension);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void ReasonDetails_Populated_For_Json() {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".json");
        try {
            File.WriteAllText(p, "{\"a\":1,\"b\":2}");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("json", r!.Extension);
            Assert.False(string.IsNullOrEmpty(r!.ReasonDetails));
        } finally { if (File.Exists(p)) File.Delete(p); }
    }
    [Fact]
    public void PowerShell_Heuristic_Detected() {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            File.WriteAllText(p, "#requires -Modules PSReadLine\nparam()\nWrite-Host 'Hello'\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("ps1", r!.Extension);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Yaml_NoFrontMatter_Detected() {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            File.WriteAllText(p, "name: test\nversion: 1\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("yml", r!.Extension);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Markdown_Detected() {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            File.WriteAllText(p, "# Title\nSome text\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("md", r!.Extension);
            Assert.Equal("text/markdown", r.MimeType);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Ndjson_Detected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".ndjson");
        try
        {
            File.WriteAllText(p, "{\"a\":1}\n{\"b\":\"x\"}\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("ndjson", r!.Extension);
            Assert.Equal("application/x-ndjson", r.MimeType);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Jsonl_Detected_As_Ndjson()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".jsonl");
        try
        {
            File.WriteAllText(p, "{\"a\":1}\n{\"b\":\"x\"}\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("ndjson", r!.Extension);
            Assert.Equal("application/x-ndjson", r.MimeType);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Toml_Detected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".toml");
        try
        {
            var txt = "title = \"TOML Example\"\n[owner]\nname = \"Tom\"\n";
            File.WriteAllText(p, txt);
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("toml", r!.Extension);
            Assert.Equal("application/toml", r.MimeType);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Ndjson_Malformed_NotDetected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".ndjson");
        try
        {
            // Missing closing brace on second line
            File.WriteAllText(p, "{\"a\":1}\n{\"b\":\"x\"\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.NotEqual("ndjson", r!.Extension);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Toml_NestedTables_Detected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".toml");
        try
        {
            var txt = "[database.settings]\nuser=\"sa\"\npassword=\"p@ss\"\n[products]\n[[products.item]]\nname=\"X\"\n";
            File.WriteAllText(p, txt);
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("toml", r!.Extension);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Json_Utf8Bom_Detected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var bom = new byte[] { 0xEF, 0xBB, 0xBF };
            using (var fs = File.Create(p))
            {
                fs.Write(bom, 0, bom.Length);
                var txt = System.Text.Encoding.UTF8.GetBytes("{\"ok\":true}\n");
                fs.Write(txt, 0, txt.Length);
            }
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("json", r!.Extension);
            Assert.Equal("application/json", r.MimeType);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void VBScript_Heuristic_Detected() {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            File.WriteAllText(p, "Dim x\nSet o = CreateObject(\"WScript.Shell\")\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("vbs", r!.Extension);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void ShellScript_Heuristic_Detected() {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            File.WriteAllText(p, "#!/bin/bash\nset -e\necho hi\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("sh", r!.Extension);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Batch_Heuristic_Detected() {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            File.WriteAllText(p, "@echo off\r\nREM test\r\nset VAR=1\r\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("bat", r!.Extension);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Html_External_Links_Parsed()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".html");
        try
        {
            File.WriteAllText(p, "<html><head><script src=\"https://cdn.example.com/app.js\"></script></head><body><a href=\"http://example.com\">x</a><img src=\"//cdn.example.com/img.png\"></body></html>");
            var a = FileInspector.Analyze(p);
            Assert.NotNull(a);
            Assert.True((a.Flags & ContentFlags.HtmlHasExternalLinks) != 0);
            Assert.NotNull(a.References);
            Assert.Contains(a.References!, r => r.Kind == ReferenceKind.Url && (r.SourceTag ?? string.Empty).StartsWith("html:"));
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Log_With_Markdown_Like_Header_Is_Not_Markdown()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".log");
        try
        {
            File.WriteAllText(p, "# Fields: time level message\n2025-01-01 12:00:00 INFO started\n2025-01-01 12:01:00 ERROR failed\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("log", r!.Extension);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Comma_Delimited_Logs_Not_Classified_As_Csv()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try
        {
            File.WriteAllText(p, "2025-01-01 00:00:00,INFO,Started\n2025-01-01 00:01:00,ERROR,Failed\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("log", r!.Extension);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void PowerShell_Shebang_Minimal_Script_Detected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".ps1");
        try
        {
            File.WriteAllText(p, "#!/usr/bin/env pwsh\nGet-ChildItem\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("ps1", r!.Extension);
            Assert.Equal("text/x-powershell", r.MimeType);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void PowerShell_VerbNoun_Function_Detected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try
        {
            File.WriteAllText(p, "function Get-Thing { param([string]$Name) Write-Output $Name }\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("ps1", r!.Extension);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void PowerShell_Pipeline_Detected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try
        {
            File.WriteAllText(p, "Get-Process | Where-Object { $_.Id -gt 4 }\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("ps1", r!.Extension);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void PowerShell_Module_Psm1_Detected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".psm1");
        try
        {
            File.WriteAllText(p, "function Get-Thing { Write-Output 1 }\nExport-ModuleMember -Function Get-Thing\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("psm1", r!.Extension);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void PowerShell_Data_Psd1_Detected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".psd1");
        try
        {
            File.WriteAllText(p, "@{ ModuleVersion = '1.0'; RootModule = 'My.psm1' }\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("psd1", r!.Extension);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Markdown_With_PowerShell_Content_Stays_Markdown()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".md");
        try
        {
            File.WriteAllText(p, "# Doc\n\n```powershell\nGet-ChildItem\n```\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("md", r!.Extension);
            Assert.Equal("text/markdown", r.MimeType);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Declared_Log_With_Low_Cues_Biased_To_Log()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".log");
        try
        {
            File.WriteAllText(p, "Only one line without timestamps or levels\n");
            var r = FileInspector.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("log", r!.Extension);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

}
