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
}
