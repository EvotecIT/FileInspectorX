using Xunit;

namespace FileInspectorX.Tests;

public class MoreImprovementsTests {
    [Fact]
    public void Dmg_Koly_Trailer_Detected() {
        var p = Path.GetTempFileName();
        try {
            using (var fs = File.Create(p)) {
                fs.Write(new byte[1024], 0, 1024);
                fs.Seek(-512, SeekOrigin.End);
                fs.Write(System.Text.Encoding.ASCII.GetBytes("koly"), 0, 4);
            }
            var res = FileInspector.Detect(p);
            Assert.NotNull(res);
            Assert.Equal("dmg", res!.Extension);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Csv_Estimated_Lines() {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".csv");
        try {
            var lines = string.Join('\n', Enumerable.Range(0, 100).Select(i => $"a,b,c{i}"));
            File.WriteAllText(p, lines);
            var a = FileInspector.Analyze(p);
            Assert.True(a.EstimatedLineCount.HasValue);
            Assert.True(a.EstimatedLineCount.Value >= 90); // allow roughness
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void SecurityFindings_Powershell_IEX_Encoded_B64() {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".ps1");
        try {
            // Construct a PS snippet using IEX and FromBase64String without embedding raw high-signal names.
            var b64 = Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes("Write-Output 'hi'"));
            var txt = $"$x = [Convert]::FromBase64String(\"{b64}\"); IEX ([System.Text.Encoding]::UTF8.GetString($x))\n";
            File.WriteAllText(p, txt);
            var a = FileInspector.Analyze(p);
            Assert.NotNull(a);
            Assert.NotNull(a!.SecurityFindings);
            Assert.Contains("ps:encoded", a!.SecurityFindings!);
            Assert.Contains("ps:iex", a!.SecurityFindings!);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void SecurityFindings_Encoded_HighSignal_Name() {
        // Avoid running by default to reduce chance of AV triggering on disk-scanned test files.
        var run = Environment.GetEnvironmentVariable("FI_RUN_HIGH_SIGNAL_TESTS");
        if (run != "1") return;
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            // Avoid writing the raw token in source; build at runtime from base64.
            string token = System.Text.Encoding.ASCII.GetString(Convert.FromBase64String("bWltaWthdHo="));
            File.WriteAllText(p, $"test {token} here\n");
            var a = FileInspector.Analyze(p);
            Assert.NotNull(a);
            Assert.NotNull(a!.SecurityFindings);
            Assert.Contains("sig:X1001", a!.SecurityFindings!);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }
}
