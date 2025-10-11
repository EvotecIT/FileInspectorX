using System.Runtime.CompilerServices;
using Xunit;

namespace FileInspectorX.Tests;

public class AnalyzeDirectoryTests {
    [Fact]
    public void AnalyzeDirectory_Basic_And_Filter() {
        var dir = Directory.CreateTempSubdirectory();
        try {
            var pPng = Path.Combine(dir.FullName, "a.bin");
            File.WriteAllBytes(pPng, new byte[] { 0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A });
            var pTxt = Path.Combine(dir.FullName, "b.txt");
            File.WriteAllText(pTxt, "{\"x\":1}");

            var all = FileInspector.AnalyzeDirectory(dir.FullName).ToList();
            Assert.Equal(2, all.Count);
            Assert.Contains(all, a => a.Detection?.Extension == "png");
            Assert.Contains(all, a => a.Detection?.Extension == "json" || a.Kind == ContentKind.Text);

            var onlyPng = FileInspector.AnalyzeDirectory(dir.FullName, SearchOption.TopDirectoryOnly, p => p.EndsWith("a.bin", StringComparison.OrdinalIgnoreCase)).ToList();
            Assert.Single(onlyPng);
            Assert.Equal("png", onlyPng[0].Detection?.Extension);
        } finally { try { dir.Delete(true); } catch { } }
    }

    [Fact]
    public void AnalyzeDirectory_NonExisting_Empty() {
        var res = FileInspector.AnalyzeDirectory(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"))).ToList();
        Assert.Empty(res);
    }

    [Fact]
    public async Task AnalyzeDirectoryAsync_Parallel_YieldsAll() {
        var dir = Directory.CreateTempSubdirectory();
        try {
            for (int i = 0; i < 10; i++) {
                var p = Path.Combine(dir.FullName, $"f{i}.txt");
                File.WriteAllText(p, "hello world" + i);
            }

            var list = new List<FileAnalysis>();
            await foreach (var a in FileInspector.AnalyzeDirectoryAsync(dir.FullName, SearchOption.TopDirectoryOnly, null, null, maxDegreeOfParallelism: 4)) {
                list.Add(a);
            }
            Assert.Equal(10, list.Count);
            Assert.All(list, a => Assert.NotNull(a.Detection));
        } finally { try { dir.Delete(true); } catch { } }
    }
}

