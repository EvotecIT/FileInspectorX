using System.IO.Compression;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class FiftyFifthReviewRegressionTests
{
    [Fact]
    public void RegistryExportsRouteAsExecutableContent()
    {
        var bytes = Encoding.ASCII.GetBytes(
            "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\Example]\r\n");

        var result = FileInspector.Detect(bytes);

        Assert.Equal("reg", result?.Extension);
        Assert.Equal(ContentKind.Executable, KindClassifier.Classify(result));
    }

    [Fact]
    public void EncodedLuaPayloadsReceiveTheInnerScriptSignal()
    {
        var analysis = new FileAnalysis
        {
            EncodedKind = "base64",
            EncodedInnerDetection = new ContentTypeDetectionResult { Extension = "lua" }
        };

        var assessment = FileInspector.Assess(analysis);

        Assert.Contains("Encoded.InnerScript", assessment.Codes);
    }

    [Fact]
    public void LuaEntriesSetArchiveScriptSignals()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".zip");
        try
        {
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            using (var writer = new StreamWriter(archive.CreateEntry("scripts/payload.lua").Open()))
            {
                writer.Write("os.execute('whoami')");
            }

            var analysis = FileInspector.Analyze(path);
            var assessment = FileInspector.Assess(analysis);

            Assert.True((analysis.Flags & ContentFlags.ContainerContainsScripts) != 0);
            Assert.Contains("Archive.ContainsScripts", assessment.Codes);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void KornShellEntriesRemainScriptLike()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".zip");
        try
        {
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            using (var writer = new StreamWriter(archive.CreateEntry("scripts/payload.ksh").Open()))
            {
                writer.Write("#!/usr/bin/env ksh\nprint -- hello");
            }

            var analysis = FileInspector.Analyze(path);

            Assert.True((analysis.Flags & ContentFlags.ContainerContainsScripts) != 0);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }
}
