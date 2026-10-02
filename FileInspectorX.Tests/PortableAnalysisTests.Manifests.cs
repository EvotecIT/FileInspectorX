using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed partial class PortableAnalysisTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InstallerManifestDepthLimitKeepsCompletionPartial(bool vsix)
    {
        string root = vsix ? "PackageManifest" : "Package";
        var manifest = new StringBuilder("<" + root + ">");
        for (int i = 0; i < 258; i++) manifest.Append("<nested>");
        for (int i = 0; i < 258; i++) manifest.Append("</nested>");
        manifest.Append("</" + root + ">");
        var bytes = ZipTestArchive.Create((vsix ? "extension.vsixmanifest" : "AppxManifest.xml", manifest.ToString()));
        var options = Options(); options.IncludeInstaller = true; options.IncludeContainer = false;
        foreach (var result in InspectShapes(bytes, vsix ? "upload.vsix" : "upload.appx", options))
        {
            Assert.Equal(InspectionStageStatus.Partial, Stage(result, InspectionStage.Installer).Status);
            Assert.Contains("archive:installer-manifest-depth-limit", result.AnalysisIssues!);
            Assert.False(result.AnalysisComplete);
            Assert.Equal(InspectionOutcome.Partial, result.Outcome);
        }
        CheckManifestPath(bytes, options, complete: false, "archive:installer-manifest-depth-limit");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CorruptCompressedInstallerManifestKeepsCompletionUnavailable(bool vsix)
    {
        var bytes = ZipTestArchive.Create((vsix ? "extension.vsixmanifest" : "AppxManifest.xml", "<invalid />"));
        // A reserved DEFLATE block type gives the real decompressor a payload read failure.
        int directory = ZipTestArchive.LastSignature(bytes, 0x02014b50);
        bytes[8] = bytes[directory + 10] = 8;
        int payload = 30 + BitConverter.ToUInt16(bytes, 26) + BitConverter.ToUInt16(bytes, 28);
        bytes[payload] = 7;
        var options = Options(); options.IncludeInstaller = true; options.IncludeContainer = false;
        foreach (var result in InspectShapes(bytes, vsix ? "upload.vsix" : "upload.appx", options))
        {
            Assert.Equal(InspectionStageStatus.Unavailable, Stage(result, InspectionStage.Installer).Status);
            Assert.Contains("archive:installer-manifest-unavailable", result.AnalysisIssues!);
            Assert.False(result.AnalysisComplete);
            Assert.Equal(InspectionOutcome.Partial, result.Outcome);
        }
        CheckManifestPath(bytes, options, complete: false, "archive:installer-manifest-unavailable");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MalformedInstallerManifestCompletesItsNegativeInspection(bool vsix)
    {
        var bytes = ZipTestArchive.Create((vsix ? "extension.vsixmanifest" : "AppxManifest.xml", "<broken>"));
        var options = Options(); options.IncludeInstaller = true; options.IncludeContainer = false;
        var result = FileInspector.Analyze(bytes, options, vsix ? "upload.vsix" : "upload.appx");
        Assert.Null(result.Installer);
        Assert.Equal(InspectionStageStatus.Completed, Stage(result, InspectionStage.Installer).Status);
        Assert.True(result.AnalysisComplete);
        Assert.Equal(InspectionOutcome.Complete, result.Outcome);
        CheckManifestPath(bytes, options, complete: true, issue: null);
    }

    private static void CheckManifestPath(byte[] bytes, FileInspector.DetectionOptions options, bool complete, string? issue)
    {
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, bytes);
            var result = FileInspector.Analyze(path, options);
            Assert.Equal(complete, result.AnalysisComplete);
            Assert.Equal(complete ? InspectionOutcome.Complete : InspectionOutcome.Partial, result.Outcome);
            if (issue != null) Assert.Contains(issue, result.AnalysisIssues!);
            using var exclusive = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        }
        finally { TestHelpers.SafeDelete(path); }
    }
}
