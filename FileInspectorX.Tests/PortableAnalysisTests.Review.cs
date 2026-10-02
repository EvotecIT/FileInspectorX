using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed partial class PortableAnalysisTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void ForwardOnlyDetectionPreservesOwnershipWithAndWithoutInstrumentation(bool metrics, bool cancellation)
    {
        using var token = new CancellationTokenSource();
        using var input = new FragmentedInput(Encoding.UTF8.GetBytes("{\"value\":1}"), seekable: false);
        var options = Options(); options.DetectOnly = true; options.CollectMetrics = metrics;
        options.CancellationToken = cancellation ? token.Token : default;
        Assert.Equal("json", FileInspector.Inspect(input, options).Detection!.Extension);
        Assert.False(input.Disposed);
        Assert.True(input.CanRead);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void EncodedExecutableFactsSurviveFragmentedContentReads(bool hex)
    {
        var pe = TestHelpers.CreateMinimalPe();
        var bytes = Encoding.ASCII.GetBytes(hex ? BitConverter.ToString(pe).Replace("-", "") : Convert.ToBase64String(pe));
        foreach (var result in InspectShapes(bytes, "upload.txt", Options()))
        {
            Assert.Equal(hex ? "hex" : "base64", result.EncodedKind);
            Assert.Equal("exe", result.EncodedInnerDetection!.Extension);
            Assert.Equal(Hash(bytes), result.Detection!.Sha256Hex);
        }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void ContentInstallerManifestsAreIndependentOfFilesystemAndContainerEnrichment(bool vsix, bool container)
    {
        string name = vsix ? "extension.vsixmanifest" : "AppxManifest.xml";
        string manifest = vsix
            ? "<PackageManifest xmlns='http://schemas.microsoft.com/developer/vsx-schema/2011'><Metadata><Identity Id='Portable.Extension' Publisher='Portable' Version='1.2.3'/><DisplayName>Portable Extension</DisplayName></Metadata></PackageManifest>"
            : "<Package xmlns='http://schemas.microsoft.com/appx/manifest/foundation/windows10'><Identity Name='Portable.App' Publisher='CN=Portable' Version='1.2.3.4'/><Properties><PublisherDisplayName>Portable</PublisherDisplayName></Properties><Capabilities><Capability Name='internetClient'/></Capabilities></Package>";
        var bytes = ZipTestArchive.Create((name, manifest));
        var options = Options(); options.IncludeInstaller = true; options.IncludeContainer = container;
        foreach (var result in InspectShapes(bytes, "upload.zip", options))
        {
            Assert.Equal(vsix ? InstallerKind.Vsix : InstallerKind.Msix, result.Installer!.Kind);
            Assert.Equal(InspectionStageStatus.Completed, Stage(result, InspectionStage.Installer).Status);
            Assert.Equal(InspectionOutcome.Complete, result.Outcome);
        }
    }

    [Fact]
    public void MissingNestedTarPayloadKeepsBothChildAndParentPartial()
    {
        using var tar = new MemoryStream();
        InspectionIntegrityTests.WriteTarHeader(tar, "missing.bin", size: 4096);
        var child = FileInspector.Analyze(tar.ToArray(), Options(), "upload.tar");
        Assert.False(child.AnalysisComplete);
        Assert.Equal(InspectionStageStatus.Partial, Stage(child, InspectionStage.Container).Status);
        var parent = FileInspector.Analyze(Archive("zip", "nested.tar", tar.ToArray()), Options(), "upload.zip");
        Assert.False(parent.AnalysisComplete);
        Assert.Equal(InspectionOutcome.Partial, parent.Outcome);
        Assert.Equal(InspectionStageStatus.Partial, Stage(parent, InspectionStage.Container).Status);
        Assert.Contains(parent.AnalysisIssues!, issue => issue.StartsWith("archive:inner-", StringComparison.Ordinal));
    }

    [Fact]
    public void PackageManifestLimitsAndNativeTrustKeepTheirOwnOutcomes()
    {
        var bytes = ZipTestArchive.Create(("AppxManifest.xml", "<Package><Identity Name='Portable.App' Publisher='CN=Portable' Version='1.2.3.4'/></Package>"));
        var options = Options(); options.IncludeInstaller = true; options.IncludeContainer = false;
        options.Settings = options.Settings! with { ArchiveMaxEntryReadBytes = 16 };
        var limited = FileInspector.Analyze(bytes, options, "upload.zip");
        Assert.Equal(InspectionStageStatus.Partial, Stage(limited, InspectionStage.Installer).Status);
        Assert.False(limited.AnalysisComplete);

        options.Settings = Options().Settings! with { VerifyAuthenticodeWithWinTrust = true };
        options.IncludeAuthenticode = true;
        var policy = FileInspector.Analyze(bytes, options, "upload.zip");
        if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
        {
            Assert.Equal(InspectionStageStatus.Unavailable, Stage(policy, InspectionStage.AuthenticodePolicy).Status);
            Assert.Contains("authenticode-policy:path-required", policy.AnalysisIssues!);
            Assert.False(policy.AnalysisComplete);
        }
    }
}
