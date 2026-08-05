using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class SecurityClosureRegressionTests
{
    [Theory]
    [InlineData("REGEDIT4\r\n\r\n[HKEY_CURRENT_USER\\Software\\Contoso]", "Medium")]
    [InlineData("Windows Registry Editor Version 5.00\n\n[HKEY_CURRENT_USER\\Software\\Contoso]", "High")]
    public void RegistryExportRequiresACompleteHeaderLine(string content, string confidence)
    {
        var detected = FileInspector.Detect(Encoding.ASCII.GetBytes(content));

        Assert.Equal("reg", detected?.Extension);
        Assert.Equal(confidence, detected?.Confidence);
    }

    [Theory]
    [InlineData("REGEDIT notes for operators")]
    [InlineData("REGEDIT4 notes for operators")]
    [InlineData("Windows Registry Editor Version 5.00 notes")]
    public void RegistryLikeTextDoesNotMatchWithoutAHeaderBoundary(string content)
    {
        var detected = FileInspector.Detect(Encoding.ASCII.GetBytes(content));

        Assert.NotEqual("reg", detected?.Extension);
    }

    [Theory]
    [InlineData("appx")]
    [InlineData("msix")]
    public void AppPackageSubtypeSuppressesExpectedExecutableAndScriptContainerSignals(string subtype)
    {
        var analysis = new FileAnalysis
        {
            ContainerSubtype = subtype,
            Flags = ContentFlags.ContainerContainsExecutables | ContentFlags.ContainerContainsScripts
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(0, assessed.Score);
        Assert.DoesNotContain("Archive.ContainsExecutables", assessed.Codes);
        Assert.DoesNotContain("Archive.ContainsScripts", assessed.Codes);
        Assert.DoesNotContain("Sig.Absent", assessed.Codes);
    }

    [Fact]
    public void FailedWinTrustStatusRemainsInvalidSignatureEvidence()
    {
        var analysis = new FileAnalysis
        {
            Detection = new ContentTypeDetectionResult { Extension = "msi" },
            Authenticode = new AuthenticodeInfo
            {
                Present = false,
                IsTrustedWindowsPolicy = false,
                WinTrustStatusCode = unchecked((int)0x800B0109)
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(25, assessed.Score);
        Assert.Contains("Sig.WinTrustInvalid", assessed.Codes);
        Assert.DoesNotContain("Sig.Absent", assessed.Codes);
    }
}
