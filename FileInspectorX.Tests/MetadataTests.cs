using Xunit;

namespace FileInspectorX.Tests;

public class MetadataTests
{
    [Fact]
    public void GetSignatureStatus_Treats_WinTrustTrusted_Binary_As_Signed()
    {
        var analysis = new FileAnalysis
        {
            Authenticode = new AuthenticodeInfo
            {
                Present = false,
                IsTrustedWindowsPolicy = true,
                SignerSubject = "CN=Microsoft Windows",
                SignerThumbprint = "ABC123"
            }
        };

        var status = FileInspector.GetSignatureStatus(analysis);

        Assert.NotNull(status);
        Assert.True(status!.IsSigned);
        Assert.True(status.IsValid);
        Assert.Equal("CN=Microsoft Windows", status.SignerSubject);
        Assert.Equal("ABC123", status.SignerThumbprint);
    }

    [Fact]
    public void GetSignatureStatus_WinTrustFailure_Overrides_CrossPlatformSignals()
    {
        var analysis = CreateSignedAnalysis();
        analysis.Authenticode!.IsTrustedWindowsPolicy = false;

        var status = FileInspector.GetSignatureStatus(analysis);

        Assert.False(status!.IsValid);
    }

    [Fact]
    public void GetSignatureStatus_FileDigestMismatch_IsInvalid_When_WinTrustWasNotRun()
    {
        var analysis = CreateSignedAnalysis();
        analysis.Authenticode!.FileHashMatches = false;

        var status = FileInspector.GetSignatureStatus(analysis);

        Assert.False(status!.IsValid);
    }

    [Fact]
    public void GetSignatureStatus_Requires_All_CrossPlatform_Verification_Signals()
    {
        var analysis = CreateSignedAnalysis();

        Assert.True(FileInspector.GetSignatureStatus(analysis)!.IsValid);

        analysis.Authenticode!.FileHashMatches = null;
        Assert.Null(FileInspector.GetSignatureStatus(analysis)!.IsValid);
    }

    private static FileAnalysis CreateSignedAnalysis()
    {
        return new FileAnalysis
        {
            Authenticode = new AuthenticodeInfo
            {
                Present = true,
                EnvelopeSignatureValid = true,
                FileHashMatches = true,
                ChainValid = true,
                SignerSubject = "CN=Example Publisher"
            }
        };
    }
}
