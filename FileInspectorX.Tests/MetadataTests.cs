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
}
