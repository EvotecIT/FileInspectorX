using System.Linq;
using Xunit;

namespace FileInspectorX.Tests;

public class AssessmentTests
{
    [Fact]
    public void AssessMulti_Profiles_ShareScore_AndShiftDecisions()
    {
        int oldWarn = Settings.AssessmentWarnThreshold;
        int oldBlock = Settings.AssessmentBlockThreshold;
        try
        {
            Settings.AssessmentWarnThreshold = 40;
            Settings.AssessmentBlockThreshold = 70;

            var a = new FileAnalysis
            {
                SecurityFindings = new[] { "secret:jwt", "secret:keypattern", "secret:token" }
            };

            var multi = FileInspector.AssessMulti(a);

            Assert.Equal(multi.Balanced.Score, multi.Strict.Score);
            Assert.Equal(multi.Balanced.Score, multi.Lenient.Score);
            Assert.Equal(AssessmentDecision.Block, multi.Balanced.Decision);
            Assert.Equal(AssessmentDecision.Block, multi.Strict.Decision);
            Assert.Equal(AssessmentDecision.Warn, multi.Lenient.Decision);
            Assert.Equal(multi.Balanced.Codes, multi.Strict.Codes);
            Assert.Equal(multi.Balanced.Codes, multi.Lenient.Codes);
        }
        finally
        {
            Settings.AssessmentWarnThreshold = oldWarn;
            Settings.AssessmentBlockThreshold = oldBlock;
        }
    }

    [Fact]
    public void Assess_SecretsVolume_IncreasesScore()
    {
        var low = new FileAnalysis
        {
            SecurityFindings = new[] { "secret:jwt" },
            Secrets = new SecretsSummary { JwtLikeCount = 1 }
        };
        var high = new FileAnalysis
        {
            SecurityFindings = new[] { "secret:jwt" },
            Secrets = new SecretsSummary { JwtLikeCount = 5 }
        };

        var aLow = FileInspector.Assess(low);
        var aHigh = FileInspector.Assess(high);

        Assert.True(aHigh.Score > aLow.Score);
        Assert.Contains("Secret.JWT.Volume", aHigh.Codes);
        Assert.True(aHigh.Factors.TryGetValue("Secret.JWT.Volume", out var vol) && vol > 0);
    }

    [Fact]
    public void Assess_SecretsCounts_WorkWithoutFindings()
    {
        var a = new FileAnalysis
        {
            Secrets = new SecretsSummary
            {
                PrivateKeyCount = 1,
                KeyPatternCount = 2,
                TokenFamilyCount = 3,
                GitHubTokenCount = 2,
                AwsAccessKeyIdCount = 1
            }
        };

        var assessed = FileInspector.Assess(a);
        Assert.True(assessed.Score > 0);
        Assert.Contains("Secret.PrivateKey", assessed.Codes);
        Assert.Contains("Secret.KeyPattern", assessed.Codes);
        Assert.Contains("Secret.KeyPattern.Volume", assessed.Codes);
        Assert.Contains("Secret.TokenFamily.GitHub", assessed.Codes);
        Assert.Contains("Secret.TokenFamily.GitHub.Volume", assessed.Codes);
        Assert.Contains("Secret.TokenFamily.AwsAccessKeyId", assessed.Codes);
    }

    [Fact]
    public void AssessmentLegend_ContainsSecretEntries()
    {
        var legend = AssessmentLegend.GetLegend();
        Assert.Contains(legend, e => e.Code == "Secret.JWT");
        Assert.Contains(legend, e => e.Code == "Secret.JWT.Volume");
        Assert.Contains(legend, e => e.Code == "Secret.PrivateKey");
        Assert.Contains(legend, e => e.Code == "Secret.KeyPattern");
        Assert.Contains(legend, e => e.Code == "Secret.TokenFamily");
        Assert.Contains(legend, e => e.Code == "Secret.TokenFamily.Volume");
        Assert.Contains(legend, e => e.Code == "Secret.TokenFamily.GitHub");
        Assert.Contains(legend, e => e.Code == "Secret.TokenFamily.AwsAccessKeyId");
        Assert.Contains(legend, e => e.Code == "Secret.TokenFamily.Slack");
        Assert.Contains(legend, e => e.Code == "Secret.TokenFamily.Stripe");
    }

    [Fact]
    public void Assess_Presence_And_Discount_Codes_Populate_Factors_Without_Eating_Future_Risk()
    {
        var oldAllowedVendors = Settings.AllowedVendors;
        var oldVendorMatchMode = Settings.VendorMatchMode;
        try
        {
            Settings.AllowedVendors = new[] { "Contoso" };
            Settings.VendorMatchMode = VendorMatchMode.Exact;

            var analysis = new FileAnalysis
            {
                Flags = ContentFlags.PeIsDotNet,
                DotNetStrongNameSigned = true,
                Installer = new InstallerInfo
                {
                    PublisherDisplayName = "Contoso",
                    MsiCustomActions = new MsiCustomActionSummary
                    {
                        CountExe = 1
                    }
                }
            };

            var assessed = FileInspector.Assess(analysis);

            Assert.Equal(20, assessed.Score);
            Assert.Contains("DotNet.StrongName", assessed.Codes);
            Assert.Contains("Package.VendorPresent", assessed.Codes);
            Assert.Contains("Package.VendorAllowed", assessed.Codes);
            Assert.Contains("Msi.CustomActionExe", assessed.Codes);
            Assert.Equal(-5, assessed.Factors["DotNet.StrongName"]);
            Assert.Equal(0, assessed.Factors["Package.VendorPresent"]);
            Assert.Equal(-15, assessed.Factors["Package.VendorAllowed"]);
            Assert.Equal(20, assessed.Factors["Msi.CustomActionExe"]);
        }
        finally
        {
            Settings.AllowedVendors = oldAllowedVendors;
            Settings.VendorMatchMode = oldVendorMatchMode;
        }
    }

    [Fact]
    public void Assess_Appx_Presence_Signals_Do_Not_Duplicate_Codes_Or_Inflate_Score()
    {
        var analysis = new FileAnalysis
        {
            Installer = new InstallerInfo
            {
                Capabilities = new[]
                {
                    "runFullTrust",
                    "runFullTrust",
                    "broadFileSystemAccess"
                },
                Extensions = new[]
                {
                    "windows.protocol",
                    "windows.protocol",
                    "filetypeassociation"
                }
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(45, assessed.Score);
        Assert.Equal(1, assessed.Codes.Count(c => c == "Appx.Capability.RunFullTrust"));
        Assert.Equal(1, assessed.Codes.Count(c => c == "Appx.Capability.BroadFileSystemAccess"));
        Assert.Equal(1, assessed.Codes.Count(c => c == "Appx.Extension.Protocol"));
        Assert.Equal(1, assessed.Codes.Count(c => c == "Appx.Extension.FTA"));
        Assert.Equal(20, assessed.Factors["Appx.Capability.RunFullTrust"]);
        Assert.Equal(15, assessed.Factors["Appx.Capability.BroadFileSystemAccess"]);
        Assert.Equal(5, assessed.Factors["Appx.Extension.Protocol"]);
        Assert.Equal(5, assessed.Factors["Appx.Extension.FTA"]);
    }
}
