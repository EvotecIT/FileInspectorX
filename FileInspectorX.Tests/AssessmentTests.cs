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
}
