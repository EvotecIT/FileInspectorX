using Xunit;

namespace FileInspectorX.Tests;

public class DetectionDetailsTests
{
    [Fact]
    public void Analyze_And_Report_Expose_DetectionReasonDetails()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try
        {
            var js = "const fs = require('fs');\nmodule.exports = function(x) { return x + 1; }\n";
            File.WriteAllText(p, js);

            var a = FileInspector.Analyze(p);
            Assert.NotNull(a.DetectionReasonDetails);
            Assert.StartsWith("js:cues-", a.DetectionReasonDetails!, StringComparison.OrdinalIgnoreCase);

            var rv = ReportView.From(a);
            Assert.Equal(a.DetectionReasonDetails, rv.DetectionReasonDetails);

            var map = rv.ToDictionary();
            Assert.True(map.ContainsKey("DetectionReasonDetails"));
            Assert.Equal(rv.DetectionReasonDetails, map["DetectionReasonDetails"] as string);

            var md = MarkdownRenderer.From(rv);
            Assert.Contains("js:cues-", md, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (File.Exists(p)) File.Delete(p);
        }
    }

    [Fact]
    public void ReportView_ToDictionary_Exports_SecretsTokenFamilyCount()
    {
        var a = new FileAnalysis
        {
            Secrets = new SecretsSummary
            {
                TokenFamilyCount = 2
            }
        };

        var rv = ReportView.From(a);
        Assert.Equal(2, rv.SecretsTokenFamilyCount);

        var map = rv.ToDictionary();
        Assert.True(map.ContainsKey("SecretsTokenFamilyCount"));
        Assert.Equal(2, map["SecretsTokenFamilyCount"]);
    }

    [Fact]
    public void Markdown_Includes_Secrets_Counts_WhenPresent()
    {
        var rv = new ReportView
        {
            SecretsPrivateKeyCount = 1,
            SecretsJwtLikeCount = 2,
            SecretsKeyPatternCount = 3,
            SecretsTokenFamilyCount = 4
        };

        var md = MarkdownRenderer.From(rv);
        Assert.Contains("### Secrets", md);
        Assert.Contains("Private key indicators: 1", md);
        Assert.Contains("JWT-like tokens: 2", md);
        Assert.Contains("Key/secret patterns: 3", md);
        Assert.Contains("Token-family secrets: 4", md);
    }
}
