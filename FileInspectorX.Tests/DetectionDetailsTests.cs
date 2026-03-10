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
                TokenFamilyCount = 2,
                GitHubTokenCount = 1,
                AwsAccessKeyIdCount = 1
            }
        };

        var rv = ReportView.From(a);
        Assert.Equal(2, rv.SecretsTokenFamilyCount);
        Assert.Equal(1, rv.SecretsGitHubTokenCount);
        Assert.Equal(1, rv.SecretsAwsAccessKeyIdCount);

        var map = rv.ToDictionary();
        Assert.True(map.ContainsKey("SecretsTokenFamilyCount"));
        Assert.Equal(2, map["SecretsTokenFamilyCount"]);
        Assert.True(map.ContainsKey("SecretsGitHubTokenCount"));
        Assert.True(map.ContainsKey("SecretsAwsAccessKeyIdCount"));
    }

    [Fact]
    public void Markdown_Includes_Secrets_Counts_WhenPresent()
    {
        var rv = new ReportView
        {
            SecretsPrivateKeyCount = 1,
            SecretsJwtLikeCount = 2,
            SecretsKeyPatternCount = 3,
            SecretsTokenFamilyCount = 4,
            SecretsGitHubTokenCount = 2,
            SecretsAwsAccessKeyIdCount = 1,
            SecretsSlackTokenCount = 1
        };

        var md = MarkdownRenderer.From(rv);
        Assert.Contains("### Secrets", md);
        Assert.Contains("Private key indicators: 1", md);
        Assert.Contains("JWT-like tokens: 2", md);
        Assert.Contains("Key/secret patterns: 3", md);
        Assert.Contains("Token-family secrets: 4", md);
        Assert.Contains("GitHub token-family: 2", md);
        Assert.Contains("AWS access key id: 1", md);
        Assert.Contains("Slack token-family: 1", md);
    }

    [Fact]
    public void Report_And_Markdown_Expose_New_Secret_Details()
    {
        var a = new FileAnalysis
        {
            Secrets = new SecretsSummary
            {
                GcpApiKeyCount = 1,
                NpmTokenCount = 2,
                AzureSasTokenCount = 1,
                Findings = new[]
                {
                    new SecretFindingDetail
                    {
                        Code = "secret:token:gcp-apikey",
                        Confidence = "High",
                        Line = 12,
                        Evidence = "AIzaSy...9x2Q"
                    },
                    new SecretFindingDetail
                    {
                        Code = "secret:token:npm",
                        Confidence = "Medium",
                        Line = 24,
                        Evidence = "npm_12...abCD"
                    }
                }
            }
        };

        var rv = ReportView.From(a);
        Assert.Equal(1, rv.SecretsGcpApiKeyCount);
        Assert.Equal(2, rv.SecretsNpmTokenCount);
        Assert.Equal(1, rv.SecretsAzureSasTokenCount);
        Assert.NotNull(rv.SecretsFindings);
        Assert.Collection(
            rv.SecretsFindings!,
            finding =>
            {
                Assert.Equal("secret:token:gcp-apikey", finding.Code);
                Assert.Equal("High", finding.Confidence);
                Assert.Equal(12, finding.Line);
                Assert.Equal("AIzaSy...9x2Q", finding.Evidence);
            },
            finding =>
            {
                Assert.Equal("secret:token:npm", finding.Code);
                Assert.Equal("Medium", finding.Confidence);
                Assert.Equal(24, finding.Line);
                Assert.Equal("npm_12...abCD", finding.Evidence);
            });

        var map = rv.ToDictionary();
        Assert.Equal(1, map["SecretsGcpApiKeyCount"]);
        Assert.Equal(2, map["SecretsNpmTokenCount"]);
        Assert.Equal(1, map["SecretsAzureSasTokenCount"]);
        var findings = Assert.IsAssignableFrom<IReadOnlyList<SecretFindingDetail>>(map["SecretsFindings"]);
        Assert.Equal(2, findings.Count);
        Assert.Equal("secret:token:gcp-apikey", findings[0].Code);
        Assert.Equal("secret:token:npm", findings[1].Code);

        var md = MarkdownRenderer.From(rv);
        Assert.Contains("GCP API key: 1", md);
        Assert.Contains("npm token-family: 2", md);
        Assert.Contains("Azure SAS token-family: 1", md);
        Assert.Contains("[High] secret:token:gcp-apikey line 12 -> `AIzaSy...9x2Q`", md);
        Assert.Contains("[Medium] secret:token:npm line 24 -> `npm_12...abCD`", md);
    }

    [Fact]
    public void CollectMetadata_Exports_New_Secret_Detail_Surface()
    {
        var analysis = new FileAnalysis
        {
            Secrets = new SecretsSummary
            {
                GcpApiKeyCount = 1,
                NpmTokenCount = 2,
                AzureSasTokenCount = 1,
                Findings = new[]
                {
                    new SecretFindingDetail
                    {
                        Code = "secret:token:azure-sas",
                        Confidence = "High",
                        Line = 9,
                        Evidence = "sv=20...sig=abCD"
                    }
                }
            }
        };

        var metadata = FileInspector.CollectMetadata(analysis);

        Assert.Equal(1, metadata["SecretsGcpApiKeyCount"]);
        Assert.Equal(2, metadata["SecretsNpmTokenCount"]);
        Assert.Equal(1, metadata["SecretsAzureSasTokenCount"]);
        var findings = Assert.IsAssignableFrom<IReadOnlyList<SecretFindingDetail>>(metadata["SecretsFindings"]);
        Assert.Single(findings);
        Assert.Equal("secret:token:azure-sas", findings[0].Code);
        Assert.Equal("High", findings[0].Confidence);
        Assert.Equal(9, findings[0].Line);
        Assert.Equal("sv=20...sig=abCD", findings[0].Evidence);
    }

    [Fact]
    public void Analyze_Generates_Redacted_Secret_Details_With_LineNumbers()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try
        {
            var jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0IiwiZXhwIjoyMDAwMDAwMDAwfQ.c2lnbmF0dXJl";
            var github = "ghp_0123456789abcdef0123456789abcdef0123";
            var text = string.Join("\n", new[]
            {
                "header",
                jwt,
                "github_token=" + github
            });
            File.WriteAllText(p, text);

            var analysis = FileInspector.Analyze(p);

            Assert.NotNull(analysis.Secrets);
            Assert.NotNull(analysis.Secrets!.Findings);
            Assert.Collection(
                analysis.Secrets!.Findings!,
                jwtFinding =>
                {
                    Assert.Equal("secret:jwt", jwtFinding.Code);
                    Assert.Equal("Medium", jwtFinding.Confidence);
                    Assert.Equal(2, jwtFinding.Line);
                    Assert.Equal(Redact(jwt, keepHead: 8, keepTail: 6), jwtFinding.Evidence);
                },
                githubFinding =>
                {
                    Assert.Equal("secret:token:github", githubFinding.Code);
                    Assert.Equal("High", githubFinding.Confidence);
                    Assert.Equal(3, githubFinding.Line);
                    Assert.Equal(Redact(github, keepHead: 9, keepTail: 4), githubFinding.Evidence);
                });
        }
        finally
        {
            if (File.Exists(p)) File.Delete(p);
        }

        static string Redact(string token, int keepHead, int keepTail)
        {
            int middle = token.Length - keepHead - keepTail;
            return token.Substring(0, keepHead) + new string('*', middle) + token.Substring(token.Length - keepTail, keepTail);
        }
    }

    [Fact]
    public void Report_And_Markdown_Expose_MultiAssessment_Profile_Decisions()
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

            var rv = ReportView.From(a);
            Assert.Equal("Block", rv.AssessmentDecisionStrict);
            Assert.Equal("Block", rv.AssessmentDecisionBalanced);
            Assert.Equal("Warn", rv.AssessmentDecisionLenient);

            var map = rv.ToDictionary();
            Assert.Equal("Block", map["AssessmentDecisionStrict"]);
            Assert.Equal("Block", map["AssessmentDecisionBalanced"]);
            Assert.Equal("Warn", map["AssessmentDecisionLenient"]);

            var md = MarkdownRenderer.From(rv);
            Assert.Contains("Profile decisions: Strict=Block, Balanced=Block, Lenient=Warn", md);
        }
        finally
        {
            Settings.AssessmentWarnThreshold = oldWarn;
            Settings.AssessmentBlockThreshold = oldBlock;
        }
    }
}
