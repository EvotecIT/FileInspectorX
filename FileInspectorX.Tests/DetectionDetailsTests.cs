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
    public void ReportView_Advice_Shows_Heuristics_For_Secrets_Only_Analysis()
    {
        var analysis = new FileAnalysis
        {
            Secrets = new SecretsSummary
            {
                AzureSasTokenCount = 1,
                Findings = new[]
                {
                    new SecretFindingDetail
                    {
                        Code = "secret:token:azure-sas",
                        Confidence = "High",
                        Evidence = "sv=20...sig=abCD"
                    }
                }
            }
        };

        var rv = ReportView.From(analysis);

        Assert.NotNull(rv.Advice);
        Assert.True(rv.Advice.ShowHeuristics);
        Assert.NotNull(rv.CompactFields);
        Assert.True(rv.CompactFields!.ContainsKey("Heuristics"));
        Assert.Contains("Findings", rv.CompactFields["Heuristics"]);

        var map = rv.ToDictionary();
        var advice = Assert.IsAssignableFrom<Dictionary<string, object?>>(map["Advice"]);
        Assert.Equal(true, advice["ShowHeuristics"]);
        var compact = Assert.IsAssignableFrom<IReadOnlyDictionary<string, IReadOnlyList<string>>>(map["Compact"]);
        Assert.True(compact.ContainsKey("Heuristics"));
        Assert.Contains("Findings", compact["Heuristics"]);
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
    public void ReportView_Archive_Presentation_Includes_Preview_Only_Analysis()
    {
        var analysis = new FileAnalysis
        {
            ArchivePreviewEntries = new[]
            {
                new InnerEntryPreview { Name = "setup.exe", DetectedExtension = "exe" }
            },
            InnerExecutablesSampled = 1
        };

        var rv = ReportView.From(analysis);

        Assert.NotNull(rv.Advice);
        Assert.True(rv.Advice.ShowArchiveDetails);
        Assert.NotNull(rv.ArchivePreview);
        Assert.Contains("setup.exe (exe)", rv.ArchivePreview!);
        Assert.NotNull(rv.CompactFields);
        Assert.True(rv.CompactFields!.ContainsKey("Archive"));
        Assert.Contains("Preview", rv.CompactFields["Archive"]);
        Assert.Contains("InnerBinariesSummary", rv.CompactFields["Archive"]);

        var map = rv.ToDictionary();
        var advice = Assert.IsAssignableFrom<Dictionary<string, object?>>(map["Advice"]);
        Assert.Equal(true, advice["ShowArchiveDetails"]);
        var compact = Assert.IsAssignableFrom<IReadOnlyDictionary<string, IReadOnlyList<string>>>(map["Compact"]);
        Assert.True(compact.ContainsKey("Archive"));
        Assert.Contains("Preview", compact["Archive"]);
        Assert.Contains("InnerBinariesSummary", compact["Archive"]);
        var preview = Assert.IsAssignableFrom<IReadOnlyList<string>>(map["ArchivePreview"]);
        Assert.Contains("setup.exe (exe)", preview);
        Assert.Equal("Binaries: 1", map["InnerBinariesSummary"]);

        var md = MarkdownRenderer.From(rv);
        Assert.Contains("### Archive", md);
        Assert.Contains("Binaries: 1", md);
        Assert.Contains("Preview: setup.exe (exe)", md);
    }

    [Fact]
    public void ReportView_Signature_Presentation_Includes_Certificate_Bundle_Only_Analysis()
    {
        var analysis = new FileAnalysis
        {
            CertificateBundleCount = 2,
            CertificateBundleSubjects = new[] { "CN=Leaf", "CN=Root" }
        };

        var rv = ReportView.From(analysis);

        Assert.NotNull(rv.Advice);
        Assert.True(rv.Advice.ShowSignature);
        Assert.Equal(2, rv.CertBundleCount);
        Assert.NotNull(rv.CertBundleSubjects);
        Assert.Equal(new[] { "CN=Leaf", "CN=Root" }, rv.CertBundleSubjects);
        Assert.NotNull(rv.CompactFields);
        Assert.True(rv.CompactFields!.ContainsKey("Signature"));
        Assert.Contains("CertBundleCount", rv.CompactFields["Signature"]);
        Assert.Contains("CertBundleSubjects", rv.CompactFields["Signature"]);

        var map = rv.ToDictionary();
        var advice = Assert.IsAssignableFrom<Dictionary<string, object?>>(map["Advice"]);
        Assert.Equal(true, advice["ShowSignature"]);
        var compact = Assert.IsAssignableFrom<IReadOnlyDictionary<string, IReadOnlyList<string>>>(map["Compact"]);
        Assert.True(compact.ContainsKey("Signature"));
        Assert.Contains("CertBundleCount", compact["Signature"]);
        Assert.Contains("CertBundleSubjects", compact["Signature"]);
        Assert.Equal(2, map["CertBundleCount"]);
        var subjects = Assert.IsAssignableFrom<IReadOnlyList<string>>(map["CertBundleSubjects"]);
        Assert.Equal(new[] { "CN=Leaf", "CN=Root" }, subjects);

        var md = MarkdownRenderer.From(rv);
        Assert.Contains("### Signature", md);
        Assert.Contains("Certificate bundle count: 2", md);
        Assert.Contains("Certificate bundle subjects: CN=Leaf, CN=Root", md);
    }

    [Fact]
    public void ReportView_TypeAnalysis_Presentation_Includes_Encoded_Only_Analysis()
    {
        var analysis = new FileAnalysis
        {
            EncodedKind = "base64",
            EncodedInnerDetection = new ContentTypeDetectionResult
            {
                Extension = "exe",
                MimeType = "application/vnd.microsoft.portable-executable",
                Confidence = "High",
                Reason = "magic:mz"
            }
        };

        var rv = ReportView.From(analysis);

        Assert.NotNull(rv.Advice);
        Assert.True(rv.Advice.ShowTypeAnalysis);
        Assert.Equal("base64", rv.EncodedKind);
        Assert.Equal("exe", rv.EncodedInnerDetectedExtension);
        Assert.Equal("application/vnd.microsoft.portable-executable", rv.EncodedInnerDetectedName);
        Assert.NotNull(rv.CompactFields);
        Assert.True(rv.CompactFields!.ContainsKey("TypeAnalysis"));
        Assert.Contains("EncodedKind", rv.CompactFields["TypeAnalysis"]);
        Assert.Contains("EncodedInnerDetectedExtension", rv.CompactFields["TypeAnalysis"]);
        Assert.Contains("EncodedInnerDetectedName", rv.CompactFields["TypeAnalysis"]);

        var map = rv.ToDictionary();
        var advice = Assert.IsAssignableFrom<Dictionary<string, object?>>(map["Advice"]);
        Assert.Equal(true, advice["ShowTypeAnalysis"]);
        var compact = Assert.IsAssignableFrom<IReadOnlyDictionary<string, IReadOnlyList<string>>>(map["Compact"]);
        Assert.True(compact.ContainsKey("TypeAnalysis"));
        Assert.Contains("EncodedKind", compact["TypeAnalysis"]);
        Assert.Contains("EncodedInnerDetectedExtension", compact["TypeAnalysis"]);
        Assert.Contains("EncodedInnerDetectedName", compact["TypeAnalysis"]);
        Assert.Equal("base64", map["EncodedKind"]);
        Assert.Equal("exe", map["EncodedInnerDetectedExtension"]);
        Assert.Equal("application/vnd.microsoft.portable-executable", map["EncodedInnerDetectedName"]);

        var md = MarkdownRenderer.From(rv);
        Assert.Contains("### File Type", md);
        Assert.Contains("Encoded payload: base64", md);
        Assert.Contains("(exe)", md);
    }

    [Fact]
    public void Markdown_Includes_Detection_Candidates_And_Alternatives_When_Present()
    {
        var analysis = new FileAnalysis
        {
            Detection = new ContentTypeDetectionResult
            {
                Extension = "txt",
                MimeType = "text/plain",
                Confidence = "Low",
                Reason = "text:plain",
                Candidates = new[]
                {
                    new ContentTypeDetectionCandidate
                    {
                        Extension = "ps1",
                        MimeType = "text/x-powershell",
                        Confidence = "High",
                        Reason = "text:ps1",
                        Score = 92,
                        IsDangerous = true
                    }
                },
                Alternatives = new[]
                {
                    new ContentTypeDetectionCandidate
                    {
                        Extension = "cmd",
                        MimeType = "text/x-shellscript",
                        Confidence = "Medium",
                        Reason = "text:cmd",
                        Score = 61,
                        IsDangerous = true
                    }
                }
            }
        };

        var rv = ReportView.From(analysis);

        Assert.NotNull(rv.Advice);
        Assert.True(rv.Advice.ShowTypeAnalysis);
        Assert.NotNull(rv.CompactFields);
        Assert.True(rv.CompactFields!.ContainsKey("TypeAnalysis"));
        Assert.Contains("DetectionCandidates", rv.CompactFields["TypeAnalysis"]);
        Assert.Contains("DetectionAlternatives", rv.CompactFields["TypeAnalysis"]);

        var map = rv.ToDictionary();
        var advice = Assert.IsAssignableFrom<Dictionary<string, object?>>(map["Advice"]);
        Assert.Equal(true, advice["ShowTypeAnalysis"]);
        Assert.True(map.ContainsKey("DetectionCandidates"));
        Assert.True(map.ContainsKey("DetectionAlternatives"));

        var md = MarkdownRenderer.From(rv);
        Assert.Contains("### File Type", md);
        Assert.Contains("Candidates: ps1 High 92 dangerous (text:ps1)", md);
        Assert.Contains("Alternatives: cmd Medium 61 dangerous (text:cmd)", md);
    }

    [Fact]
    public void ReportView_Compact_Includes_Assessment_Group_When_Assessment_Is_Present()
    {
        int oldWarn = Settings.AssessmentWarnThreshold;
        int oldBlock = Settings.AssessmentBlockThreshold;
        try
        {
            Settings.AssessmentWarnThreshold = 40;
            Settings.AssessmentBlockThreshold = 70;

            var analysis = new FileAnalysis
            {
                SecurityFindings = new[] { "secret:jwt", "secret:keypattern", "secret:token" }
            };

            var rv = ReportView.From(analysis);

            Assert.NotNull(rv.Advice);
            Assert.True(rv.Advice.ShowAssessment);
            Assert.NotNull(rv.CompactFields);
            Assert.True(rv.CompactFields!.ContainsKey("Assessment"));
            Assert.Contains("AssessmentScore", rv.CompactFields["Assessment"]);
            Assert.Contains("AssessmentDecision", rv.CompactFields["Assessment"]);
            Assert.Contains("AssessmentDecisionStrict", rv.CompactFields["Assessment"]);
            Assert.Contains("AssessmentDecisionBalanced", rv.CompactFields["Assessment"]);
            Assert.Contains("AssessmentDecisionLenient", rv.CompactFields["Assessment"]);
            Assert.Contains("AssessmentCodes", rv.CompactFields["Assessment"]);
            Assert.Contains("AssessmentFactors", rv.CompactFields["Assessment"]);

            var map = rv.ToDictionary();
            var advice = Assert.IsAssignableFrom<Dictionary<string, object?>>(map["Advice"]);
            Assert.Equal(true, advice["ShowAssessment"]);
            var compact = Assert.IsAssignableFrom<IReadOnlyDictionary<string, IReadOnlyList<string>>>(map["Compact"]);
            Assert.True(compact.ContainsKey("Assessment"));
            Assert.Contains("AssessmentScore", compact["Assessment"]);
            Assert.Contains("AssessmentDecision", compact["Assessment"]);
            Assert.Contains("AssessmentCodes", compact["Assessment"]);
            Assert.Contains("AssessmentFactors", compact["Assessment"]);
        }
        finally
        {
            Settings.AssessmentWarnThreshold = oldWarn;
            Settings.AssessmentBlockThreshold = oldBlock;
        }
    }

    [Fact]
    public void ReportView_Installer_Presentation_And_Markdown_Include_Installer_Only_Analysis()
    {
        var analysis = new FileAnalysis
        {
            Installer = new InstallerInfo
            {
                Kind = InstallerKind.Msi,
                Name = "Contoso Agent",
                Manufacturer = "Contoso",
                Version = "1.2.3",
                ProductCode = "{11111111-1111-1111-1111-111111111111}",
                Scope = "PerMachine",
                UrlInfoAbout = "https://contoso.example/info",
                MsiCustomActions = new MsiCustomActionSummary
                {
                    CountExe = 1,
                    CountDll = 2,
                    CountScript = 3,
                    Samples = new[] { "3073:BinaryKey/InstallAgent" }
                }
            }
        };

        var rv = ReportView.From(analysis);

        Assert.NotNull(rv.Advice);
        Assert.True(rv.Advice.ShowInstaller);
        Assert.Equal("Msi", rv.InstallerKind);
        Assert.Equal("Contoso Agent", rv.InstallerName);
        Assert.NotNull(rv.CompactFields);
        Assert.True(rv.CompactFields!.ContainsKey("Installer"));
        Assert.Contains("InstallerKind", rv.CompactFields["Installer"]);
        Assert.Contains("InstallerName", rv.CompactFields["Installer"]);
        Assert.Contains("MsiCAExe", rv.CompactFields["Installer"]);
        Assert.Contains("MsiCASamples", rv.CompactFields["Installer"]);

        var map = rv.ToDictionary();
        var advice = Assert.IsAssignableFrom<Dictionary<string, object?>>(map["Advice"]);
        Assert.Equal(true, advice["ShowInstaller"]);
        var compact = Assert.IsAssignableFrom<IReadOnlyDictionary<string, IReadOnlyList<string>>>(map["Compact"]);
        Assert.True(compact.ContainsKey("Installer"));
        Assert.Contains("InstallerKind", compact["Installer"]);
        Assert.Contains("MsiCAExe", compact["Installer"]);
        Assert.Equal("Msi", map["InstallerKind"]);
        Assert.Equal("Contoso Agent", map["InstallerName"]);
        Assert.Equal(1, map["MsiCAExe"]);
        Assert.Equal("3073:BinaryKey/InstallAgent", map["MsiCASamples"]);

        var md = MarkdownRenderer.From(rv);
        Assert.Contains("### Installer", md);
        Assert.Contains("Kind: Msi", md);
        Assert.Contains("Name: Contoso Agent", md);
        Assert.Contains("MSI custom actions (EXE): 1", md);
        Assert.Contains("MSI custom action samples: 3073:BinaryKey/InstallAgent", md);
    }

    [Fact]
    public void Markdown_Includes_Flattened_Properties_Without_VersionInfo_Map()
    {
        var rv = new ReportView
        {
            CompanyName = "Contoso",
            ProductName = "Contoso Agent",
            FileDescription = "Background service",
            FileVersion = "2.1.0",
            ProductVersion = "2.1",
            OriginalFilename = "agent.exe"
        };

        Assert.NotNull(rv.Advice);

        var md = MarkdownRenderer.From(rv);
        Assert.Contains("### Properties", md);
        Assert.Contains("Company: Contoso", md);
        Assert.Contains("Product: Contoso Agent", md);
        Assert.Contains("Description: Background service", md);
        Assert.Contains("FileVersion: 2.1.0", md);
        Assert.Contains("ProductVersion: 2.1", md);
        Assert.Contains("OriginalFilename: agent.exe", md);
    }

    [Fact]
    public void Markdown_Includes_TopTokens_For_Heuristics_Only_Analysis()
    {
        var analysis = new FileAnalysis
        {
            TopTokens = new[] { "downloadstring", "invoke-expression", "frombase64string" }
        };

        var rv = ReportView.From(analysis);

        Assert.NotNull(rv.Advice);
        Assert.True(rv.Advice.ShowHeuristics);
        Assert.NotNull(rv.CompactFields);
        Assert.True(rv.CompactFields!.ContainsKey("Heuristics"));
        Assert.Contains("TopTokens", rv.CompactFields["Heuristics"]);

        var map = rv.ToDictionary();
        var advice = Assert.IsAssignableFrom<Dictionary<string, object?>>(map["Advice"]);
        Assert.Equal(true, advice["ShowHeuristics"]);
        var compact = Assert.IsAssignableFrom<IReadOnlyDictionary<string, IReadOnlyList<string>>>(map["Compact"]);
        Assert.True(compact.ContainsKey("Heuristics"));
        Assert.Contains("TopTokens", compact["Heuristics"]);

        var md = MarkdownRenderer.From(rv);
        Assert.Contains("### Heuristics", md);
        Assert.Contains("Top tokens: downloadstring, invoke-expression, frombase64string", md);
    }

    [Fact]
    public void CollectMetadata_FileMetadataOnly_Exports_Exists_Flag()
    {
        var metadata = FileInspector.CollectMetadata(new FileSystemMetadata
        {
            Exists = false,
            Path = @"C:\missing\sample.txt"
        });

        Assert.True(metadata.ContainsKey("Exists"));
        Assert.Equal(false, metadata["Exists"]);
        Assert.Equal(@"C:\missing\sample.txt", metadata["Path"]);
    }

    [Fact]
    public void InspectWithMetadata_Exports_Exists_For_Present_File()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try
        {
            File.WriteAllText(p, "plain text");

            var summary = FileInspector.InspectWithMetadata(
                p,
                metadataOptions: new FileMetadataOptions
                {
                    IncludePath = true,
                    IncludeSize = true,
                    IncludeTimestamps = false
                });

            Assert.NotNull(summary.FileMetadata);
            Assert.True(summary.FileMetadata!.Exists);
            Assert.True(summary.Metadata.ContainsKey("Exists"));
            Assert.Equal(true, summary.Metadata["Exists"]);
            Assert.Equal(p, summary.Metadata["Path"]);
            Assert.Equal(10L, summary.Metadata["Size"]);
        }
        finally
        {
            if (File.Exists(p)) File.Delete(p);
        }
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
