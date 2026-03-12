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
    public void Assess_Specific_Token_Finding_Does_Not_Also_Add_Generic_Token_Count_Code()
    {
        var analysis = new FileAnalysis
        {
            SecurityFindings = new[] { "secret:token:github" },
            Secrets = new SecretsSummary
            {
                TokenFamilyCount = 1
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Contains("Secret.TokenFamily.GitHub", assessed.Codes);
        Assert.DoesNotContain("Secret.TokenFamily", assessed.Codes);
        Assert.Equal(32, assessed.Factors["Secret.TokenFamily.GitHub"]);
    }

    [Fact]
    public void Assess_New_Token_Families_Are_Scored_From_Findings_And_Counts()
    {
        var analysis = new FileAnalysis
        {
            SecurityFindings = new[]
            {
                "secret:token:gcp-apikey",
                "secret:token:npm",
                "secret:token:azure-sas"
            },
            Secrets = new SecretsSummary
            {
                GitHubTokenCount = 1,
                GcpApiKeyCount = 2,
                NpmTokenCount = 1,
                AzureSasTokenCount = 1
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Contains("Secret.TokenFamily.GitHub", assessed.Codes);
        Assert.Contains("Secret.TokenFamily.GcpApiKey", assessed.Codes);
        Assert.Contains("Secret.TokenFamily.GcpApiKey.Volume", assessed.Codes);
        Assert.Contains("Secret.TokenFamily.Npm", assessed.Codes);
        Assert.Contains("Secret.TokenFamily.AzureSas", assessed.Codes);
        Assert.True(assessed.Score > 32);
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
        Assert.Contains(legend, e => e.Code == "Secret.TokenFamily.GcpApiKey");
        Assert.Contains(legend, e => e.Code == "Secret.TokenFamily.Npm");
        Assert.Contains(legend, e => e.Code == "Secret.TokenFamily.AzureSas");
        Assert.Contains(legend, e => e.Code == "Sig.BadEnvelope");
        Assert.Contains(legend, e => e.Code == "Sig.WinTrustInvalid");
        Assert.Contains(legend, e => e.Code == "Sig.NoTimestamp");
        Assert.Contains(legend, e => e.Code == "Sig.Absent");
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
    public void Assess_Does_Not_Triple_Count_One_SelfSigned_Trust_Failure()
    {
        var analysis = new FileAnalysis
        {
            Authenticode = new AuthenticodeInfo
            {
                Present = true,
                IsSelfSigned = true,
                ChainValid = false,
                IsTrustedWindowsPolicy = false,
                TimestampPresent = true
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(20, assessed.Score);
        Assert.Contains("Sig.SelfSigned", assessed.Codes);
        Assert.DoesNotContain("Sig.ChainInvalid", assessed.Codes);
        Assert.DoesNotContain("Sig.WinTrustInvalid", assessed.Codes);
    }

    [Fact]
    public void Assess_Does_Not_Add_NoTimestamp_When_Signature_Envelope_Is_Already_Invalid()
    {
        var analysis = new FileAnalysis
        {
            Authenticode = new AuthenticodeInfo
            {
                Present = true,
                EnvelopeSignatureValid = false,
                TimestampPresent = false
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(15, assessed.Score);
        Assert.Contains("Sig.BadEnvelope", assessed.Codes);
        Assert.DoesNotContain("Sig.NoTimestamp", assessed.Codes);
    }

    [Fact]
    public void Assess_Does_Not_Add_NoTimestamp_When_Windows_Trust_Has_Already_Failed()
    {
        var analysis = new FileAnalysis
        {
            Authenticode = new AuthenticodeInfo
            {
                Present = true,
                ChainValid = true,
                IsTrustedWindowsPolicy = false,
                TimestampPresent = false
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(25, assessed.Score);
        Assert.Contains("Sig.WinTrustInvalid", assessed.Codes);
        Assert.DoesNotContain("Sig.NoTimestamp", assessed.Codes);
    }

    [Fact]
    public void Assess_Does_Not_Double_Discount_Allowed_Vendor_From_Package_And_Signature()
    {
        var oldAllowedVendors = Settings.AllowedVendors;
        var oldVendorMatchMode = Settings.VendorMatchMode;
        try
        {
            Settings.AllowedVendors = new[] { "Contoso" };
            Settings.VendorMatchMode = VendorMatchMode.Exact;

            var analysis = new FileAnalysis
            {
                Installer = new InstallerInfo
                {
                    PublisherDisplayName = "Contoso",
                    MsiCustomActions = new MsiCustomActionSummary
                    {
                        CountExe = 1
                    }
                },
                Authenticode = new AuthenticodeInfo
                {
                    Present = true,
                    SignerSubjectCN = "Contoso"
                }
            };

            var assessed = FileInspector.Assess(analysis);

            Assert.Equal(20, assessed.Score);
            Assert.Contains("Package.VendorAllowed", assessed.Codes);
            Assert.DoesNotContain("Sig.VendorAllowed", assessed.Codes);
            Assert.Equal(-15, assessed.Factors["Package.VendorAllowed"]);
        }
        finally
        {
            Settings.AllowedVendors = oldAllowedVendors;
            Settings.VendorMatchMode = oldVendorMatchMode;
        }
    }

    [Fact]
    public void Assess_Empty_Authenticode_Object_Does_Not_Suppress_Unsigned_Penalty()
    {
        var analysis = new FileAnalysis
        {
            Detection = new ContentTypeDetectionResult
            {
                Extension = "exe"
            },
            Authenticode = new AuthenticodeInfo
            {
                Present = false
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(10, assessed.Score);
        Assert.Contains("Sig.Absent", assessed.Codes);
    }

    [Fact]
    public void Assess_Unsigned_Sys_File_Gets_Signature_Absent_Penalty()
    {
        var analysis = new FileAnalysis
        {
            Detection = new ContentTypeDetectionResult
            {
                Extension = "sys"
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(10, assessed.Score);
        Assert.Contains("Sig.Absent", assessed.Codes);
    }

    [Fact]
    public void Assess_Unsigned_Ocx_File_Gets_Signature_Absent_Penalty()
    {
        var analysis = new FileAnalysis
        {
            Detection = new ContentTypeDetectionResult
            {
                Extension = "ocx"
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(10, assessed.Score);
        Assert.Contains("Sig.Absent", assessed.Codes);
    }

    [Fact]
    public void Assess_Unsigned_Scr_File_Gets_Signature_Absent_Penalty()
    {
        var analysis = new FileAnalysis
        {
            Detection = new ContentTypeDetectionResult
            {
                Extension = "scr"
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(10, assessed.Score);
        Assert.Contains("Sig.Absent", assessed.Codes);
    }

    [Fact]
    public void Assess_Unsigned_Com_File_Gets_Signature_Absent_Penalty()
    {
        var analysis = new FileAnalysis
        {
            Detection = new ContentTypeDetectionResult
            {
                Extension = "com"
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(10, assessed.Score);
        Assert.Contains("Sig.Absent", assessed.Codes);
    }

    [Fact]
    public void Assess_Unsigned_Pif_File_Gets_Signature_Absent_Penalty()
    {
        var analysis = new FileAnalysis
        {
            Detection = new ContentTypeDetectionResult
            {
                Extension = "pif"
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(10, assessed.Score);
        Assert.Contains("Sig.Absent", assessed.Codes);
    }

    [Fact]
    public void Assess_Unsigned_Msp_File_Gets_Signature_Absent_Penalty()
    {
        var analysis = new FileAnalysis
        {
            Detection = new ContentTypeDetectionResult
            {
                Extension = "msp"
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(10, assessed.Score);
        Assert.Contains("Sig.Absent", assessed.Codes);
    }

    [Fact]
    public void Assess_Unsigned_Msi_File_Gets_Signature_Absent_Penalty()
    {
        var analysis = new FileAnalysis
        {
            Detection = new ContentTypeDetectionResult
            {
                Extension = "msi"
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(10, assessed.Score);
        Assert.Contains("Sig.Absent", assessed.Codes);
    }

    [Fact]
    public void Assess_Unsigned_Appx_File_Gets_Signature_Absent_Penalty()
    {
        var analysis = new FileAnalysis
        {
            Detection = new ContentTypeDetectionResult
            {
                Extension = "appx"
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(10, assessed.Score);
        Assert.Contains("Sig.Absent", assessed.Codes);
    }

    [Theory]
    [InlineData("com")]
    [InlineData("pif")]
    [InlineData("msp")]
    [InlineData("msix")]
    [InlineData("appx")]
    public void Assess_Encoded_Inner_Risky_Executable_Families_Get_Executable_Penalty(string extension)
    {
        var analysis = new FileAnalysis
        {
            EncodedKind = "base64",
            EncodedInnerDetection = new ContentTypeDetectionResult
            {
                Extension = extension
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(30, assessed.Score);
        Assert.Contains("Encoded.Present", assessed.Codes);
        Assert.Contains("Encoded.InnerExecutable", assessed.Codes);
        Assert.Equal(20, assessed.Factors["Encoded.InnerExecutable"]);
    }

    [Theory]
    [InlineData("vbe")]
    [InlineData("wsf")]
    [InlineData("wsh")]
    public void Assess_Encoded_Inner_Vbscript_Families_Get_Script_Penalty(string extension)
    {
        var analysis = new FileAnalysis
        {
            EncodedKind = "base64",
            EncodedInnerDetection = new ContentTypeDetectionResult
            {
                Extension = extension
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(25, assessed.Score);
        Assert.Contains("Encoded.Present", assessed.Codes);
        Assert.Contains("Encoded.InnerScript", assessed.Codes);
        Assert.Equal(15, assessed.Factors["Encoded.InnerScript"]);
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

    [Fact]
    public void Assess_Repeated_Security_Findings_Do_Not_Inflate_Same_Assessment_Code()
    {
        var analysis = new FileAnalysis
        {
            SecurityFindings = new[]
            {
                "tool:bitsadmin",
                "tool:certutil",
                "ps:iex",
                "ps:iex"
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(30, assessed.Score);
        Assert.Equal(1, assessed.Codes.Count(c => c == "Tool.Indicator"));
        Assert.Equal(1, assessed.Codes.Count(c => c == "Script.IEX"));
        Assert.Equal(10, assessed.Factors["Tool.Indicator"]);
        Assert.Equal(20, assessed.Factors["Script.IEX"]);
    }

    [Fact]
    public void Assess_Tool_Indicator_Still_Scores_When_It_Is_The_Only_Signal()
    {
        var analysis = new FileAnalysis
        {
            SecurityFindings = new[] { "tool:bitsadmin" }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(10, assessed.Score);
        Assert.Contains("Tool.Indicator", assessed.Codes);
        Assert.Equal(10, assessed.Factors["Tool.Indicator"]);
    }

    [Fact]
    public void Assess_Tool_Indicator_Does_Not_Stack_On_Generic_Archive_Content_Signals()
    {
        var analysis = new FileAnalysis
        {
            Flags = ContentFlags.ContainerContainsExecutables,
            SecurityFindings = new[] { "tool:bitsadmin" }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(25, assessed.Score);
        Assert.Contains("Archive.ContainsExecutables", assessed.Codes);
        Assert.DoesNotContain("Tool.Indicator", assessed.Codes);
    }

    [Fact]
    public void Assess_Disguised_Archive_Executable_Does_Not_Also_Add_Generic_Executable_Container_Penalty()
    {
        var analysis = new FileAnalysis
        {
            Flags = ContentFlags.ContainerContainsExecutables | ContentFlags.ContainerHasDisguisedExecutables
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(25, assessed.Score);
        Assert.DoesNotContain("Archive.ContainsExecutables", assessed.Codes);
        Assert.Contains("Archive.DisguisedExecutables", assessed.Codes);
        Assert.Equal(25, assessed.Factors["Archive.DisguisedExecutables"]);
    }

    [Fact]
    public void Assess_Appx_Container_Does_Not_Stack_Generic_Archive_Content_Penalties_With_Appx_Signals()
    {
        var analysis = new FileAnalysis
        {
            ContainerSubtype = "appx",
            Flags = ContentFlags.ContainerContainsExecutables | ContentFlags.ContainerContainsScripts,
            Installer = new InstallerInfo
            {
                Kind = InstallerKind.Appx,
                Capabilities = new[] { "runFullTrust", "broadFileSystemAccess" },
                Extensions = new[] { "windows.protocol", "filetypeassociation" }
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(45, assessed.Score);
        Assert.DoesNotContain("Archive.ContainsExecutables", assessed.Codes);
        Assert.DoesNotContain("Archive.ContainsScripts", assessed.Codes);
        Assert.Contains("Appx.Capability.RunFullTrust", assessed.Codes);
        Assert.Contains("Appx.Capability.BroadFileSystemAccess", assessed.Codes);
        Assert.Contains("Appx.Extension.Protocol", assessed.Codes);
        Assert.Contains("Appx.Extension.FTA", assessed.Codes);
    }

    [Fact]
    public void Assess_Archive_With_Embedded_Installer_Gets_Installer_Container_Penalty()
    {
        var analysis = new FileAnalysis
        {
            Flags = ContentFlags.ContainerContainsInstallers
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(15, assessed.Score);
        Assert.Contains("Archive.ContainsInstallers", assessed.Codes);
        Assert.Equal(15, assessed.Factors["Archive.ContainsInstallers"]);
    }

    [Fact]
    public void ToAssessmentView_Preserves_Captured_Assessment_When_Current_Settings_Change()
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

            analysis.Assessment = FileInspector.Assess(analysis);

            Settings.AssessmentWarnThreshold = 80;
            Settings.AssessmentBlockThreshold = 90;

            var view = analysis.ToAssessmentView(@"C:\sample.txt");

            Assert.Equal(70, view.Score);
            Assert.Equal(AssessmentDecision.Block, view.Decision);
            Assert.Contains("Secret.JWT", view.Codes);
        }
        finally
        {
            Settings.AssessmentWarnThreshold = oldWarn;
            Settings.AssessmentBlockThreshold = oldBlock;
        }
    }

    [Fact]
    public void Analyze_Captures_MultiProfile_Assessment_Snapshot()
    {
        int oldWarn = Settings.AssessmentWarnThreshold;
        int oldBlock = Settings.AssessmentBlockThreshold;
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");

        try
        {
            Settings.AssessmentWarnThreshold = 40;
            Settings.AssessmentBlockThreshold = 70;

            File.WriteAllText(path, "-----BEGIN PRIVATE KEY-----\nABCDEF\n-----END PRIVATE KEY-----");

            var analysis = FileInspector.Analyze(path);

            Assert.NotNull(analysis.Assessment);
            Assert.NotNull(analysis.AssessmentProfiles);
            Assert.Equal(analysis.Assessment!.Score, analysis.AssessmentProfiles!.Balanced.Score);
            Assert.Equal(analysis.Assessment.Decision, analysis.AssessmentProfiles.Balanced.Decision);
        }
        finally
        {
            Settings.AssessmentWarnThreshold = oldWarn;
            Settings.AssessmentBlockThreshold = oldBlock;
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void ToAssessmentView_Uses_Captured_Profile_Snapshot_When_Balanced_Assessment_Field_Is_Missing()
    {
        var analysis = new FileAnalysis
        {
            AssessmentProfiles = new MultiAssessmentResult
            {
                Balanced = new AssessmentResult
                {
                    Score = 55,
                    Decision = AssessmentDecision.Warn,
                    Codes = new[] { "Test.Code" },
                    Factors = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["Test.Code"] = 55
                    }
                }
            }
        };

        var view = analysis.ToAssessmentView(@"C:\sample.txt");

        Assert.Equal(55, view.Score);
        Assert.Equal(AssessmentDecision.Warn, view.Decision);
        Assert.Equal("Test.Code", view.Codes);
    }
}
