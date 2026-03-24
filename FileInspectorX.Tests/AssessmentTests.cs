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
        Assert.Contains(legend, e => e.Code == "Archive.ContainsInstallers");
        Assert.Contains(legend, e => e.Code == "DotNet.StrongName");
        Assert.Contains(legend, e => e.Code == "DotNet.NoStrongName");
        Assert.Contains(legend, e => e.Code == "Html.ExternalLinks");
        Assert.Contains(legend, e => e.Code == "Msi.PerUser");
        Assert.Contains(legend, e => e.Code == "Msi.UrlsPresent");
        Assert.Contains(legend, e => e.Code == "Name.DoubleExtension");
        Assert.Contains(legend, e => e.Code == "Name.BiDiOverride");
        Assert.Contains(legend, e => e.Code == "Name.ExtensionMismatch");
        Assert.Contains(legend, e => e.Code == "Type.ExtensionOnlyRisk");
        Assert.Contains(legend, e => e.Code == "Type.LowConfidenceRisk");
        Assert.Contains(legend, e => e.Code == "Type.AmbiguousCandidates");
        Assert.Contains(legend, e => e.Code == "Type.DangerousAlternative");
        Assert.Contains(legend, e => e.Code == "Type.DangerousMismatch");
        Assert.Contains(legend, e => e.Code == "Type.GuessedSubtypeRisk");
        Assert.Contains(legend, e => e.Code == "Type.ValidationUncertain");
        Assert.Contains(legend, e => e.Code == "Archive.InnerScriptEncoded");
        Assert.Contains(legend, e => e.Code == "Archive.InnerScriptExec");
        Assert.Contains(legend, e => e.Code == "Archive.InnerScriptDownload");
        Assert.Contains(legend, e => e.Code == "Archive.InnerExternalHosts");
        Assert.Contains(legend, e => e.Code == "Archive.InnerUncShares");
        Assert.Contains(legend, e => e.Code == "Archive.InnerDisguisedScript");
        Assert.Contains(legend, e => e.Code == "PE.RegSvrExport");
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
        Assert.Contains(legend, e => e.Code == "Encoded.EmbeddedExecutable");
        Assert.Contains(legend, e => e.Code == "Encoded.EmbeddedScript");
        Assert.Contains(legend, e => e.Code == "Script.Encoded");
        Assert.Contains(legend, e => e.Code == "Script.IEX");
        Assert.Contains(legend, e => e.Code == "Script.WebDownload");
        Assert.Contains(legend, e => e.Code == "Script.Reflection");
        Assert.Contains(legend, e => e.Code == "Script.CertutilDecode");
        Assert.Contains(legend, e => e.Code == "Script.Mshta");
        Assert.Contains(legend, e => e.Code == "Script.ActiveX");
        Assert.Contains(legend, e => e.Code == "Script.FromCharCode");
        Assert.Contains(legend, e => e.Code == "Script.PyExecB64");
        Assert.Contains(legend, e => e.Code == "Script.PyExec");
        Assert.Contains(legend, e => e.Code == "Script.RbEval");
        Assert.Contains(legend, e => e.Code == "Script.LuaExec");
        Assert.Contains(legend, e => e.Code == "Script.UncShares");
        Assert.Contains(legend, e => e.Code == "Script.NetworkDriveMapping");
        Assert.Contains(legend, e => e.Code == "Script.ExternalHosts");
        Assert.Contains(legend, e => e.Code == "Tool.Indicator");
    }

    [Fact]
    public void Assess_ArchiveInnerSignals_Add_ArchiveAssessmentCodes()
    {
        var analysis = new FileAnalysis
        {
            SecurityFindings = new[]
            {
                "archive:inner-script-encoded",
                "archive:inner-script-exec",
                "archive:inner-script-download",
                "archive:inner-external-hosts",
                "archive:inner-unc",
                "archive:inner-disguised-script"
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.True(assessed.Score > 0);
        Assert.Contains("Archive.InnerScriptEncoded", assessed.Codes);
        Assert.Contains("Archive.InnerScriptExec", assessed.Codes);
        Assert.Contains("Archive.InnerScriptDownload", assessed.Codes);
        Assert.Contains("Archive.InnerExternalHosts", assessed.Codes);
        Assert.Contains("Archive.InnerUncShares", assessed.Codes);
        Assert.Contains("Archive.InnerDisguisedScript", assessed.Codes);
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
    public void Assess_WinTrustTrusted_Pe_Without_Embedded_Signature_Does_Not_Get_SigAbsent()
    {
        var analysis = new FileAnalysis
        {
            Detection = new ContentTypeDetectionResult
            {
                Extension = "exe"
            },
            Authenticode = new AuthenticodeInfo
            {
                Present = false,
                IsTrustedWindowsPolicy = true,
                VerificationNote = "WinTrust policy validation"
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(0, assessed.Score);
        Assert.DoesNotContain("Sig.Absent", assessed.Codes);
        Assert.DoesNotContain("Sig.WinTrustInvalid", assessed.Codes);
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

    [Fact]
    public void Assess_Unsigned_Appx_ContainerSubtype_Gets_Signature_Absent_Penalty()
    {
        var analysis = new FileAnalysis
        {
            ContainerSubtype = "appx"
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(10, assessed.Score);
        Assert.Contains("Sig.Absent", assessed.Codes);
    }

    [Fact]
    public void Assess_Unsigned_Msix_InstallerKind_Gets_Signature_Absent_Penalty()
    {
        var analysis = new FileAnalysis
        {
            Installer = new InstallerInfo
            {
                Kind = InstallerKind.Msix
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
    public void Assess_Embedded_Data_Uri_Executable_Payloads_Get_Executable_Penalty()
    {
        var analysis = new FileAnalysis
        {
            SecurityFindings = new[]
            {
                "html:data-b64=1",
                "html:data-exts=exe:1,png:2"
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(30, assessed.Score);
        Assert.Contains("Encoded.Embedded", assessed.Codes);
        Assert.Contains("Encoded.EmbeddedExecutable", assessed.Codes);
        Assert.Equal(20, assessed.Factors["Encoded.EmbeddedExecutable"]);
    }

    [Fact]
    public void Assess_Embedded_Data_Uri_Script_Payloads_Get_Script_Penalty()
    {
        var analysis = new FileAnalysis
        {
            SecurityFindings = new[]
            {
                "script:data-b64=2",
                "script:data-exts=ps1:1,txt:1"
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(25, assessed.Score);
        Assert.Contains("Encoded.Embedded", assessed.Codes);
        Assert.Contains("Encoded.EmbeddedScript", assessed.Codes);
        Assert.Equal(15, assessed.Factors["Encoded.EmbeddedScript"]);
    }

    [Fact]
    public void Assess_NonBase64_Embedded_Data_Uri_Script_Payloads_Get_Script_Penalty()
    {
        var analysis = new FileAnalysis
        {
            SecurityFindings = new[]
            {
                "script:data-uri=1",
                "script:data-exts=js:1"
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(25, assessed.Score);
        Assert.Contains("Encoded.Embedded", assessed.Codes);
        Assert.Contains("Encoded.EmbeddedScript", assessed.Codes);
        Assert.Equal(15, assessed.Factors["Encoded.EmbeddedScript"]);
    }

    [Fact]
    public void Assess_New_Sensitive_Signature_Codes_Are_Scored_And_Deduplicated()
    {
        var analysis = new FileAnalysis
        {
            SecurityFindings = new[]
            {
                "sig:X1001",
                "sig:X1002",
                "sig:X1003",
                "sig:X1004",
                "sig:X1005",
                "sig:X1006"
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(100, assessed.Score);
        Assert.Contains("Sig.MimikatzEncodedHint", assessed.Codes);
        Assert.Contains("Sig.SekurlsaEncodedHint", assessed.Codes);
        Assert.Contains("Sig.DCSyncEncodedHint", assessed.Codes);
        Assert.Contains("Sig.InvokeMimikatzHint", assessed.Codes);
        Assert.Contains("Sig.ProcdumpHint", assessed.Codes);
        Assert.Equal(1, assessed.Codes.Count(c => c == "Sig.SekurlsaEncodedHint"));
        Assert.Equal(140, assessed.Factors.Values.Sum());
        Assert.Equal(20, assessed.Factors["Sig.ProcdumpHint"]);
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
    public void Assess_New_Script_Indicators_Are_Scored_And_Deduplicated()
    {
        var analysis = new FileAnalysis
        {
            SecurityFindings = new[]
            {
                "bat:certutil",
                "js:mshta",
                "js:activex",
                "js:fromcharcode",
                "js:fromcharcode"
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(60, assessed.Score);
        Assert.Contains("Script.CertutilDecode", assessed.Codes);
        Assert.Contains("Script.Mshta", assessed.Codes);
        Assert.Contains("Script.ActiveX", assessed.Codes);
        Assert.Contains("Script.FromCharCode", assessed.Codes);
        Assert.Equal(1, assessed.Codes.Count(c => c == "Script.FromCharCode"));
        Assert.Equal(15, assessed.Factors["Script.CertutilDecode"]);
        Assert.Equal(20, assessed.Factors["Script.Mshta"]);
        Assert.Equal(15, assessed.Factors["Script.ActiveX"]);
        Assert.Equal(10, assessed.Factors["Script.FromCharCode"]);
    }

    [Fact]
    public void Assess_Runtime_Script_Indicators_Are_Scored_And_Deduplicated()
    {
        var analysis = new FileAnalysis
        {
            SecurityFindings = new[]
            {
                "py:exec-b64",
                "py:exec",
                "rb:eval",
                "lua:exec",
                "py:exec"
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(50, assessed.Score);
        Assert.Contains("Script.PyExecB64", assessed.Codes);
        Assert.Contains("Script.PyExec", assessed.Codes);
        Assert.Contains("Script.RbEval", assessed.Codes);
        Assert.Contains("Script.LuaExec", assessed.Codes);
        Assert.Equal(1, assessed.Codes.Count(c => c == "Script.PyExec"));
        Assert.Equal(20, assessed.Factors["Script.PyExecB64"]);
        Assert.Equal(10, assessed.Factors["Script.PyExec"]);
        Assert.Equal(10, assessed.Factors["Script.RbEval"]);
        Assert.Equal(10, assessed.Factors["Script.LuaExec"]);
    }

    [Fact]
    public void Assess_External_Script_Host_Indicators_Are_Scored()
    {
        var analysis = new FileAnalysis
        {
            SecurityFindings = new[]
            {
                "net:hosts=2",
                "net:hosts-int=1",
                "net:hosts-ext=1"
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(10, assessed.Score);
        Assert.Contains("Script.ExternalHosts", assessed.Codes);
        Assert.Equal(10, assessed.Factors["Script.ExternalHosts"]);
    }

    [Fact]
    public void Assess_Network_Share_Script_Indicators_Are_Scored()
    {
        var analysis = new FileAnalysis
        {
            SecurityFindings = new[]
            {
                "net:unc=2",
                "net:map=1",
                "net:hosts=1",
                "net:hosts-int=1"
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(10, assessed.Score);
        Assert.Contains("Script.UncShares", assessed.Codes);
        Assert.Contains("Script.NetworkDriveMapping", assessed.Codes);
        Assert.Equal(5, assessed.Factors["Script.UncShares"]);
        Assert.Equal(5, assessed.Factors["Script.NetworkDriveMapping"]);
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

        Assert.Equal(55, assessed.Score);
        Assert.Contains("Sig.Absent", assessed.Codes);
        Assert.DoesNotContain("Archive.ContainsExecutables", assessed.Codes);
        Assert.DoesNotContain("Archive.ContainsScripts", assessed.Codes);
        Assert.Contains("Appx.Capability.RunFullTrust", assessed.Codes);
        Assert.Contains("Appx.Capability.BroadFileSystemAccess", assessed.Codes);
        Assert.Contains("Appx.Extension.Protocol", assessed.Codes);
        Assert.Contains("Appx.Extension.FTA", assessed.Codes);
    }

    [Fact]
    public void Assess_Risky_Ambiguous_Detection_Adds_Type_Uncertainty_Codes()
    {
        var analysis = new FileAnalysis
        {
            Detection = new ContentTypeDetectionResult
            {
                Extension = "txt",
                Confidence = "Low",
                Reason = "text:plain",
                Candidates = new[]
                {
                    new ContentTypeDetectionCandidate
                    {
                        Extension = "txt",
                        Confidence = "Low",
                        Score = 35
                    },
                    new ContentTypeDetectionCandidate
                    {
                        Extension = "ps1",
                        Confidence = "High",
                        Score = 82,
                        IsDangerous = true
                    }
                }
            },
            GuessedExtension = "ps1",
            NameIssues = NameIssues.ExtensionMismatch
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(48, assessed.Score);
        Assert.Contains("Name.ExtensionMismatch", assessed.Codes);
        Assert.Contains("Type.LowConfidenceRisk", assessed.Codes);
        Assert.Contains("Type.AmbiguousCandidates", assessed.Codes);
        Assert.Contains("Type.DangerousAlternative", assessed.Codes);
        Assert.Contains("Type.GuessedSubtypeRisk", assessed.Codes);
        Assert.Equal(10, assessed.Factors["Type.LowConfidenceRisk"]);
        Assert.Equal(8, assessed.Factors["Type.AmbiguousCandidates"]);
        Assert.Equal(12, assessed.Factors["Type.DangerousAlternative"]);
        Assert.Equal(8, assessed.Factors["Type.GuessedSubtypeRisk"]);
    }

    [Fact]
    public void Assess_Dangerous_Extension_Only_Detection_Adds_Type_ExtensionOnlyRisk()
    {
        var analysis = new FileAnalysis
        {
            Detection = new ContentTypeDetectionResult
            {
                Extension = "ps1",
                Confidence = "Low",
                Reason = "extension:ps1",
                IsDangerous = true
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(12, assessed.Score);
        Assert.Contains("Type.ExtensionOnlyRisk", assessed.Codes);
        Assert.DoesNotContain("Type.LowConfidenceRisk", assessed.Codes);
        Assert.Equal(12, assessed.Factors["Type.ExtensionOnlyRisk"]);
    }

    [Fact]
    public void Assess_Harmless_LowConfidence_Text_Does_Not_Add_Type_Uncertainty_Code()
    {
        var analysis = new FileAnalysis
        {
            Detection = new ContentTypeDetectionResult
            {
                Extension = "txt",
                Confidence = "Low",
                Reason = "text:plain"
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(0, assessed.Score);
        Assert.DoesNotContain("Type.LowConfidenceRisk", assessed.Codes);
        Assert.DoesNotContain("Type.AmbiguousCandidates", assessed.Codes);
    }

    [Fact]
    public void Assess_Risky_Detection_With_Validation_Timeout_Adds_Validation_Uncertain_Code()
    {
        var analysis = new FileAnalysis
        {
            Detection = new ContentTypeDetectionResult
            {
                Extension = "ps1",
                Confidence = "Medium",
                Reason = "text:ps1",
                ValidationStatus = "timeout",
                IsDangerous = true,
                Candidates = new[]
                {
                    new ContentTypeDetectionCandidate
                    {
                        Extension = "ps1",
                        Confidence = "Medium",
                        Score = 72,
                        IsDangerous = true
                    },
                    new ContentTypeDetectionCandidate
                    {
                        Extension = "txt",
                        Confidence = "Low",
                        Score = 41
                    }
                }
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(16, assessed.Score);
        Assert.Contains("Type.AmbiguousCandidates", assessed.Codes);
        Assert.Contains("Type.ValidationUncertain", assessed.Codes);
        Assert.Equal(8, assessed.Factors["Type.ValidationUncertain"]);
    }

    [Fact]
    public void Assess_Detected_Dangerous_Mismatch_Adds_DangerousMismatch_Code()
    {
        var analysis = new FileAnalysis
        {
            Detection = new ContentTypeDetectionResult
            {
                Extension = "ps1",
                MimeType = "text/x-powershell",
                Confidence = "High",
                Reason = "text:ps1",
                IsDangerous = true
            },
            NameIssues = NameIssues.ExtensionMismatch
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(40, assessed.Score);
        Assert.Contains("Name.ExtensionMismatch", assessed.Codes);
        Assert.Contains("Type.DangerousMismatch", assessed.Codes);
        Assert.Equal(30, assessed.Factors["Type.DangerousMismatch"]);
    }

    [Fact]
    public void Assess_Archive_With_Embedded_Installer_Gets_Installer_Container_Penalty()
    {
        var analysis = new FileAnalysis
        {
            Flags = ContentFlags.ContainerContainsInstallers
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(25, assessed.Score);
        Assert.Contains("Archive.ContainsInstallers", assessed.Codes);
        Assert.Equal(25, assessed.Factors["Archive.ContainsInstallers"]);
    }

    [Fact]
    public void Assess_Archive_With_Embedded_Installer_Does_Not_Add_Generic_Executable_Container_Penalty()
    {
        var analysis = new FileAnalysis
        {
            Flags = ContentFlags.ContainerContainsExecutables | ContentFlags.ContainerContainsInstallers
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(25, assessed.Score);
        Assert.Contains("Archive.ContainsInstallers", assessed.Codes);
        Assert.DoesNotContain("Archive.ContainsExecutables", assessed.Codes);
        Assert.Equal(25, assessed.Factors["Archive.ContainsInstallers"]);
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

    [Fact]
    public void ToPolicySummaryView_Exposes_TopDrivers_Categories_And_RecommendedAction()
    {
        var analysis = new FileAnalysis
        {
            Assessment = new AssessmentResult
            {
                Score = 55,
                Decision = AssessmentDecision.Warn,
                Codes = new[] { "Secret.JWT", "Name.DoubleExtension" },
                Factors = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Secret.JWT"] = 40,
                    ["Name.DoubleExtension"] = 15
                }
            },
            AssessmentProfiles = new MultiAssessmentResult
            {
                Strict = new AssessmentResult { Score = 55, Decision = AssessmentDecision.Block },
                Balanced = new AssessmentResult { Score = 55, Decision = AssessmentDecision.Warn },
                Lenient = new AssessmentResult { Score = 55, Decision = AssessmentDecision.Allow }
            },
            Detection = new ContentTypeDetectionResult
            {
                Extension = "txt",
                MimeType = "text/plain"
            }
        };

        var view = analysis.ToPolicySummaryView(@"C:\sample.txt");

        Assert.Equal(55, view.Score);
        Assert.Equal("Warn", view.Decision);
        Assert.Equal("Block", view.DecisionStrict);
        Assert.Equal("Warn", view.DecisionBalanced);
        Assert.Equal("Allow", view.DecisionLenient);
        Assert.Contains("JWT", view.TopDrivers);
        Assert.Contains("Secrets", view.Categories);
        Assert.Contains("manual review", view.RecommendedAction, StringComparison.OrdinalIgnoreCase);
        Assert.False(view.SafeForAutomation);
    }

    [Fact]
    public void ReportView_From_Populates_PolicyAssessment_Fields()
    {
        var analysis = new FileAnalysis
        {
            Assessment = new AssessmentResult
            {
                Score = 0,
                Decision = AssessmentDecision.Allow,
                Codes = new[] { "DotNet.StrongName" },
                Factors = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
                {
                    ["DotNet.StrongName"] = -5
                }
            }
        };

        var report = ReportView.From(analysis);

        Assert.Equal("Allow", report.AssessmentDecision);
        Assert.DoesNotContain("(0)", report.AssessmentSummary ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("Allow automatically and keep routine logging.", report.AssessmentRecommendedAction);
        Assert.True(report.AssessmentSafeForAutomation);
    }

    [Fact]
    public void Analyze_Timestamped_Service_Log_Does_Not_Add_Ambiguous_Type_Code()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".log");

        try
        {
            File.WriteAllText(path,
                "2026-03-17T18:00:00 INFO Startup complete for worker C:\\TierBridge\\agent\\worker.exe\r\n" +
                "2026-03-17T18:00:01 WARN Fetching https://contoso.example/bootstrap.json\r\n" +
                "2026-03-17T18:00:02 WARN Fetching https://cdn.contoso.example/app.js for worker update\r\n" +
                "2026-03-17T18:00:03 ERROR Retry scheduled for \\\\fileserver\\drop\\package.zip\r\n");

            var analysis = FileInspector.Analyze(path);

            Assert.NotNull(analysis.Detection);
            Assert.Equal("log", analysis.Detection!.Extension);
            Assert.Equal("Medium", analysis.Detection.Confidence);
            Assert.Equal("text:log-levels", analysis.Detection.Reason);
            Assert.NotNull(analysis.Assessment);
            Assert.DoesNotContain("Type.AmbiguousCandidates", analysis.Assessment!.Codes);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }
}
