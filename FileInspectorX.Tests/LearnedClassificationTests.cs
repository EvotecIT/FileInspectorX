using System.Text;
using System.IO.Compression;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class LearnedClassificationTests
{
    [Fact]
    public void Detect_RejectsUndefinedLearnedClassificationMode()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => FileInspector.Detect(
                Encoding.UTF8.GetBytes("plain text"),
                new FileInspector.DetectionOptions {
                    LearnedClassificationMode = (LearnedClassificationMode)999
                }));
    }

    [Fact]
    public void Inspect_DetectOnlyUsesLearnedTextKind()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "fn main() { println!(\"hello\"); }");

            var result = FileInspector.Inspect(
                path,
                new FileInspector.DetectionOptions {
                    DetectOnly = true,
                    LearnedClassifier = new StubClassifier(CreatePrediction("rust", "rs")),
                    LearnedClassificationMode = LearnedClassificationMode.Assist
                });

            Assert.Equal("rs", result.Detection?.Extension);
            Assert.Equal(ContentKind.Text, result.Kind);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Detect_DefaultDoesNotInvokeLearnedClassifier()
    {
        var classifier = new StubClassifier(CreatePrediction("javascript", "js"));

        var result = FileInspector.Detect(
            Encoding.UTF8.GetBytes("hello world this is ordinary prose"),
            new FileInspector.DetectionOptions { LearnedClassifier = classifier });

        Assert.NotNull(result);
        Assert.Equal(0, classifier.CallCount);
        Assert.Null(result!.LearnedClassification);
    }

    [Fact]
    public void Detect_AssistPromotesGenericLowConfidenceDetection()
    {
        var classifier = new StubClassifier(CreatePrediction("javascript", "js"));

        var result = FileInspector.Detect(
            Encoding.UTF8.GetBytes("hello world this is ordinary prose"),
            new FileInspector.DetectionOptions
            {
                LearnedClassifier = classifier,
                LearnedClassificationMode = LearnedClassificationMode.Assist
            });

        Assert.NotNull(result);
        Assert.Equal("js", result!.Extension);
        Assert.Equal(LearnedClassificationDisposition.Promoted, result.LearnedClassification!.Disposition);
        Assert.Null(result.Score);
        Assert.Equal("js", result.Candidates![0].Extension);
        Assert.Equal(0, result.Candidates[0].Score);
        Assert.Contains(result.Alternatives!, candidate => candidate.Extension == "txt");
    }

    [Fact]
    public void Detect_StrongDeterministicEvidenceWinsAndConflictIsVisible()
    {
        var classifier = new StubClassifier(CreatePrediction("javascript", "js"));
        var png = TestHelpers.CreateMinimalPng();

        var result = FileInspector.Detect(
            png,
            new FileInspector.DetectionOptions
            {
                LearnedClassifier = classifier,
                LearnedClassificationMode = LearnedClassificationMode.Assist
            });

        Assert.NotNull(result);
        Assert.Equal("png", result!.Extension);
        Assert.Equal(LearnedClassificationDisposition.Conflict, result.LearnedClassification!.Disposition);
        Assert.Equal("png", result.LearnedClassification.DeterministicExtension);
    }

    [Fact]
    public void Detect_CanonicalExtensionWinsOverGenericProviderLabel()
    {
        var prediction = CreatePrediction("unknown", "exe");
        prediction.IsText = false;
        prediction.MimeType = "application/vnd.microsoft.portable-executable";
        var png = TestHelpers.CreateMinimalPng();

        var result = FileInspector.Detect(
            png,
            new FileInspector.DetectionOptions
            {
                LearnedClassifier = new StubClassifier(prediction),
                LearnedClassificationMode = LearnedClassificationMode.Assist
            });

        Assert.NotNull(result);
        Assert.Equal("png", result!.Extension);
        Assert.Equal(LearnedClassificationDisposition.Conflict, result.LearnedClassification!.Disposition);
        Assert.Contains(result.Candidates!, candidate => candidate.Extension == "exe");
    }

    [Fact]
    public void Detect_ExtensionlessLearnedLabelIsSupplemental()
    {
        var prediction = new LearnedContentPrediction
        {
            Provider = "Test",
            ModelId = "test-v1",
            RawLabel = "cad",
            OutputLabel = "cad",
            Extension = null,
            ExtensionAliases = Array.Empty<string>(),
            MimeType = null,
            Probability = 0.99,
            Threshold = 0.5,
            ThresholdMet = true,
            PredictionMode = "HighConfidence",
            IsText = false
        };
        var png = TestHelpers.CreateMinimalPng();

        var result = FileInspector.Detect(
            png,
            new FileInspector.DetectionOptions
            {
                LearnedClassifier = new StubClassifier(prediction),
                LearnedClassificationMode = LearnedClassificationMode.Assist
            });

        Assert.NotNull(result);
        Assert.Equal("png", result!.Extension);
        Assert.Equal(LearnedClassificationDisposition.Supplemental, result.LearnedClassification!.Disposition);
        Assert.DoesNotContain(
            result.Candidates ?? Array.Empty<ContentTypeDetectionCandidate>(),
            candidate => string.IsNullOrWhiteSpace(candidate.Extension));
    }

    [Fact]
    public void Detect_AssistRecordsProviderFailure()
    {
        var result = FileInspector.Detect(
            Encoding.UTF8.GetBytes("plain text"),
            new FileInspector.DetectionOptions
            {
                LearnedClassifier = new ThrowingClassifier(),
                LearnedClassificationMode = LearnedClassificationMode.Assist
            });

        Assert.NotNull(result);
        Assert.Equal(LearnedClassificationDisposition.Failed, result!.LearnedClassification!.Disposition);
        Assert.Equal("provider-failed:InvalidOperationException", result.LearnedClassification.Message);
    }

    [Fact]
    public void Detect_AssistRecordsProviderLearnedClassificationException()
    {
        var result = FileInspector.Detect(
            Encoding.UTF8.GetBytes("plain text"),
            new FileInspector.DetectionOptions
            {
                LearnedClassifier = new LearnedExceptionClassifier(),
                LearnedClassificationMode = LearnedClassificationMode.Assist
            });

        Assert.NotNull(result);
        Assert.Equal(LearnedClassificationDisposition.Failed, result!.LearnedClassification!.Disposition);
        Assert.Equal("provider-failed:LearnedClassificationException", result.LearnedClassification.Message);
    }

    [Fact]
    public void Detect_RequiredPropagatesProviderFailure()
    {
        var options = new FileInspector.DetectionOptions
        {
            LearnedClassifier = new ThrowingClassifier(),
            LearnedClassificationMode = LearnedClassificationMode.Required
        };

        Assert.Throws<LearnedClassificationException>(
            () => FileInspector.Detect(Encoding.UTF8.GetBytes("plain text"), options));
    }

    [Fact]
    public void Detect_PathRequiredPropagatesFileOpenFailure()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        var options = new FileInspector.DetectionOptions
        {
            LearnedClassifier = new StubClassifier(CreatePrediction("javascript", "js")),
            LearnedClassificationMode = LearnedClassificationMode.Required
        };

        Assert.Throws<LearnedClassificationException>(
            () => FileInspector.Detect(path, options));
    }

    [Fact]
    public void Detect_PathArbitratesAfterPeFamilyRefinement()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".exe");
        File.WriteAllBytes(path, CreateMinimalPeDll());
        try
        {
            var result = FileInspector.Detect(
                path,
                new FileInspector.DetectionOptions
                {
                    LearnedClassifier = new StubClassifier(CreatePrediction("executable", "exe")),
                    LearnedClassificationMode = LearnedClassificationMode.Assist
                });

            Assert.NotNull(result);
            Assert.Equal("dll", result!.Extension);
            Assert.Equal(LearnedClassificationDisposition.Conflict, result.LearnedClassification!.Disposition);
            Assert.Equal("dll", result.LearnedClassification.DeterministicExtension);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Detect_StreamArbitratesAfterStructuredTextValidation()
    {
        using var content = new MemoryStream(Encoding.UTF8.GetBytes("{ \"value\": ] }"));

        var result = FileInspector.Detect(
            content,
            new FileInspector.DetectionOptions
            {
                LearnedClassifier = new StubClassifier(CreatePrediction("javascript", "js")),
                LearnedClassificationMode = LearnedClassificationMode.Assist
            },
            declaredExtension: "json");

        Assert.NotNull(result);
        Assert.Equal("json", result!.Extension);
        Assert.Equal("failed", result.ValidationStatus);
        Assert.Contains("json:validation-error", result.Reason);
        Assert.Equal("Low", result.LearnedClassification!.DeterministicConfidence);
        Assert.Contains("json:validation-error", result.LearnedClassification.DeterministicReason);
    }

    [Fact]
    public void Detect_DeclaredTextBiasRemainsFillableBySpecificLearnedPrediction()
    {
        var result = FileInspector.Detect(
            Encoding.UTF8.GetBytes("ordinary prose"),
            new FileInspector.DetectionOptions
            {
                LearnedClassifier = new StubClassifier(CreatePrediction("javascript", "js")),
                LearnedClassificationMode = LearnedClassificationMode.Assist
            },
            declaredExtension: "md");

        Assert.NotNull(result);
        Assert.Equal("js", result!.Extension);
        Assert.Equal(LearnedClassificationDisposition.Promoted, result.LearnedClassification!.Disposition);
        Assert.Equal("md", result.LearnedClassification.DeterministicExtension);
        Assert.Contains("bias:decl:md", result.LearnedClassification.DeterministicReason);
        Assert.Contains(result.Candidates!, candidate => candidate.Extension == "md");
    }

    [Fact]
    public void Detect_AssistRejectsNonSeekableStreamBeforeInvokingLearnedClassifier()
    {
        var bytes = Encoding.UTF8.GetBytes(new string('a', Settings.HeaderReadBytes + 4096));
        var classifier = new RecordingClassifier(CreatePrediction("javascript", "js"));
        using var content = new NonSeekableReadStream(bytes);

        var result = FileInspector.Detect(
            content,
            new FileInspector.DetectionOptions
            {
                LearnedClassifier = classifier,
                LearnedClassificationMode = LearnedClassificationMode.Assist
            });

        Assert.NotNull(result);
        Assert.Null(classifier.Content);
        Assert.Equal(LearnedClassificationDisposition.Failed, result!.LearnedClassification!.Disposition);
        Assert.Equal("provider-failed:NotSupportedException", result.LearnedClassification.Message);
    }

    [Fact]
    public void Detect_RequiredRejectsNonSeekableStreamBeforeInvokingLearnedClassifier()
    {
        var classifier = new RecordingClassifier(CreatePrediction("javascript", "js"));
        using var content = new NonSeekableReadStream(Encoding.UTF8.GetBytes("plain text"));
        var options = new FileInspector.DetectionOptions
        {
            LearnedClassifier = classifier,
            LearnedClassificationMode = LearnedClassificationMode.Required
        };

        Assert.Throws<LearnedClassificationException>(
            () => FileInspector.Detect(content, options));
        Assert.Null(classifier.Content);
    }

    [Fact]
    public void Detect_LearnedPredictionCanAgreeWithDeterministicZipSubtype()
    {
        var path = CreateZip(
            ("AndroidManifest.xml", "<manifest />"),
            ("classes.dex", "dex"));
        try
        {
            var result = FileInspector.Detect(
                path,
                new FileInspector.DetectionOptions
                {
                    LearnedClassifier = new StubClassifier(CreatePrediction("apk", "apk")),
                    LearnedClassificationMode = LearnedClassificationMode.Assist
                });

            Assert.NotNull(result);
            Assert.Equal("zip", result!.Extension);
            Assert.Equal("apk", result.GuessedExtension);
            Assert.Equal(LearnedClassificationDisposition.Agreed, result.LearnedClassification!.Disposition);
            Assert.Equal("apk", result.LearnedClassification.DeterministicAgreementExtension);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Detect_ExtensionlessLearnedOutputIsSupplementalToMachO()
    {
        var result = FileInspector.Detect(
            new byte[] {
                0xFE, 0xED, 0xFA, 0xCE,
                0x00, 0x00, 0x00, 0x07,
                0x00, 0x00, 0x00, 0x03,
                0x00, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            },
            new FileInspector.DetectionOptions
            {
                LearnedClassifier = new StubClassifier(CreatePrediction("macho", extension: null)),
                LearnedClassificationMode = LearnedClassificationMode.Assist
            });

        Assert.NotNull(result);
        Assert.Equal("macho", result!.Extension);
        Assert.Equal(LearnedClassificationDisposition.Supplemental, result.LearnedClassification!.Disposition);
        Assert.Null(result.LearnedClassification.DeterministicAgreementExtension);
    }

    [Fact]
    public void Detect_OutputLabelDoesNotOverrideCanonicalExtensionAgreement()
    {
        var png = TestHelpers.CreateMinimalPng();
        var prediction = CreatePrediction("png", "exe", "exe");

        var result = FileInspector.Detect(
            png,
            new FileInspector.DetectionOptions
            {
                LearnedClassifier = new StubClassifier(prediction),
                LearnedClassificationMode = LearnedClassificationMode.Assist
            });

        Assert.NotNull(result);
        Assert.Equal("png", result!.Extension);
        Assert.Equal(LearnedClassificationDisposition.Conflict, result.LearnedClassification!.Disposition);
        Assert.Null(result.LearnedClassification.DeterministicAgreementExtension);
    }

    [Fact]
    public void Detect_ExtensionlessSpecificLearnedOutputIsSupplemental()
    {
        var png = TestHelpers.CreateMinimalPng();

        var result = FileInspector.Detect(
            png,
            new FileInspector.DetectionOptions
            {
                LearnedClassifier = new StubClassifier(CreatePrediction("macho", extension: null)),
                LearnedClassificationMode = LearnedClassificationMode.Assist
            });

        Assert.NotNull(result);
        Assert.Equal("png", result!.Extension);
        Assert.Equal(LearnedClassificationDisposition.Supplemental, result.LearnedClassification!.Disposition);
    }

    [Fact]
    public void Detect_TiffAndTifExtensionsAgree()
    {
        var result = FileInspector.Detect(
            new byte[] { 0x49, 0x49, 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            new FileInspector.DetectionOptions
            {
                LearnedClassifier = new StubClassifier(CreatePrediction("tiff", "tiff")),
                LearnedClassificationMode = LearnedClassificationMode.Assist
            });

        Assert.NotNull(result);
        Assert.Equal("tif", result!.Extension);
        Assert.Equal(LearnedClassificationDisposition.Agreed, result.LearnedClassification!.Disposition);
        Assert.Equal("tif", result.LearnedClassification.DeterministicAgreementExtension);
    }

    [Fact]
    public void Detect_BatAndCmdExtensionsAgree()
    {
        var result = FileInspector.Detect(
            Encoding.UTF8.GetBytes("@echo off\r\nsetlocal\r\necho test\r\n"),
            new FileInspector.DetectionOptions
            {
                LearnedClassifier = new StubClassifier(CreatePrediction("cmd", "cmd")),
                LearnedClassificationMode = LearnedClassificationMode.Assist
            });

        Assert.NotNull(result);
        Assert.Equal("bat", result!.Extension);
        Assert.Equal(LearnedClassificationDisposition.Agreed, result.LearnedClassification!.Disposition);
        Assert.Equal("bat", result.LearnedClassification.DeterministicAgreementExtension);
    }

    [Fact]
    public void Detect_LearnedCertificateAliasesAgreeWithDeterministicCer()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=FileInspectorX Learned Alias Test",
            rsa,
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
        var bytes = certificate.Export(
            System.Security.Cryptography.X509Certificates.X509ContentType.Cert);

        var result = FileInspector.Detect(
            bytes,
            new FileInspector.DetectionOptions
            {
                LearnedClassifier = new StubClassifier(
                    CreatePrediction("crt", "der", "der", "cer", "crt")),
                LearnedClassificationMode = LearnedClassificationMode.Assist
            });

        Assert.NotNull(result);
        Assert.Equal("cer", result!.Extension);
        Assert.Equal(LearnedClassificationDisposition.Agreed, result.LearnedClassification!.Disposition);
        Assert.Equal("cer", result.LearnedClassification.DeterministicAgreementExtension);
    }

    [Fact]
    public void Detect_LearnedHeifAliasesAgreeWithDeterministicHeic()
    {
        var bytes = new byte[16];
        bytes[3] = 16;
        Encoding.ASCII.GetBytes("ftyp").CopyTo(bytes, 4);
        Encoding.ASCII.GetBytes("heic").CopyTo(bytes, 8);

        var result = FileInspector.Detect(
            bytes,
            new FileInspector.DetectionOptions
            {
                LearnedClassifier = new StubClassifier(
                    CreatePrediction("heif", "heif", "heif", "heifs", "heic", "heics")),
                LearnedClassificationMode = LearnedClassificationMode.Assist
            });

        Assert.NotNull(result);
        Assert.Equal("heic", result!.Extension);
        Assert.Equal(LearnedClassificationDisposition.Agreed, result.LearnedClassification!.Disposition);
        Assert.Equal("heic", result.LearnedClassification.DeterministicAgreementExtension);
    }

    [Fact]
    public void Analyze_PathArbitratesAfterFullDeterministicRefinement()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".exe");
        File.WriteAllBytes(path, CreateMinimalPeDll());
        try
        {
            var result = FileInspector.Analyze(
                path,
                new FileInspector.DetectionOptions
                {
                    LearnedClassifier = new StubClassifier(CreatePrediction("executable", "exe")),
                    LearnedClassificationMode = LearnedClassificationMode.Assist,
                    IncludeAssessment = false,
                    IncludeAuthenticode = false,
                    IncludePermissions = false,
                    IncludeShellProperties = false
                });

            Assert.Equal("dll", result.Detection!.Extension);
            Assert.Equal(LearnedClassificationDisposition.Conflict, result.Detection.LearnedClassification!.Disposition);
            Assert.Equal("dll", result.Detection.LearnedClassification.DeterministicExtension);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Analyze_PreservesMacroSubtypeAndUsesItForLearnedAgreement()
    {
        var path = CreateZip(
            ("[Content_Types].xml", "<Types />"),
            ("word/document.xml", "<document />"),
            ("word/vbaProject.bin", "macro"));
        try
        {
            var result = FileInspector.Analyze(
                path,
                new FileInspector.DetectionOptions
                {
                    LearnedClassifier = new StubClassifier(CreatePrediction("docm", "docm")),
                    LearnedClassificationMode = LearnedClassificationMode.Assist,
                    IncludeAssessment = false,
                    IncludeAuthenticode = false,
                    IncludePermissions = false,
                    IncludeShellProperties = false
                });

            Assert.Equal("docx", result.Detection!.Extension);
            Assert.Equal("docm", result.GuessedExtension);
            Assert.Equal("docm", result.Detection.GuessedExtension);
            Assert.Equal(LearnedClassificationDisposition.Agreed, result.Detection.LearnedClassification!.Disposition);
            Assert.Equal("docm", result.Detection.LearnedClassification.DeterministicAgreementExtension);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Analyze_LearnedOnlyDetectionBuildsAssessment(bool enrichUnknown)
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        File.WriteAllBytes(path, Array.Empty<byte>());
        try
        {
            var result = FileInspector.Analyze(
                path,
                new FileInspector.DetectionOptions
                {
                    LearnedClassifier = new StubClassifier(CreatePrediction("javascript", "js")),
                    LearnedClassificationMode = LearnedClassificationMode.Assist,
                    ComputeSha256 = enrichUnknown,
                    MagicHeaderBytes = enrichUnknown ? 8 : 0,
                    IncludeAuthenticode = false,
                    IncludePermissions = false,
                    IncludeShellProperties = false
                });

            Assert.Equal("js", result.Detection!.Extension);
            Assert.Equal(LearnedClassificationDisposition.Promoted, result.Detection.LearnedClassification!.Disposition);
            Assert.NotNull(result.Assessment);
            Assert.NotNull(result.AssessmentProfiles);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Analyze_ReconcilesLearnedOnlyPromotionWithDeclaredInstallerAnalysis()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".msi");
        File.WriteAllBytes(path, Array.Empty<byte>());
        try
        {
            var result = FileInspector.Analyze(
                path,
                new FileInspector.DetectionOptions
                {
                    LearnedClassifier = new StubClassifier(CreatePrediction("javascript", "js")),
                    LearnedClassificationMode = LearnedClassificationMode.Assist,
                    IncludeAssessment = false,
                    IncludeAuthenticode = false,
                    IncludePermissions = false,
                    IncludeShellProperties = false
                });

            Assert.Equal("msi", result.Detection!.Extension);
            Assert.Equal(
                LearnedClassificationDisposition.Conflict,
                result.Detection.LearnedClassification!.Disposition);
            Assert.Equal("msi", result.Detection.LearnedClassification.DeterministicExtension);
            Assert.Contains(result.Detection.Candidates!, candidate => candidate.Extension == "js");
            Assert.Null(result.ScriptLanguage);
            Assert.Null(result.TextSubtype);
            Assert.True((result.Flags & ContentFlags.IsScript) == 0);
            Assert.True((result.Flags & ContentFlags.ScriptsPotentiallyDangerous) == 0);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Analyze_BinaryLearnedPromotionDoesNotSkipDeterministicTextStructure()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(
            path,
            "function RenderReport {\n" +
            "    param($Name)\n" +
            "    Get-Content $Name\n" +
            "}\n");
        try
        {
            var prediction = CreatePrediction("portable-executable", "exe");
            prediction.IsText = false;
            prediction.MimeType = "application/vnd.microsoft.portable-executable";

            var result = FileInspector.Analyze(
                path,
                new FileInspector.DetectionOptions
                {
                    LearnedClassifier = new StubClassifier(prediction),
                    LearnedClassificationMode = LearnedClassificationMode.Assist,
                    IncludeAssessment = false,
                    IncludeAuthenticode = false,
                    IncludePermissions = false,
                    IncludeShellProperties = false
                });

            Assert.Equal("ps1", result.Detection!.Extension);
            Assert.Equal(
                LearnedClassificationDisposition.Conflict,
                result.Detection.LearnedClassification!.Disposition);
            Assert.Equal("powershell", result.ScriptLanguage);
            Assert.Contains("ps:structure", result.SecurityFindings!);
            Assert.True((result.Flags & ContentFlags.IsScript) != 0);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Analyze_LearnedPromotionRefreshesNameAndScriptAnalysis()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(path, "ordinary prose without deterministic script structure");
        try
        {
            var result = FileInspector.Analyze(
                path,
                new FileInspector.DetectionOptions
                {
                    LearnedClassifier = new StubClassifier(CreatePrediction("javascript", "js")),
                    LearnedClassificationMode = LearnedClassificationMode.Assist,
                    IncludeAuthenticode = false,
                    IncludePermissions = false,
                    IncludeShellProperties = false
                });

            Assert.Equal("js", result.Detection!.Extension);
            Assert.True((result.NameIssues & NameIssues.ExtensionMismatch) != 0);
            Assert.Equal("javascript", result.ScriptLanguage);
            Assert.True((result.Flags & ContentFlags.IsScript) != 0);
            Assert.True((result.Flags & ContentFlags.ScriptsPotentiallyDangerous) != 0);
            Assert.Null(result.ScriptCmdlets);
            Assert.NotNull(result.Assessment);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Analyze_SuffixlessLearnedJavaScriptRunsMinificationAnalysis()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        File.WriteAllText(path, string.Concat(Enumerable.Repeat("a=1;b=2;", 300)));
        try
        {
            var result = FileInspector.Analyze(
                path,
                new FileInspector.DetectionOptions
                {
                    LearnedClassifier = new StubClassifier(CreatePrediction("javascript", "js")),
                    LearnedClassificationMode = LearnedClassificationMode.Assist,
                    IncludeAssessment = false,
                    IncludeAuthenticode = false,
                    IncludePermissions = false,
                    IncludeShellProperties = false
                });

            Assert.Equal("js", result.Detection!.Extension);
            Assert.Equal(
                LearnedClassificationDisposition.Promoted,
                result.Detection.LearnedClassification!.Disposition);
            Assert.True((result.Flags & ContentFlags.JsLooksMinified) != 0);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void RefreshDerivedAnalysisAfterLearnedPromotion_RecomputesPowerShellCmdlets()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(path, "Get-Content ./input.txt");
        try
        {
            var analysis = new FileAnalysis
            {
                ScriptCmdlets = new[] { "stale-cmdlet" }
            };
            var result = new ContentTypeDetectionResult
            {
                Extension = "ps1",
                MimeType = "text/plain",
                Confidence = "High",
                Reason = "learned:stub:powershell",
                LearnedClassification = new LearnedClassificationEvidence
                {
                    Disposition = LearnedClassificationDisposition.Promoted,
                    Prediction = CreatePrediction("powershell", "ps1")
                }
            };

            FileInspector.RefreshDerivedAnalysisAfterLearnedPromotion(analysis, path, result);

            Assert.Equal("powershell", analysis.ScriptLanguage);
            Assert.Contains("get-content", analysis.ScriptCmdlets!);
            Assert.DoesNotContain("stale-cmdlet", analysis.ScriptCmdlets!);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void RefreshDerivedAnalysisAfterLearnedPromotion_ClearsNonPowerShellCmdlets()
    {
        var analysis = new FileAnalysis
        {
            ScriptCmdlets = new[] { "stale-cmdlet" }
        };
        var result = new ContentTypeDetectionResult
        {
            Extension = "js",
            MimeType = "text/javascript",
            Confidence = "High",
            Reason = "learned:stub:javascript",
            LearnedClassification = new LearnedClassificationEvidence
            {
                Disposition = LearnedClassificationDisposition.Promoted,
                Prediction = CreatePrediction("javascript", "js")
            }
        };

        FileInspector.RefreshDerivedAnalysisAfterLearnedPromotion(
            analysis,
            "unused.txt",
            result);

        Assert.Equal("javascript", analysis.ScriptLanguage);
        Assert.Null(analysis.ScriptCmdlets);
    }

    [Fact]
    public void Analyze_ReconcilesLearnedPromotionWhenStrongAnalysisDerivesPowerShell()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(
            path,
            "ordinary preamble that keeps the detector's short read generic\n" +
            "function RenderReport {\n" +
            "    param($Name)\n" +
            "    \"Report for $Name\"\n" +
            "}\n");
        try
        {
            var deterministic = FileInspector.Analyze(
                path,
                new FileInspector.DetectionOptions
                {
                    MagicHeaderBytes = 24,
                    IncludeAssessment = false,
                    IncludeAuthenticode = false,
                    IncludePermissions = false,
                    IncludeShellProperties = false
                });
            var result = FileInspector.Analyze(
                path,
                new FileInspector.DetectionOptions
                {
                    LearnedClassifier = new StubClassifier(CreatePrediction("yaml", "yaml")),
                    LearnedClassificationMode = LearnedClassificationMode.Assist,
                    MagicHeaderBytes = 24,
                    IncludeAssessment = false,
                    IncludeAuthenticode = false,
                    IncludePermissions = false,
                    IncludeShellProperties = false
                });

            Assert.Equal("ps1", result.Detection!.Extension);
            Assert.Equal("text/x-powershell", result.Detection.MimeType);
            Assert.Equal(deterministic.Detection!.Confidence, result.Detection.Confidence);
            Assert.Equal(deterministic.Detection.Reason, result.Detection.Reason);
            Assert.Equal(deterministic.Detection.ReasonDetails, result.Detection.ReasonDetails);
            Assert.Equal(deterministic.Detection.Score, result.Detection.Score);
            Assert.Equal(LearnedClassificationDisposition.Conflict, result.Detection.LearnedClassification!.Disposition);
            Assert.Equal("ps1", result.Detection.LearnedClassification.DeterministicExtension);
            Assert.Equal("deterministic-and-learned-disagree", result.Detection.LearnedClassification.Message);
            Assert.Equal("ps1", result.Detection.Candidates![0].Extension);
            Assert.Contains(result.Detection.Candidates, candidate => candidate.Extension == "yaml");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Detect_BinaryLearnedPromotionDoesNotRetainGenericTextMime()
    {
        var prediction = new LearnedContentPrediction
        {
            Provider = "Test",
            ModelId = "test-v1",
            RawLabel = "custom_binary",
            OutputLabel = "custom_binary",
            Extension = "custombin",
            Probability = 0.99,
            Threshold = 0.5,
            ThresholdMet = true,
            PredictionMode = "HighConfidence",
            IsText = false
        };

        var result = FileInspector.Detect(
            System.Text.Encoding.UTF8.GetBytes("ordinary generic text"),
            new FileInspector.DetectionOptions
            {
                LearnedClassifier = new StubClassifier(prediction),
                LearnedClassificationMode = LearnedClassificationMode.Assist
            });

        Assert.NotNull(result);
        Assert.Equal("custombin", result!.Extension);
        Assert.Equal("application/octet-stream", result.MimeType);
        Assert.Equal(LearnedClassificationDisposition.Promoted, result.LearnedClassification!.Disposition);
    }

    [Fact]
    public void Analyze_BinaryLearnedPromotionClearsDeclaredScriptMetadata()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".ps1");
        File.WriteAllText(path, "ordinary prose without deterministic script cues");
        try
        {
            var prediction = CreatePrediction("custom_binary", "custombin");
            prediction.IsText = false;
            prediction.MimeType = "application/octet-stream";

            var result = FileInspector.Analyze(
                path,
                new FileInspector.DetectionOptions
                {
                    LearnedClassifier = new StubClassifier(prediction),
                    LearnedClassificationMode = LearnedClassificationMode.Assist,
                    IncludeAssessment = false,
                    IncludeAuthenticode = false,
                    IncludePermissions = false,
                    IncludeShellProperties = false
                });

            Assert.Equal("custombin", result.Detection!.Extension);
            Assert.Equal(
                LearnedClassificationDisposition.Promoted,
                result.Detection.LearnedClassification!.Disposition);
            Assert.Null(result.ScriptLanguage);
            Assert.Null(result.TextSubtype);
            Assert.Equal(ContentFlags.None, result.Flags & (ContentFlags.IsScript | ContentFlags.ScriptsPotentiallyDangerous));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Analyze_LearnedTextPromotionRefreshesTextSubtype()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(path, "ordinary prose without deterministic markdown cues");
        try
        {
            var result = FileInspector.Analyze(
                path,
                new FileInspector.DetectionOptions
                {
                    LearnedClassifier = new StubClassifier(CreatePrediction("markdown", "md")),
                    LearnedClassificationMode = LearnedClassificationMode.Assist,
                    IncludeAssessment = false,
                    IncludeAuthenticode = false,
                    IncludePermissions = false,
                    IncludeShellProperties = false
                });

            Assert.Equal("md", result.Detection!.Extension);
            Assert.Equal("markdown", result.TextSubtype);
            Assert.Null(result.ScriptLanguage);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Analyze_LearnedTextPredictionSetsTextKindWithoutKnownExtensionOrMime()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        File.WriteAllBytes(path, Array.Empty<byte>());
        try
        {
            var prediction = CreatePrediction("custom_text", "customtxt");
            prediction.MimeType = "application/octet-stream";
            var result = FileInspector.Analyze(
                path,
                new FileInspector.DetectionOptions
                {
                    LearnedClassifier = new StubClassifier(prediction),
                    LearnedClassificationMode = LearnedClassificationMode.Assist,
                    IncludeAssessment = false,
                    IncludeAuthenticode = false,
                    IncludePermissions = false,
                    IncludeShellProperties = false
                });

            Assert.Equal(LearnedClassificationDisposition.Promoted, result.Detection!.LearnedClassification!.Disposition);
            Assert.Equal(ContentKind.Text, result.Kind);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Analyze_LearnedSvgTextPredictionKeepsImageKind()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        File.WriteAllBytes(path, Array.Empty<byte>());
        try
        {
            var prediction = CreatePrediction("svg", "svg");
            prediction.MimeType = "image/svg+xml";
            prediction.IsText = true;
            var result = FileInspector.Analyze(
                path,
                new FileInspector.DetectionOptions
                {
                    LearnedClassifier = new StubClassifier(prediction),
                    LearnedClassificationMode = LearnedClassificationMode.Assist,
                    IncludeAssessment = false,
                    IncludeAuthenticode = false,
                    IncludePermissions = false,
                    IncludeShellProperties = false
                });

            Assert.Equal(LearnedClassificationDisposition.Promoted, result.Detection!.LearnedClassification!.Disposition);
            Assert.Equal(ContentKind.Image, result.Kind);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Analyze_LearnedPromotionPreservesDeterministicMimeWhenPredictionOmitsIt()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(path, "ordinary prose without deterministic language cues");
        try
        {
            var prediction = CreatePrediction("solidity", "sol");
            prediction.MimeType = null;

            var result = FileInspector.Analyze(
                path,
                new FileInspector.DetectionOptions
                {
                    LearnedClassifier = new StubClassifier(prediction),
                    LearnedClassificationMode = LearnedClassificationMode.Assist,
                    IncludeAssessment = false,
                    IncludeAuthenticode = false,
                    IncludePermissions = false,
                    IncludeShellProperties = false
                });

            Assert.Equal(LearnedClassificationDisposition.Promoted, result.Detection!.LearnedClassification!.Disposition);
            Assert.Equal("sol", result.Detection.Extension);
            Assert.Equal("text/plain", result.Detection.MimeType);
            Assert.Equal("text/plain", result.Detection.Candidates![0].MimeType);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Analyze_ExtensionlessLearnedTextSupplementsGenericText()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(path, "FROM scratch\nRUN echo hello");
        try
        {
            var result = FileInspector.Analyze(
                path,
                new FileInspector.DetectionOptions
                {
                    LearnedClassifier = new StubClassifier(CreatePrediction("dockerfile", null)),
                    LearnedClassificationMode = LearnedClassificationMode.Assist,
                    IncludeAssessment = false,
                    IncludeAuthenticode = false,
                    IncludePermissions = false,
                    IncludeShellProperties = false
                });

            Assert.Equal("txt", result.Detection!.Extension);
            Assert.Equal(
                LearnedClassificationDisposition.Supplemental,
                result.Detection.LearnedClassification!.Disposition);
            Assert.Null(result.Detection.LearnedClassification.Message);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Analyze_CapturesLearnedPredictionOnceBeforeFullAnalysis()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(path, "ordinary prose");
        try
        {
            var classifier = new StubClassifier(CreatePrediction("markdown", "md"));
            var result = FileInspector.Analyze(
                path,
                new FileInspector.DetectionOptions
                {
                    LearnedClassifier = classifier,
                    LearnedClassificationMode = LearnedClassificationMode.Assist,
                    IncludeAssessment = false,
                    IncludeAuthenticode = false,
                    IncludePermissions = false,
                    IncludeShellProperties = false
                });

            Assert.NotNull(result.Detection!.LearnedClassification);
            Assert.Equal(1, classifier.CallCount);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void AnalyzeDirectory_RequiredPropagatesProviderFailure()
    {
        var directory = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")));
        File.WriteAllText(Path.Combine(directory.FullName, "sample.txt"), "plain text");
        try
        {
            var options = new FileInspector.DetectionOptions
            {
                LearnedClassifier = new ThrowingClassifier(),
                LearnedClassificationMode = LearnedClassificationMode.Required
            };

            Assert.Throws<LearnedClassificationException>(
                () => FileInspector.AnalyzeDirectory(directory.FullName, options: options).ToList());
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void AnalyzeDirectory_RejectsUndefinedLearnedClassificationMode()
    {
        var directory = Directory.CreateDirectory(
            Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")));
        try
        {
            File.WriteAllText(Path.Combine(directory.FullName, "sample.txt"), "plain text");
            var options = new FileInspector.DetectionOptions
            {
                LearnedClassificationMode = (LearnedClassificationMode)999
            };

            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                _ = FileInspector.AnalyzeDirectory(directory.FullName, options: options).ToList();
            });
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

#if NET8_0_OR_GREATER
    [Fact]
    public async Task AnalyzeDirectoryAsync_RequiredPropagatesProviderFailure()
    {
        var directory = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")));
        File.WriteAllText(Path.Combine(directory.FullName, "sample.txt"), "plain text");
        try
        {
            var options = new FileInspector.DetectionOptions
            {
                LearnedClassifier = new ThrowingClassifier(),
                LearnedClassificationMode = LearnedClassificationMode.Required
            };

            await Assert.ThrowsAsync<LearnedClassificationException>(async () =>
            {
                await foreach (var _ in FileInspector.AnalyzeDirectoryAsync(directory.FullName, options: options))
                {
                }
            });
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task AnalyzeDirectoryAsync_RejectsUndefinedLearnedClassificationMode()
    {
        var directory = Directory.CreateDirectory(
            Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")));
        try
        {
            File.WriteAllText(Path.Combine(directory.FullName, "sample.txt"), "plain text");
            var options = new FileInspector.DetectionOptions
            {
                LearnedClassificationMode = (LearnedClassificationMode)999
            };

            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () =>
            {
                await foreach (var _ in FileInspector.AnalyzeDirectoryAsync(
                                   directory.FullName,
                                   options: options))
                {
                }
            });
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task AnalyzeDirectoryAsync_SerializesClassifierWithoutConcurrencyContract()
    {
        var directory = Directory.CreateDirectory(
            Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")));
        try
        {
            for (var index = 0; index < 6; index++)
                File.WriteAllText(Path.Combine(directory.FullName, $"{index}.txt"), "plain text");

            var classifier = new ConcurrencyTrackingClassifier(
                CreatePrediction("text", "txt"));
            var options = new FileInspector.DetectionOptions
            {
                LearnedClassifier = classifier,
                LearnedClassificationMode = LearnedClassificationMode.Assist,
                IncludeAssessment = false,
                IncludeAuthenticode = false,
                IncludePermissions = false,
                IncludeShellProperties = false
            };

            var results = new List<FileAnalysis>();
            await foreach (var result in FileInspector.AnalyzeDirectoryAsync(
                               directory.FullName,
                               options: options,
                               maxDegreeOfParallelism: 4))
            {
                results.Add(result);
            }

            Assert.Equal(6, results.Count);
            Assert.Equal(6, classifier.CallCount);
            Assert.Equal(1, classifier.MaxObservedConcurrency);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }
#endif

    private static LearnedContentPrediction CreatePrediction(
        string label,
        string? extension,
        params string[] extensionAliases)
        => new()
        {
            Provider = "Test",
            ModelId = "test-v1",
            RawLabel = label,
            OutputLabel = label,
            Extension = extension,
            ExtensionAliases = extensionAliases,
            MimeType = "application/javascript",
            Probability = 0.99,
            Threshold = 0.5,
            ThresholdMet = true,
            PredictionMode = "HighConfidence",
            IsText = true
        };

    private static byte[] CreateMinimalPeDll()
    {
        var bytes = new byte[512];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        BitConverter.GetBytes(0x80).CopyTo(bytes, 0x3C);
        bytes[0x80] = (byte)'P';
        bytes[0x81] = (byte)'E';
        BitConverter.GetBytes((ushort)0x014C).CopyTo(bytes, 0x84);
        BitConverter.GetBytes((ushort)1).CopyTo(bytes, 0x86);
        BitConverter.GetBytes((ushort)0x00E0).CopyTo(bytes, 0x94);
        BitConverter.GetBytes((ushort)0x2000).CopyTo(bytes, 0x96);
        BitConverter.GetBytes((ushort)0x010B).CopyTo(bytes, 0x98);
        return bytes;
    }

    private static string CreateZip(params (string Name, string Content)[] entries)
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".zip");
        using var archive = ZipFile.Open(path, ZipArchiveMode.Create);
        foreach (var item in entries)
        {
            var entry = archive.CreateEntry(item.Name);
            using var writer = new StreamWriter(entry.Open());
            writer.Write(item.Content);
        }
        return path;
    }

    private sealed class StubClassifier : ILearnedContentClassifier
    {
        private readonly LearnedContentPrediction _prediction;

        internal StubClassifier(LearnedContentPrediction prediction)
        {
            _prediction = prediction;
        }

        internal int CallCount { get; private set; }

        public LearnedContentPrediction Predict(ReadOnlyMemory<byte> content)
        {
            CallCount++;
            return _prediction;
        }

        public LearnedContentPrediction Predict(Stream content)
        {
            CallCount++;
            return _prediction;
        }
    }

    private sealed class ThrowingClassifier : ILearnedContentClassifier
    {
        public LearnedContentPrediction Predict(ReadOnlyMemory<byte> content)
            => throw new InvalidOperationException("test");

        public LearnedContentPrediction Predict(Stream content)
            => throw new InvalidOperationException("test");
    }

    private sealed class LearnedExceptionClassifier : ILearnedContentClassifier
    {
        public LearnedContentPrediction Predict(ReadOnlyMemory<byte> content)
            => throw new LearnedClassificationException("test", new InvalidOperationException("inner"));

        public LearnedContentPrediction Predict(Stream content)
            => throw new LearnedClassificationException("test", new InvalidOperationException("inner"));
    }

    private sealed class RecordingClassifier : ILearnedContentClassifier
    {
        private readonly LearnedContentPrediction _prediction;

        internal RecordingClassifier(LearnedContentPrediction prediction) => _prediction = prediction;

        internal byte[]? Content { get; private set; }

        public LearnedContentPrediction Predict(ReadOnlyMemory<byte> content)
        {
            Content = content.ToArray();
            return _prediction;
        }

        public LearnedContentPrediction Predict(Stream content)
        {
            Assert.True(content.CanSeek);
            var originalPosition = content.Position;
            content.Position = 0;
            using var buffer = new MemoryStream();
            content.CopyTo(buffer);
            Content = buffer.ToArray();
            content.Position = originalPosition;
            return _prediction;
        }
    }

    private sealed class ConcurrencyTrackingClassifier : ILearnedContentClassifier
    {
        private readonly LearnedContentPrediction _prediction;
        private int _active;
        private int _callCount;
        private int _maxObservedConcurrency;

        internal ConcurrencyTrackingClassifier(LearnedContentPrediction prediction)
            => _prediction = prediction;

        internal int CallCount => _callCount;
        internal int MaxObservedConcurrency => _maxObservedConcurrency;

        public LearnedContentPrediction Predict(ReadOnlyMemory<byte> content)
            => PredictCore();

        public LearnedContentPrediction Predict(Stream content)
            => PredictCore();

        private LearnedContentPrediction PredictCore()
        {
            Interlocked.Increment(ref _callCount);
            var active = Interlocked.Increment(ref _active);
            int observed;
            while (active > (observed = _maxObservedConcurrency))
            {
                if (Interlocked.CompareExchange(
                        ref _maxObservedConcurrency,
                        active,
                        observed) == observed)
                {
                    break;
                }
            }

            try
            {
                Thread.Sleep(20);
                return _prediction;
            }
            finally
            {
                Interlocked.Decrement(ref _active);
            }
        }
    }

    private sealed class NonSeekableReadStream : Stream
    {
        private readonly MemoryStream _inner;

        internal NonSeekableReadStream(byte[] content)
            => _inner = new MemoryStream(content, writable: false);

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
            => _inner.Read(buffer, offset, count);

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                _inner.Dispose();
            base.Dispose(disposing);
        }
    }
}
