using System.IO.Compression;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

[Collection(nameof(DetectionSettingsCollection))]
public sealed class SecurityFindingRegressionTests
{
    [Fact]
    public void TruncatedJpeg2000ComponentDescriptorsAreRejectedWithoutThrowing()
    {
        var valid = TestHelpers.CreateMinimalJpeg2000();
        const int dataBoxOffset = 77;
        const int codestreamOffset = dataBoxOffset + 8;
        var crafted = new byte[codestreamOffset + 47];
        Array.Copy(valid, crafted, crafted.Length);
        TestHelpers.WriteUInt32BigEndian(crafted, dataBoxOffset, 55);
        TestHelpers.WriteUInt16BigEndian(crafted, codestreamOffset + 4, 44);
        TestHelpers.WriteUInt16BigEndian(crafted, codestreamOffset + 40, 2);

        var exception = Record.Exception(() => FileInspector.Detect(crafted));

        Assert.Null(exception);
        Assert.NotEqual("jp2", FileInspector.Detect(crafted)?.Extension);
    }

    [Fact]
    public void ZeroEntryTiffDirectoryChainHonorsDirectoryBudget()
    {
        int previous = Settings.DetectionReadBudgetBytes;
        try
        {
            Settings.DetectionReadBudgetBytes = 64;
            var bytes = new byte[8 + 6 * 100];
            bytes[0] = (byte)'I';
            bytes[1] = (byte)'I';
            TestHelpers.WriteUInt16LittleEndian(bytes, 2, 42);
            TestHelpers.WriteUInt32LittleEndian(bytes, 4, 8);
            for (int directory = 0; directory < 100; directory++)
            {
                int offset = 8 + directory * 6;
                TestHelpers.WriteUInt32LittleEndian(bytes, offset + 2,
                    directory == 99 ? 0u : (uint)(offset + 6));
            }

            var result = FileInspector.Detect(bytes);
            Assert.Equal("tif", result?.Extension);
            Assert.Equal("Medium", result?.Confidence);
            Assert.Contains("sampled-ifd-chain", result?.Reason);
        }
        finally
        {
            Settings.DetectionReadBudgetBytes = previous;
        }
    }

    [Fact]
    public void CabDataBlockValidationUsesOneAggregateBudget()
    {
        int previous = Settings.DetectionReadBudgetBytes;
        try
        {
            var bytes = CreateCabWithDataBlocks(3);

            Settings.DetectionReadBudgetBytes = 24;
            var complete = FileInspector.Detect(bytes);
            Assert.Equal("cab", complete?.Extension);
            Assert.Equal("High", complete?.Confidence);

            Settings.DetectionReadBudgetBytes = 16;
            var budgetLimited = FileInspector.Detect(bytes);
            Assert.Equal("cab", budgetLimited?.Extension);
            Assert.Equal("Medium", budgetLimited?.Confidence);
            Assert.Contains("validation-budget-exceeded", budgetLimited?.Reason);
        }
        finally
        {
            Settings.DetectionReadBudgetBytes = previous;
        }
    }

    [Fact]
    public void Hdf5UserBlockSignatureDoesNotMaskPortableExecutable()
    {
        var pe = TestHelpers.CreateMinimalPe();
        Array.Resize(ref pe, 1024);
        new byte[] { 0x89, (byte)'H', (byte)'D', (byte)'F', 0x0D, 0x0A, 0x1A, 0x0A }.CopyTo(pe, 512);

        Assert.Equal("exe", FileInspector.Detect(pe)?.Extension);
    }

    [Fact]
    public void MalformedPngDeflateIsRejectedWithoutThrowing()
    {
        var bytes = TestHelpers.CreateMinimalPng();
        int idat = FindChunk(bytes, "IDAT");
        int length = checked((int)ReadUInt32BigEndian(bytes, idat));
        bytes[idat + 10] ^= 0x7F;
        WriteChunkCrc(bytes, idat, length);

        var exception = Record.Exception(() => FileInspector.Detect(bytes));

        Assert.Null(exception);
        Assert.NotEqual("png", FileInspector.Detect(bytes)?.Extension);
    }

    [Fact]
    public void NonSeekablePeWithSampledOptionalHeaderRetainsExecutableIdentity()
    {
        int previous = Settings.HeaderReadBytes;
        var original = TestHelpers.CreateMinimalPe();
        const int originalPeOffset = 0x80;
        const int sampledPeOffset = 230;
        var bytes = new byte[original.Length + sampledPeOffset - originalPeOffset];
        Array.Copy(original, 0, bytes, 0, originalPeOffset);
        Array.Copy(original, originalPeOffset, bytes, sampledPeOffset, original.Length - originalPeOffset);
        TestHelpers.WriteUInt32LittleEndian(bytes, 0x3C, sampledPeOffset);
        try
        {
            Settings.HeaderReadBytes = 256;
            using var stream = new NonSeekableReadStream(bytes);

            var result = FileInspector.Detect(stream);

            Assert.Equal("exe", result?.Extension);
            Assert.Equal("Medium", result?.Confidence);
            Assert.Contains("sampled-optional-header", result?.Reason);
        }
        finally
        {
            Settings.HeaderReadBytes = previous;
        }
    }

    [Fact]
    public void NonGlbSeekableInputReadsOnlyTheFixedHeader()
    {
        using var stream = new CountingReadStream(new byte[2_000_000]);

        Assert.False(Signatures.TryMatchGlb(stream, out _));
        Assert.True(stream.BytesRead <= 20, $"Unexpectedly read {stream.BytesRead} bytes.");
    }

    [Fact]
    public void NetCdfRejectsNamesBeyondTheConfiguredAllocationLimit()
    {
        int previous = Settings.NetCdfNameMaxBytes;
        try
        {
            Settings.NetCdfNameMaxBytes = 32;
            var bytes = new byte[80];
            Encoding.ASCII.GetBytes("CDF").CopyTo(bytes, 0);
            bytes[3] = 1;
            TestHelpers.WriteUInt32BigEndian(bytes, 8, 10);
            TestHelpers.WriteUInt32BigEndian(bytes, 12, 1);
            TestHelpers.WriteUInt32BigEndian(bytes, 16, 40);
            for (int index = 20; index < 60; index++) bytes[index] = (byte)'a';

            Assert.NotEqual("nc", FileInspector.Detect(bytes)?.Extension);
        }
        finally
        {
            Settings.NetCdfNameMaxBytes = previous;
        }
    }

    [Fact]
    public void TranscriptMarkersDoNotOverrideScriptEvidence()
    {
        var text = "Windows PowerShell transcript start\nStart time: 20260805\nInvoke-Expression $payload";

        var result = FileInspector.Detect(Encoding.UTF8.GetBytes(text), null, "ps1");

        Assert.Equal("ps1", result?.Extension);
    }

    [Fact]
    public void TaskXmlBeyondUtf8PrefixAndWindowsPathsAreStillExtracted()
    {
        string path = Path.GetTempFileName() + ".xml";
        try
        {
            string padding = new string(' ', 9000);
            string xml = $"<?xml version=\"1.0\" encoding=\"utf-16\"?><Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">{padding}<Actions><Exec><Command>C:\\Tools\\agent.exe</Command></Exec></Actions></Task>";
            File.WriteAllText(path, xml, Encoding.Unicode);

            var analysis = FileInspector.Analyze(path);
            var reference = Assert.Single(analysis.References ?? Array.Empty<Reference>(),
                item => item.SourceTag == "task:exec" && item.Kind == ReferenceKind.FilePath);
            Assert.True((reference.Issues & ReferenceIssue.AbsolutePath) != 0);
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    [Fact]
    public void TaskXmlReferenceExtractionRejectsFilesBeyondItsByteBudget()
    {
        int previous = Settings.ReferenceExtractionMaxBytes;
        string path = Path.GetTempFileName() + ".xml";
        try
        {
            Settings.ReferenceExtractionMaxBytes = 1024;
            string xml = $"<Task><Padding>{new string('x', 2048)}</Padding><Actions><Exec><Command>C:\\Tools\\agent.exe</Command></Exec></Actions></Task>";
            File.WriteAllText(path, xml);

            var references = FileInspector.Analyze(path).References ?? Array.Empty<Reference>();

            Assert.DoesNotContain(references, item => item.SourceTag == "task:exec");
        }
        finally
        {
            Settings.ReferenceExtractionMaxBytes = previous;
            try { File.Delete(path); } catch { }
        }
    }

    [Fact]
    public void SharedXmlLoaderRejectsExcessiveDepthBeforeDomMaterialization()
    {
        string xml = "<Task>" + string.Concat(Enumerable.Repeat("<Node>", 300)) +
                     "<Actions><Exec><Command>agent.exe</Command></Exec></Actions>" +
                     string.Concat(Enumerable.Repeat("</Node>", 300)) + "</Task>";
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(xml));

        Assert.False(BoundedXmlDocument.TryLoad(stream, 64 * 1024, out _));
    }

    [Fact]
    public void JwtAdjacentToSentenceDotsAndSecretsContainingReplaceAreDetected()
    {
        string path = Path.GetTempFileName() + ".ps1";
        try
        {
            const string jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
            File.WriteAllText(path, $"$jwt = '.{jwt}.'\npassword=MyReplaceableSecretValue1234567890");

            var findings = FileInspector.Analyze(path).SecurityFindings ?? Array.Empty<string>();

            Assert.Contains("secret:jwt", findings);
            Assert.Contains("secret:keypattern", findings);
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    [Fact]
    public void UnsafeNativeAndReportFeaturesRemainOptInByDefault()
    {
        Assert.False(new FileInspector.DetectionOptions().IncludeInstaller);
        Assert.False(new FileInspector.DetectionOptions().IncludeShellProperties);
        Assert.False(Settings.IncludeInstaller);
        Assert.False(Settings.ReportHostFileMetadataEnabled);
        Assert.False(Settings.FindingEvidenceSnippetsEnabled);
        Assert.False(Settings.ReferencePathExistenceChecksEnabled);
        Assert.True(Settings.MotwMaxCharacters > 0);
    }

    [Fact]
    public void PerCallInstallerOptInOverridesDisabledGlobalSetting()
    {
        var previous = Settings.IncludeInstaller;
        try
        {
            Settings.IncludeInstaller = false;
            Assert.True(FileInspector.ShouldIncludeInstaller(new FileInspector.DetectionOptions { IncludeInstaller = true }));
            Assert.False(FileInspector.ShouldIncludeInstaller(new FileInspector.DetectionOptions { IncludeInstaller = false }));

            Settings.IncludeInstaller = true;
            Assert.True(FileInspector.ShouldIncludeInstaller(options: null));
        }
        finally
        {
            Settings.IncludeInstaller = previous;
        }
    }

    [Theory]
    [InlineData("AppxManifest.xml", "<Package xmlns=\"http://schemas.microsoft.com/appx/manifest/foundation/windows10\"><Identity Name=\"Contoso.App\" Publisher=\"CN=Contoso\" Version=\"1.2.3.4\"/><Properties><PublisherDisplayName>Contoso</PublisherDisplayName></Properties></Package>", InstallerKind.Msix)]
    [InlineData("extension.vsixmanifest", "<PackageManifest xmlns=\"http://schemas.microsoft.com/developer/vsx-schema/2011\"><Metadata><Identity Id=\"Contoso.Extension\" Publisher=\"Contoso\" Version=\"1.2.3\"/><DisplayName>Contoso Extension</DisplayName></Metadata></PackageManifest>", InstallerKind.Vsix)]
    public void PackageManifestEnrichmentHonorsPerCallInstallerOptIn(string entryName, string manifest, InstallerKind expectedKind)
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".zip");
        try
        {
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            {
                var entry = archive.CreateEntry(entryName);
                using var writer = new StreamWriter(entry.Open());
                writer.Write(manifest);
            }

            var excluded = FileInspector.Analyze(path, new FileInspector.DetectionOptions { IncludeInstaller = false });
            var included = FileInspector.Analyze(path, new FileInspector.DetectionOptions { IncludeInstaller = true });

            Assert.Null(excluded.Installer);
            Assert.Equal(expectedKind, included.Installer?.Kind);
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    [Fact]
    public void PropertiesOnlyAppPackageManifestDoesNotCreateAValidatedIdentity()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".msix");
        try
        {
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            {
                var manifest = archive.CreateEntry("AppxManifest.xml");
                using (var writer = new StreamWriter(manifest.Open()))
                {
                    writer.Write("<Package xmlns=\"http://schemas.microsoft.com/appx/manifest/foundation/windows10\"><Properties><PublisherDisplayName>Contoso</PublisherDisplayName></Properties></Package>");
                }

                archive.CreateEntry("payload.exe");
                archive.CreateEntry("install.ps1");
            }

            var analysis = FileInspector.Analyze(path, new FileInspector.DetectionOptions { IncludeInstaller = true });
            var assessed = FileInspector.Assess(analysis);

            Assert.NotEqual(InstallerKind.Msix, analysis.Installer?.Kind);
            Assert.Contains("Archive.ContainsExecutables", assessed.Codes);
            Assert.Contains("Archive.ContainsScripts", assessed.Codes);
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    [Fact]
    public void MalformedUtf16DoesNotHidePowerShellContent()
    {
        var valid = new UnicodeEncoding(false, true).GetBytes(
            "param([string]$Url)\nInvoke-WebRequest $Url | Invoke-Expression\n# malformed: ");
        var bytes = new byte[valid.Length + 2];
        Buffer.BlockCopy(valid, 0, bytes, 0, valid.Length);
        bytes[bytes.Length - 2] = 0x00;
        bytes[bytes.Length - 1] = 0xD8;

        var result = FileInspector.Detect(bytes, null, "txt");

        Assert.Equal("ps1", result?.Extension);
        Assert.True(result?.IsDangerous);
    }

    [Theory]
    [InlineData("# Maintenance script\nparam([string]$Url)\nInvoke-WebRequest $Url | Invoke-Expression\n", "ps1")]
    [InlineData("# Notes\nimport os\nif __name__ == '__main__':\n    print(os.getcwd())\n", "py")]
    [InlineData("<# Microsoft Defender #>\nparam([string]$Url)\nInvoke-WebRequest $Url | Invoke-Expression\n", "ps1")]
    public void PassiveTextCuesDoNotMaskActiveScripts(string content, string expectedExtension)
    {
        var result = FileInspector.Detect(Encoding.UTF8.GetBytes(content), null, "txt");

        Assert.Equal(expectedExtension, result?.Extension);
        Assert.True(result?.IsDangerous);
    }

    [Fact]
    public void MsiFileNameDoesNotOverridePowerShellContent()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".msi");
        try
        {
            File.WriteAllText(path, "param([string]$Url)\nInvoke-WebRequest $Url | Invoke-Expression\n");

            var analysis = FileInspector.Analyze(path);

            Assert.Equal("ps1", analysis.Detection?.Extension);
            Assert.True(analysis.Detection?.IsDangerous);
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    [Fact]
    public void BudgetLimitedStructuredTextCannotReportFullValidationSuccess()
    {
        int previousBudget = Settings.DetectionReadBudgetBytes;
        string path = Path.GetTempFileName() + ".json";
        try
        {
            Settings.DetectionReadBudgetBytes = 64;
            File.WriteAllText(path, "{\"ok\":true}".PadRight(64) + "attacker-controlled trailing bytes");

            var result = FileInspector.Detect(path);

            Assert.Equal("json", result?.Extension);
            Assert.Equal("skipped", result?.ValidationStatus);
        }
        finally
        {
            Settings.DetectionReadBudgetBytes = previousBudget;
            try { File.Delete(path); } catch { }
        }
    }

    [Fact]
    public void MalformedStructuredTextFailsGrammarValidation()
    {
        string jsonPath = Path.GetTempFileName() + ".json";
        string xmlPath = Path.GetTempFileName() + ".xml";
        try
        {
            File.WriteAllText(jsonPath, "{\"a\": [ } ]");
            File.WriteAllText(xmlPath, "<?xml version=\"1.0\"?><root><child></root>");

            Assert.Equal("failed", FileInspector.Detect(jsonPath)?.ValidationStatus);
            Assert.Equal("failed", FileInspector.Detect(xmlPath)?.ValidationStatus);
        }
        finally
        {
            try { File.Delete(jsonPath); } catch { }
            try { File.Delete(xmlPath); } catch { }
        }
    }

    [Fact]
    public void DriverDetectionRemainsExecutable()
    {
        Assert.Equal(ContentKind.Executable,
            KindClassifier.Classify(new ContentTypeDetectionResult { Extension = "sys" }));
    }

    [Fact]
    public void RestoredActiveContentSignaturesRemainDangerous()
    {
        var chmBytes = new byte[0x60];
        Encoding.ASCII.GetBytes("ITSF").CopyTo(chmBytes, 0);
        TestHelpers.WriteUInt32LittleEndian(chmBytes, 4, 3);
        TestHelpers.WriteUInt32LittleEndian(chmBytes, 8, 0x60);
        var swfBytes = new byte[] { (byte)'F', (byte)'W', (byte)'S', 9, 14, 0, 0, 0, 0x08, 0, 0, 0, 1, 0 };

        var chm = FileInspector.Detect(chmBytes);
        var swf = FileInspector.Detect(swfBytes);

        Assert.Equal("chm", chm?.Extension);
        Assert.True(chm?.IsDangerous);
        Assert.Equal("swf", swf?.Extension);
        Assert.True(swf?.IsDangerous);
    }

    [Fact]
    public void ChmVersionTwoWithItsValidHeaderLengthRemainsDangerous()
    {
        var chmBytes = new byte[0x58];
        Encoding.ASCII.GetBytes("ITSF").CopyTo(chmBytes, 0);
        TestHelpers.WriteUInt32LittleEndian(chmBytes, 4, 2);
        TestHelpers.WriteUInt32LittleEndian(chmBytes, 8, 0x58);

        var detection = FileInspector.Detect(chmBytes);

        Assert.Equal("chm", detection?.Extension);
        Assert.True(detection?.IsDangerous);
    }

    [Theory]
    [InlineData("ITSF ordinary text")]
    [InlineData("FWS ordinary text")]
    [InlineData("CWS ordinary text")]
    public void ShortActiveContentPrefixesRequireStructuralHeaders(string content)
    {
        var detection = FileInspector.Detect(Encoding.ASCII.GetBytes(content));

        Assert.NotEqual("chm", detection?.Extension);
        Assert.NotEqual("swf", detection?.Extension);
    }

    [Fact]
    public void DetectOnlyCopiesDangerousSummaryFields()
    {
        string path = Path.GetTempFileName() + ".chm";
        try
        {
            var chmBytes = new byte[0x60];
            Encoding.ASCII.GetBytes("ITSF").CopyTo(chmBytes, 0);
            TestHelpers.WriteUInt32LittleEndian(chmBytes, 4, 3);
            TestHelpers.WriteUInt32LittleEndian(chmBytes, 8, 0x60);
            File.WriteAllBytes(path, chmBytes);

            var analysis = FileInspector.Inspect(path, new FileInspector.DetectionOptions { DetectOnly = true });

            Assert.True(analysis.Detection?.IsDangerous);
            Assert.True(analysis.DetectionIsDangerous);
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    [Fact]
    public void Rar4EncryptedHeaderStartsImmediatelyAfterSevenByteMarker()
    {
        string path = Path.GetTempFileName() + ".rar";
        try
        {
            File.WriteAllBytes(path, new byte[] {
                0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00,
                0x00, 0x00, 0x73, 0x80, 0x00, 0x07, 0x00
            });

            Assert.True((FileInspector.Analyze(path).Flags & ContentFlags.ArchiveHasEncryptedEntries) != 0);
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    [Fact]
    public void Rar4MetadataBlocksDoNotConsumeTheFileInspectionCap()
    {
        string path = Path.GetTempFileName() + ".rar";
        try
        {
            using (var stream = File.Create(path))
            {
                stream.Write(new byte[] { (byte)'R', (byte)'a', (byte)'r', (byte)'!', 0x1A, 0x07, 0x00 }, 0, 7);
                for (int index = 0; index < 321; index++)
                    WriteRarHeader(stream, 0x73, 0);
                for (int index = 0; index < 64; index++)
                    WriteRarHeader(stream, 0x74, index == 63 ? (ushort)0x04 : (ushort)0);
            }

            var analysis = FileInspector.Analyze(path);

            Assert.True((analysis.Flags & ContentFlags.ArchiveHasEncryptedEntries) != 0);
            Assert.Equal(1, analysis.EncryptedEntryCount);
            Assert.Contains("rar4:enc=1/64", analysis.SecurityFindings ?? Array.Empty<string>());
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }

        static void WriteRarHeader(Stream stream, byte type, ushort flags)
        {
            stream.WriteByte(0);
            stream.WriteByte(0);
            stream.WriteByte(type);
            stream.WriteByte((byte)(flags & 0xFF));
            stream.WriteByte((byte)(flags >> 8));
            stream.WriteByte(7);
            stream.WriteByte(0);
        }
    }

    [Fact]
    public void NestedArchiveUsesItsOwnCapInsteadOfTheDirectEntrySampleCap()
    {
        var outerPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".zip");
        bool oldDeep = Settings.DeepContainerScanEnabled;
        int oldEntryBytes = Settings.DeepContainerMaxEntryBytes;
        int oldNestedBytes = Settings.DeepContainerMaxNestedArchiveBytes;
        try
        {
            Settings.DeepContainerScanEnabled = true;
            Settings.DeepContainerMaxEntryBytes = 256 * 1024;
            Settings.DeepContainerMaxNestedArchiveBytes = 1024 * 1024;

            byte[] nestedBytes;
            using (var nestedStream = new MemoryStream())
            {
                using (var nested = new ZipArchive(nestedStream, ZipArchiveMode.Create, leaveOpen: true))
                {
                    var executable = nested.CreateEntry("tool.exe", CompressionLevel.NoCompression);
                    using (var payload = executable.Open()) payload.Write(new byte[] { (byte)'M', (byte)'Z', 0, 0 }, 0, 4);
                    var padding = nested.CreateEntry("padding.bin", CompressionLevel.NoCompression);
                    using var paddingStream = padding.Open();
                    var bytes = new byte[300 * 1024];
                    using var random = System.Security.Cryptography.RandomNumberGenerator.Create();
                    random.GetBytes(bytes);
                    paddingStream.Write(bytes, 0, bytes.Length);
                }
                nestedBytes = nestedStream.ToArray();
            }
            Assert.True(nestedBytes.Length > Settings.DeepContainerMaxEntryBytes);

            using (var outer = ZipFile.Open(outerPath, ZipArchiveMode.Create))
            {
                var entry = outer.CreateEntry("payload.zip", CompressionLevel.NoCompression);
                using var output = entry.Open();
                output.Write(nestedBytes, 0, nestedBytes.Length);
            }

            var analysis = FileInspector.Analyze(outerPath);

            Assert.True((analysis.Flags & ContentFlags.ContainerContainsExecutables) != 0);
            Assert.Contains(analysis.ArchivePreviewEntries ?? Array.Empty<InnerEntryPreview>(), item =>
                item.Name.IndexOf("tool.exe", StringComparison.OrdinalIgnoreCase) >= 0);
        }
        finally
        {
            Settings.DeepContainerScanEnabled = oldDeep;
            Settings.DeepContainerMaxEntryBytes = oldEntryBytes;
            Settings.DeepContainerMaxNestedArchiveBytes = oldNestedBytes;
            try { File.Delete(outerPath); } catch { }
        }
    }

    [Fact]
    public void SignatureViewsExposeDigestAndWindowsPolicyResults()
    {
        var auth = new AuthenticodeInfo { Present = true, ChainValid = true, FileHashMatches = false, IsTrustedWindowsPolicy = false };
        var signature = SignatureView.From("sample.exe", auth);
        var analysis = AnalysisView.From("sample.exe", new FileAnalysis { Authenticode = auth });

        Assert.False(signature.FileHashMatches);
        Assert.False(signature.IsTrustedWindowsPolicy);
        Assert.False(analysis.AuthFileHashMatches);
        Assert.False(analysis.AuthTrustedWindowsPolicy);
    }

    [Fact]
    public void LegacyTwoParameterSpanDetectOverloadRemainsAvailable()
    {
        Assert.Contains(typeof(FileInspector).GetMethods(), method =>
            method.Name == nameof(FileInspector.Detect) &&
            method.GetParameters().Length == 2 &&
            method.GetParameters()[0].ParameterType == typeof(ReadOnlySpan<byte>));
    }

    [Fact]
    public void SpanDetectSupportsDeclaredExtensionNamedArgument()
    {
        var bytes = Encoding.UTF8.GetBytes("plain text");

        var result = FileInspector.Detect(bytes.AsSpan(), declaredExtension: "txt");

        Assert.Equal("txt", result?.Extension);
    }

    private static int FindChunk(byte[] png, string chunkType)
    {
        int cursor = 8;
        while (cursor + 12 <= png.Length)
        {
            int length = checked((int)ReadUInt32BigEndian(png, cursor));
            if (Encoding.ASCII.GetString(png, cursor + 4, 4) == chunkType) return cursor;
            cursor += 12 + length;
        }
        throw new InvalidDataException($"PNG chunk {chunkType} was not found.");
    }

    private static uint ReadUInt32BigEndian(byte[] bytes, int offset)
        => (uint)bytes[offset] << 24 | (uint)bytes[offset + 1] << 16 |
           (uint)bytes[offset + 2] << 8 | bytes[offset + 3];

    private static void WriteChunkCrc(byte[] png, int chunkOffset, int dataLength)
    {
        uint crc = uint.MaxValue;
        for (int index = chunkOffset + 4; index < chunkOffset + 8 + dataLength; index++)
        {
            crc ^= png[index];
            for (int bit = 0; bit < 8; bit++)
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        }
        TestHelpers.WriteUInt32BigEndian(png, chunkOffset + 8 + dataLength, ~crc);
    }

    private sealed class NonSeekableReadStream : Stream
    {
        private readonly MemoryStream _inner;
        internal NonSeekableReadStream(byte[] bytes) => _inner = new MemoryStream(bytes, writable: false);
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
        public override int ReadByte() => _inner.ReadByte();
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) _inner.Dispose(); base.Dispose(disposing); }
    }

    private static byte[] CreateCabWithDataBlocks(ushort blockCount)
    {
        const int filesOffset = 44;
        const int dataOffset = 62;
        int cabinetSize = dataOffset + blockCount * 9;
        var bytes = new byte[cabinetSize];
        Encoding.ASCII.GetBytes("MSCF").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, (uint)cabinetSize);
        TestHelpers.WriteUInt32LittleEndian(bytes, 16, filesOffset);
        bytes[24] = 3;
        bytes[25] = 1;
        TestHelpers.WriteUInt16LittleEndian(bytes, 26, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 28, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 36, dataOffset);
        TestHelpers.WriteUInt16LittleEndian(bytes, 40, blockCount);
        TestHelpers.WriteUInt32LittleEndian(bytes, filesOffset, blockCount);
        bytes[filesOffset + 16] = (byte)'a';

        for (int block = 0; block < blockCount; block++)
        {
            int offset = dataOffset + block * 9;
            TestHelpers.WriteUInt16LittleEndian(bytes, offset + 4, 1);
            TestHelpers.WriteUInt16LittleEndian(bytes, offset + 6, 1);
            bytes[offset + 8] = (byte)block;
        }

        return bytes;
    }

    private sealed class CountingReadStream : MemoryStream
    {
        internal CountingReadStream(byte[] bytes) : base(bytes, writable: false) { }
        internal long BytesRead { get; private set; }
        public override int Read(byte[] buffer, int offset, int count)
        {
            int read = base.Read(buffer, offset, count);
            BytesRead += read;
            return read;
        }
#if NET8_0_OR_GREATER
        public override int Read(Span<byte> buffer)
        {
            int read = base.Read(buffer);
            BytesRead += read;
            return read;
        }
#endif
        public override int ReadByte()
        {
            int value = base.ReadByte();
            if (value >= 0) BytesRead++;
            return value;
        }
    }
}
