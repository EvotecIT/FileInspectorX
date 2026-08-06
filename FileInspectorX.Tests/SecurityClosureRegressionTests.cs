using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class SecurityClosureRegressionTests
{
    [Theory]
    [InlineData("REGEDIT4\r\n\r\n[HKEY_CURRENT_USER\\Software\\Contoso]", "Medium")]
    [InlineData("Windows Registry Editor Version 5.00\n\n[HKEY_CURRENT_USER\\Software\\Contoso]", "High")]
    public void RegistryExportRequiresACompleteHeaderLine(string content, string confidence)
    {
        var detected = FileInspector.Detect(Encoding.ASCII.GetBytes(content));

        Assert.Equal("reg", detected?.Extension);
        Assert.Equal(confidence, detected?.Confidence);
    }

    [Theory]
    [InlineData("REGEDIT notes for operators")]
    [InlineData("REGEDIT4 notes for operators")]
    [InlineData("Windows Registry Editor Version 5.00 notes")]
    public void RegistryLikeTextDoesNotMatchWithoutAHeaderBoundary(string content)
    {
        var detected = FileInspector.Detect(Encoding.ASCII.GetBytes(content));

        Assert.NotEqual("reg", detected?.Extension);
    }

    [Theory]
    [InlineData("utf-8-bom")]
    [InlineData("utf-16le")]
    [InlineData("utf-16be")]
    public void RegistryExportRecognizesStandardUnicodeEncodings(string encodingName)
    {
        const string content = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\Contoso]";
        Encoding encoding = encodingName switch
        {
            "utf-8-bom" => new UTF8Encoding(encoderShouldEmitUTF8Identifier: true),
            "utf-16le" => new UnicodeEncoding(bigEndian: false, byteOrderMark: true),
            "utf-16be" => new UnicodeEncoding(bigEndian: true, byteOrderMark: true),
            _ => throw new ArgumentOutOfRangeException(nameof(encodingName))
        };
        byte[] bytes = encoding.GetPreamble().Concat(encoding.GetBytes(content)).ToArray();

        var detected = FileInspector.Detect(bytes);

        Assert.Equal("reg", detected?.Extension);
        Assert.Equal("High", detected?.Confidence);
    }

    [Theory]
    [InlineData("appx")]
    [InlineData("msix")]
    public void ValidatedAppPackageIdentitySuppressesExpectedExecutableAndScriptContainerSignals(string subtype)
    {
        var analysis = new FileAnalysis
        {
            ContainerSubtype = subtype,
            Installer = new InstallerInfo
            {
                Kind = subtype == "appx" ? InstallerKind.Appx : InstallerKind.Msix,
                IdentityName = "Contoso.App",
                Publisher = "CN=Contoso",
                Version = "1.2.3.4"
            },
            Flags = ContentFlags.ContainerContainsExecutables | ContentFlags.ContainerContainsScripts
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(10, assessed.Score);
        Assert.DoesNotContain("Archive.ContainsExecutables", assessed.Codes);
        Assert.DoesNotContain("Archive.ContainsScripts", assessed.Codes);
        Assert.Contains("Sig.Absent", assessed.Codes);
    }

    [Fact]
    public void PropertiesOnlyAppPackageManifestDoesNotSuppressArchiveRiskSignals()
    {
        var analysis = new FileAnalysis
        {
            ContainerSubtype = "msix",
            Installer = new InstallerInfo
            {
                Kind = InstallerKind.Msix,
                PublisherDisplayName = "Contoso"
            },
            Flags = ContentFlags.ContainerContainsExecutables | ContentFlags.ContainerContainsScripts
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Contains("Archive.ContainsExecutables", assessed.Codes);
        Assert.Contains("Archive.ContainsScripts", assessed.Codes);
    }

    [Theory]
    [InlineData("+1.2.3.4")]
    [InlineData("1. 2.3.4")]
    [InlineData("1.2.3.4 ")]
    public void MalformedAppPackageVersionDoesNotSuppressArchiveRiskSignals(string version)
    {
        var analysis = new FileAnalysis
        {
            ContainerSubtype = "msix",
            Installer = new InstallerInfo
            {
                Kind = InstallerKind.Msix,
                IdentityName = "Contoso.App",
                Publisher = "CN=Contoso",
                Version = version
            },
            Flags = ContentFlags.ContainerContainsExecutables | ContentFlags.ContainerContainsScripts
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Contains("Archive.ContainsExecutables", assessed.Codes);
        Assert.Contains("Archive.ContainsScripts", assessed.Codes);
    }

    [Fact]
    public void FailedWinTrustStatusRemainsInvalidSignatureEvidence()
    {
        var analysis = new FileAnalysis
        {
            Detection = new ContentTypeDetectionResult { Extension = "msi" },
            Authenticode = new AuthenticodeInfo
            {
                Present = false,
                IsTrustedWindowsPolicy = false,
                WinTrustStatusCode = unchecked((int)0x800B0109)
            }
        };

        var assessed = FileInspector.Assess(analysis);

        Assert.Equal(25, assessed.Score);
        Assert.Contains("Sig.WinTrustInvalid", assessed.Codes);
        Assert.DoesNotContain("Sig.Absent", assessed.Codes);
    }

    [Fact]
    public void Rar4MetadataBlocksDoNotConsumeEntrySummaryCap()
    {
        string path = Path.GetTempFileName() + ".rar";
        int previousEntryCap = Settings.DeepContainerMaxEntries;
        try
        {
            Settings.DeepContainerMaxEntries = 64;
            using (var stream = File.Create(path))
            {
                stream.Write(new byte[] { (byte)'R', (byte)'a', (byte)'r', (byte)'!', 0x1A, 0x07, 0x00 });
                for (int index = 0; index < 65; index++)
                    stream.Write(CreateRar4Header(0x73));
                for (int index = 0; index < 64; index++)
                    stream.Write(CreateRar4FileHeader(index == 63 ? "last.exe" : $"file-{index}.txt"));
            }

            var analysis = FileInspector.Analyze(path);

            Assert.Equal(64, analysis.ContainerEntryCount);
            Assert.True((analysis.Flags & ContentFlags.ContainerContainsExecutables) != 0);
        }
        finally
        {
            Settings.DeepContainerMaxEntries = previousEntryCap;
            try { File.Delete(path); } catch { }
        }
    }

    [Theory]
    [InlineData("{\"message\":\"Write-Host $value\",\"handler\":\"def run(): pass\"}", "json")]
    [InlineData("<?xml version=\"1.0\"?><root><script>Write-Host $value</script></root>", "xml")]
    [InlineData("name: sample\ncommand: Write-Host $value\nhandler: def run(): pass\n", "yml")]
    public void StructuredTextWinsOverScriptSnippets(string content, string expectedExtension)
    {
        var detected = FileInspector.Detect(Encoding.UTF8.GetBytes(content));

        Assert.Equal(expectedExtension, detected?.Extension);
    }

    private static byte[] CreateRar4Header(byte type)
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        writer.Write((ushort)0);
        writer.Write(type);
        writer.Write((ushort)0);
        writer.Write((ushort)7);
        return stream.ToArray();
    }

    private static byte[] CreateRar4FileHeader(string name)
    {
        byte[] nameBytes = Encoding.GetEncoding(28591).GetBytes(name);
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        writer.Write((ushort)0);
        writer.Write((byte)0x74);
        writer.Write((ushort)0);
        writer.Write((ushort)(7 + 25 + nameBytes.Length));
        writer.Write((uint)0);
        writer.Write((uint)0);
        writer.Write((byte)0);
        writer.Write((uint)0);
        writer.Write((uint)0);
        writer.Write((byte)20);
        writer.Write((byte)0x30);
        writer.Write((ushort)nameBytes.Length);
        writer.Write((uint)0);
        writer.Write(nameBytes);
        return stream.ToArray();
    }
}
