using Xunit;
using System.IO.Compression;
using System.Text;
#if NET8_0_OR_GREATER
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
#endif

namespace FileInspectorX.Tests;

/// <summary>Protects content facts whose former fixtures masked parsing errors.</summary>
[Collection(nameof(ArchiveBudgetSettingsCollection))]
public sealed class PortableExtractorRegressionTests
{
    private static FileInspector.DetectionOptions Options() => new()
    {
        IncludePermissions = false, IncludeShellProperties = false, IncludeInstaller = false,
        IncludeAuthenticode = false, IncludeAssessment = false, IncludeReferences = false
    };

    [Fact]
    public void Pe32PlusConsoleSubsystemComesFromTheOptionalHeader()
    {
        var bytes = TestHelpers.CreateMinimalPe();
        Put16(bytes, 0x84, 0x8664); Put16(bytes, 0x94, 0xF0); Put16(bytes, 0x98, 0x20B);
        Put16(bytes, 0xDC, 3); Put16(bytes, 0xDE, 0x4160); Put32(bytes, 0x104, 16);
        var result = FileInspector.Analyze(bytes, Options(), "upload.exe");
        Assert.Equal("exe", result.Detection!.Extension);
        Assert.Equal("x86_64", result.PeMachine);
        Assert.Equal("Windows CUI", result.PeSubsystem);
    }

    [Theory]
    [InlineData("module.dll")]
    [InlineData("disguised.txt")]
    [InlineData(null)]
    public void PeExportsDescribeContentIndependentlyOfTheUploadName(string? name)
    {
        var bytes = new byte[1024]; TestHelpers.CreateMinimalPe(dll: true).CopyTo(bytes, 0);
        Put16(bytes, 0xDC, 3); Put32(bytes, 0xF8, 0x1000); Put32(bytes, 0xFC, 0x80);
        Put32(bytes, 0x178 + 8, 512); Put32(bytes, 0x178 + 12, 0x1000);
        Put32(bytes, 0x178 + 16, 512); Put32(bytes, 0x178 + 20, 512);
        Put32(bytes, 512 + 20, 1); Put32(bytes, 512 + 24, 1);
        Put32(bytes, 512 + 28, 0x1040); Put32(bytes, 512 + 32, 0x1044); Put32(bytes, 512 + 36, 0x1048);
        Put32(bytes, 512 + 0x44, 0x1050);
        Encoding.ASCII.GetBytes("DllRegisterServer\0").CopyTo(bytes, 512 + 0x50);
        var result = FileInspector.Analyze(bytes, Options(), name);
        Assert.Equal("dll", result.Detection!.Extension);
        Assert.Contains("pe:exports=1", result.SecurityFindings!);
        Assert.Contains("pe:regsvr", result.SecurityFindings!);
    }

    [Theory]
    [InlineData("#!/usr/bin/env pwsh")]
    [InlineData("#!/usr/bin/pwsh")]
    [InlineData("#!/usr/bin/env -S pwsh -NoProfile")]
    public void PowerShellShebangDoesNotBecomeGenericSh(string shebang)
    {
        var result = FileInspector.Analyze(Encoding.UTF8.GetBytes(shebang + "\n# A comment\n"), Options(), "upload.txt");
        Assert.Equal("powershell", result.ScriptLanguage);
    }

    [Fact]
    public void ScriptExecutionFindingsKeepTheEarlierClassificationEvidence()
    {
        var bytes = Encoding.UTF8.GetBytes("function Get-Thing { param($Value) Invoke-Expression $Value }");
        var result = FileInspector.Analyze(bytes, Options(), "upload.ps1");
        Assert.Contains("ps:structure", result.SecurityFindings!);
        Assert.Contains("ps:iex", result.SecurityFindings!);
    }

    [Fact]
    public void ServiceMainMentionInProseIsNotPeEvidence()
    {
        var result = FileInspector.Analyze(Encoding.UTF8.GetBytes("The ServiceMain function is discussed here."), Options(), "notes.txt");
        Assert.DoesNotContain("pe:servicemain", result.SecurityFindings ?? Array.Empty<string>());
    }

    [Fact]
    public void OrdinaryOleDirectoryNamesDoNotImplyVbaMacros()
    {
        var path = Path.GetTempFileName();
        try
        {
            DetectorTests.WriteSyntheticOleDirectoryFile(path, "WordDocument", "Directory");
            var result = FileInspector.Analyze(File.ReadAllBytes(path), Options(), "upload.doc");
            Assert.Equal("doc", result.Detection!.Extension);
            Assert.False(result.Flags.HasFlag(ContentFlags.OleHasVbaMacros));
        }
        finally { TestHelpers.SafeDelete(path); }
    }

    [Fact]
    public void WorkbookRelationshipAndItsExternalLinkPartCountAsOneLink()
    {
        var bytes = Zip(("[Content_Types].xml", "<Types/>"), ("xl/workbook.xml", "<workbook/>"),
            ("xl/externalLinks/externalLink1.xml", "<externalLink/>"),
            ("xl/_rels/workbook.xml.rels", "<Relationships><Relationship Target='externalLinks/externalLink1.xml'/></Relationships>"));
        var result = FileInspector.Analyze(bytes, Options(), "upload.xlsx");
        Assert.True(result.Flags.HasFlag(ContentFlags.OfficeExternalLinks));
        Assert.Equal(1, result.OfficeExternalLinksCount);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void WorkbookRelationshipsPreserveEncodingForWebAndUncTargets(bool utf16)
    {
        var encoding = utf16 ? Encoding.Unicode : Encoding.UTF8;
        byte[] RelationshipBytes(string elements)
        {
            var xml = "<?xml version='1.0' encoding='" + (utf16 ? "utf-16" : "utf-8") +
                "'?><Relationships xmlns='http://schemas.openxmlformats.org/package/2006/relationships'>" + elements + "</Relationships>";
            return encoding.GetPreamble().Concat(encoding.GetBytes(xml)).ToArray();
        }
        var bytes = ZipBytes(("[Content_Types].xml", Encoding.UTF8.GetBytes("<Types/>")),
            ("xl/workbook.xml", Encoding.UTF8.GetBytes("<workbook/>")),
            ("xl/externalLinks/externalLink1.xml", Encoding.UTF8.GetBytes("<externalLink/>")),
            ("xl/_rels/workbook.xml.rels", RelationshipBytes("<Relationship Target='externalLinks/externalLink1.xml'/>")),
            ("xl/externalLinks/_rels/externalLink1.xml.rels", RelationshipBytes(
                "<Relationship Target='https://encoding-test.example.invalid/book.xlsx' TargetMode='External'/>" +
                "<Relationship Target='\\\\fileserver\\share\\book.xlsx' TargetMode='External'/>")));
        var result = FileInspector.Analyze(bytes, Options(), "upload.xlsx");
        Assert.Equal(1, result.OfficeExternalLinksCount);
        Assert.Contains("ooxml:ext-disallowed=1", result.SecurityFindings!);
        Assert.Contains("ooxml:unc=1", result.SecurityFindings!);
        Assert.Contains("ooxml:hosts=encoding-test.example.invalid", result.SecurityFindings!);
        Assert.DoesNotContain("archive:ooxml-relationships-rejected", result.AnalysisIssues ?? Array.Empty<string>());
    }

    [Fact]
    public void TarInspectsNestedArchivePrefixesWithoutLimitingMemberSizeTo128Bytes()
    {
        var nested = Zip(("payload.txt", new string('x', 512)));
        Assert.True(nested.Length > 128);
        var result = FileInspector.Analyze(Tar("opaque.bin", nested), Options(), "upload.tar");
        Assert.Equal("tar", result.Detection!.Extension);
        Assert.True(result.Flags.HasFlag(ContentFlags.ContainerContainsArchives));
    }

    [Fact]
    public void RarEncryptedCountingSkipsTheFirstMembersPackedPayload()
    {
        using var output = new MemoryStream();
        output.Write(new byte[] { 82, 97, 114, 33, 26, 7, 0 }, 0, 7);
        RarFile(output, "plain.txt", false, new byte[16]);
        RarFile(output, "encrypted.txt", true, new byte[16]);
        var result = FileInspector.Analyze(output.ToArray(), Options(), "upload.rar");
        Assert.Equal(2, result.ContainerEntryCount);
        Assert.Equal(1, result.EncryptedEntryCount);
        Assert.Contains("rar4:enc=1/2", result.SecurityFindings!);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RarHeaderEnumerationDoesNotEstablishContentAcceptance(bool deep)
    {
        using var output = new MemoryStream();
        output.Write(new byte[] { 82, 97, 114, 33, 26, 7, 0 }, 0, 7);
        RarFile(output, "plain.txt", false, new byte[16]);
        var options = Options();
        options.Settings = (options.Settings ?? InspectionSettings.CaptureDefaults()) with { DeepContainerScanEnabled = deep };
        var analysis = FileInspector.Inspect(output.ToArray(), options, "upload.rar");
        Assert.Equal("rar", analysis.Detection!.Extension);
        Assert.Equal(1, analysis.ContainerEntryCount);
        Assert.Contains("archive:inner-content-unavailable", analysis.AnalysisIssues!);
        Assert.Equal(FileAcceptanceDecision.Incomplete, FileInspector.EvaluateAcceptance(analysis, "upload.rar").Decision);
    }

    [Fact]
    public void PdfContentAndCommentsDoNotBecomeDocumentActionsOrEncryption()
    {
        var bytes = Encoding.ASCII.GetBytes("%PDF-1.7\n% /JS /Encrypt\n1 0 obj << /Type /Catalog /Subject (mentions /JavaScript and /Encrypt (nested)) /Value <2F4A53> >> endobj\n%%EOF");
        var result = FileInspector.Analyze(bytes, Options(), "upload.pdf");
        Assert.False(result.Flags.HasFlag(ContentFlags.PdfHasJavaScript));
        Assert.False(result.Flags.HasFlag(ContentFlags.PdfEncrypted));
        Assert.False(result.AnalysisComplete);
        Assert.Contains("pdf:lexical-inspection-only", result.AnalysisIssues!);
    }

    [Fact]
    public void PdfNamesUsePdfEscapeRulesAndRawStreamBytesAreExcluded()
    {
        const string stream = "/JS /Encrypt";
        var bytes = Encoding.ASCII.GetBytes("%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction << /S /Java#53cript /J#53 (run) >> >> endobj\n2 0 obj << /Length " + stream.Length + " >> stream\n" + stream + "\nendstream\nendobj\n%%EOF");
        var result = FileInspector.Analyze(bytes, Options(), "upload.pdf");
        Assert.True(result.Flags.HasFlag(ContentFlags.PdfHasJavaScript));
        Assert.True(result.Flags.HasFlag(ContentFlags.PdfHasOpenAction));
        Assert.False(result.Flags.HasFlag(ContentFlags.PdfEncrypted));
        Assert.Contains("pdf:stream-content-not-inspected", result.AnalysisIssues!);
    }

#if NET8_0_OR_GREATER
    [Fact]
    public void AppxP7xPrefixIsParsedAndAuthenticodeExclusionIsRespected()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=FileInspectorX test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var cms = new SignedCms(new ContentInfo(Encoding.ASCII.GetBytes("synthetic package digest")));
        cms.ComputeSignature(new CmsSigner(certificate) { IncludeOption = X509IncludeOption.EndCertOnly });
        var encoded = cms.Encode(); var p7x = new byte[encoded.Length + 4];
        Encoding.ASCII.GetBytes("PKCX").CopyTo(p7x, 0); encoded.CopyTo(p7x, 4);
        var bytes = ZipBytes(("AppxManifest.xml", Encoding.UTF8.GetBytes("<Package/>")), ("AppxSignature.p7x", p7x));
        var options = Options(); options.IncludeAuthenticode = true;
        var result = FileInspector.Analyze(bytes, options, "upload.msix");
        Assert.True(result.Authenticode?.Present);
        Assert.True(result.Authenticode?.EnvelopeSignatureValid);
        Assert.Equal(certificate.Thumbprint, result.Authenticode!.SignerThumbprint);
        Assert.Null(result.Authenticode.FileHashMatches);
        options.IncludeAuthenticode = false;
        Assert.Null(FileInspector.Analyze(bytes, options, "upload.msix").Authenticode);
        options.IncludeAuthenticode = true;
        p7x[0] = (byte)'!';
        var malformed = ZipBytes(("AppxManifest.xml", Encoding.UTF8.GetBytes("<Package/>")), ("AppxSignature.p7x", p7x));
        var failed = FileInspector.Analyze(malformed, options, "upload.msix");
        Assert.Null(failed.Authenticode);
        Assert.False(failed.AnalysisComplete);
        Assert.Contains("archive:package-signature-unavailable", failed.AnalysisIssues!);
    }
#endif

    private static byte[] Zip(params (string Name, string Text)[] entries)
        => ZipBytes(entries.Select(e => (e.Name, Encoding.UTF8.GetBytes(e.Text))).ToArray());

    private static byte[] ZipBytes(params (string Name, byte[] Bytes)[] entries)
    {
        using var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
            foreach (var entry in entries)
            {
                using var content = archive.CreateEntry(entry.Name, CompressionLevel.NoCompression).Open();
                content.Write(entry.Bytes, 0, entry.Bytes.Length);
            }
        return output.ToArray();
    }

    private static byte[] Tar(string name, byte[] payload)
    {
        var header = new byte[512]; Encoding.ASCII.GetBytes(name).CopyTo(header, 0);
        Encoding.ASCII.GetBytes(Convert.ToString(payload.Length, 8).PadLeft(11, '0')).CopyTo(header, 124);
        header[156] = (byte)'0'; Encoding.ASCII.GetBytes("ustar").CopyTo(header, 257); TestHelpers.SealTarHeader(header);
        using var output = new MemoryStream(); output.Write(header, 0, header.Length); output.Write(payload, 0, payload.Length);
        var padding = new byte[(512 - payload.Length % 512) % 512 + 1024]; output.Write(padding, 0, padding.Length);
        return output.ToArray();
    }

    private static void RarFile(Stream output, string name, bool encrypted, byte[] payload)
    {
        using var writer = new BinaryWriter(output, Encoding.UTF8, leaveOpen: true);
        var filename = Encoding.ASCII.GetBytes(name);
        writer.Write((ushort)0); writer.Write((byte)0x74); writer.Write((ushort)(0x8000 | (encrypted ? 4 : 0)));
        writer.Write((ushort)(32 + filename.Length)); writer.Write((uint)payload.Length); writer.Write((uint)payload.Length);
        writer.Write((byte)0); writer.Write(0u); writer.Write(0u); writer.Write((byte)20); writer.Write((byte)0x30);
        writer.Write((ushort)filename.Length); writer.Write(0u); writer.Write(filename); writer.Write(payload);
    }

    private static void Put16(byte[] bytes, int offset, ushort value) => BitConverter.GetBytes(value).CopyTo(bytes, offset);
    private static void Put32(byte[] bytes, int offset, uint value) => BitConverter.GetBytes(value).CopyTo(bytes, offset);
}
