using System;
using System.IO;
using FileInspectorX;
using Xunit;

namespace FileInspectorX.Tests;

public class FileInspectorEtlTests
{
    [Fact]
    public void Detect_EtlMagic_ReturnsEtl()
    {
        var prevMode = Settings.EtlValidation;
        Settings.EtlValidation = Settings.EtlValidationMode.MagicOnly;
        var temp = Path.GetTempFileName();
        var etl = temp + ".etl";
        try
        {
            File.WriteAllBytes(temp, new byte[] { 0x45, 0x6C, 0x66, 0x46, 0x00, 0x01 });
            File.Move(temp, etl);
            var det = FileInspector.Detect(etl);
            Assert.NotNull(det);
            Assert.Equal("etl", det!.Extension);
        }
        finally
        {
            Settings.EtlValidation = prevMode;
            if (File.Exists(temp)) File.Delete(temp);
            if (File.Exists(etl)) File.Delete(etl);
        }
    }

    [Fact]
    public void Detect_EtlMagicMismatch_DoesNotReturnEtl()
    {
        var prevMode = Settings.EtlValidation;
        var prevQuickBytes = Settings.EtlLargeFileQuickScanBytes;
        Settings.EtlValidation = Settings.EtlValidationMode.MagicOnly;
        var temp = Path.GetTempFileName();
        var etl = temp + ".etl";
        try
        {
            File.WriteAllBytes(temp, System.Text.Encoding.UTF8.GetBytes("not an etl"));
            File.Move(temp, etl);

            var det = FileInspector.Detect(etl);
            Assert.True(det == null || !string.Equals(det.Extension, "etl", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Settings.EtlValidation = prevMode;
            Settings.EtlLargeFileQuickScanBytes = prevQuickBytes;
            if (File.Exists(temp)) File.Delete(temp);
            if (File.Exists(etl)) File.Delete(etl);
        }
    }

    [Fact]
    public void Inspect_LargeEtl_UsesQuickPath()
    {
        var prevMode = Settings.EtlValidation;
        var prevQuickBytes = Settings.EtlLargeFileQuickScanBytes;
        Settings.EtlValidation = Settings.EtlValidationMode.MagicOnly;
        Settings.EtlLargeFileQuickScanBytes = 1;
        var temp = Path.GetTempFileName();
        var etl = temp + ".etl";
        try
        {
            File.WriteAllBytes(temp, new byte[] { 0x45, 0x6C, 0x66, 0x46, 0x00, 0x01 });
            File.Move(temp, etl);

            var analysis = FileInspector.Inspect(etl, new FileInspector.DetectionOptions { ComputeSha256 = true });
            Assert.NotNull(analysis.Detection);
            Assert.Equal("etl", analysis.Detection!.Extension);
            Assert.True(string.IsNullOrEmpty(analysis.Detection.Sha256Hex));
        }
        finally
        {
            Settings.EtlValidation = prevMode;
            Settings.EtlLargeFileQuickScanBytes = prevQuickBytes;
            if (File.Exists(temp)) File.Delete(temp);
            if (File.Exists(etl)) File.Delete(etl);
        }
    }

    [Fact]
    public void Inspect_SmallEtl_DoesNotShortCircuit()
    {
        var prevMode = Settings.EtlValidation;
        var prevQuickBytes = Settings.EtlLargeFileQuickScanBytes;
        Settings.EtlValidation = Settings.EtlValidationMode.MagicOnly;
        Settings.EtlLargeFileQuickScanBytes = 1_000_000;
        var temp = Path.GetTempFileName();
        var etl = temp + ".etl";
        try
        {
            File.WriteAllBytes(temp, new byte[] { 0x45, 0x6C, 0x66, 0x46, 0x00, 0x01 });
            File.Move(temp, etl);

            var analysis = FileInspector.Inspect(etl, new FileInspector.DetectionOptions { ComputeSha256 = true });
            Assert.NotNull(analysis.Detection);
            Assert.Equal("etl", analysis.Detection!.Extension);
            Assert.False(string.IsNullOrEmpty(analysis.Detection.Sha256Hex));
        }
        finally
        {
            Settings.EtlValidation = prevMode;
            Settings.EtlLargeFileQuickScanBytes = prevQuickBytes;
            if (File.Exists(temp)) File.Delete(temp);
            if (File.Exists(etl)) File.Delete(etl);
        }
    }

    [Fact]
    public void Detect_EtlMagic_IgnoresExtension()
    {
        var prevMode = Settings.EtlValidation;
        Settings.EtlValidation = Settings.EtlValidationMode.MagicOnly;
        var temp = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(temp, new byte[] { 0x45, 0x6C, 0x66, 0x46, 0x00, 0x01 });
            var det = FileInspector.Detect(temp);
            Assert.NotNull(det);
            Assert.Equal("etl", det!.Extension);
        }
        finally
        {
            Settings.EtlValidation = prevMode;
            if (File.Exists(temp)) File.Delete(temp);
        }
    }

    [Fact]
    public void Inspect_LargeEtl_UsesQuickPath_IgnoresExtension()
    {
        var prevMode = Settings.EtlValidation;
        var prevQuickBytes = Settings.EtlLargeFileQuickScanBytes;
        Settings.EtlValidation = Settings.EtlValidationMode.MagicOnly;
        Settings.EtlLargeFileQuickScanBytes = 1;
        var temp = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(temp, new byte[] { 0x45, 0x6C, 0x66, 0x46, 0x00, 0x01 });
            var analysis = FileInspector.Inspect(temp, new FileInspector.DetectionOptions { ComputeSha256 = true });
            Assert.NotNull(analysis.Detection);
            Assert.Equal("etl", analysis.Detection!.Extension);
            Assert.True(string.IsNullOrEmpty(analysis.Detection.Sha256Hex));
        }
        finally
        {
            Settings.EtlValidation = prevMode;
            Settings.EtlLargeFileQuickScanBytes = prevQuickBytes;
            if (File.Exists(temp)) File.Delete(temp);
        }
    }
}
