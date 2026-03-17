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
            Assert.Equal("Medium", det.Confidence);
        }
        finally
        {
            Settings.EtlValidation = prevMode;
            TestHelpers.SafeDelete(temp);
            TestHelpers.SafeDelete(etl);
        }
    }

    [Fact]
    public void Detect_EtlMagicMismatch_DoesNotReturnEtl()
    {
        var prevMode = Settings.EtlValidation;
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
            TestHelpers.SafeDelete(temp);
            TestHelpers.SafeDelete(etl);
        }
    }

    [Fact]
    public void Detect_EmptyEtl_DoesNotReturnEtl()
    {
        var prevMode = Settings.EtlValidation;
        Settings.EtlValidation = Settings.EtlValidationMode.MagicOnly;
        var temp = Path.GetTempFileName();
        var etl = temp + ".etl";
        try
        {
            File.WriteAllBytes(temp, Array.Empty<byte>());
            File.Move(temp, etl);
            var det = FileInspector.Detect(etl);
            Assert.True(det == null || !string.Equals(det.Extension, "etl", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Settings.EtlValidation = prevMode;
            TestHelpers.SafeDelete(temp);
            TestHelpers.SafeDelete(etl);
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
            TestHelpers.SafeDelete(temp);
            TestHelpers.SafeDelete(etl);
        }
    }

    [Fact]
    public void Inspect_LargeEtl_UsesQuickPath_OnThresholdBoundary()
    {
        var prevMode = Settings.EtlValidation;
        var prevQuickBytes = Settings.EtlLargeFileQuickScanBytes;
        Settings.EtlValidation = Settings.EtlValidationMode.MagicOnly;
        var temp = Path.GetTempFileName();
        var etl = temp + ".etl";
        try
        {
            var payload = new byte[] { 0x45, 0x6C, 0x66, 0x46, 0x00, 0x01 };
            Settings.EtlLargeFileQuickScanBytes = payload.Length;
            File.WriteAllBytes(temp, payload);
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
            TestHelpers.SafeDelete(temp);
            TestHelpers.SafeDelete(etl);
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
            TestHelpers.SafeDelete(temp);
            TestHelpers.SafeDelete(etl);
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
            Assert.Equal("Medium", det.Confidence);
        }
        finally
        {
            Settings.EtlValidation = prevMode;
            TestHelpers.SafeDelete(temp);
        }
    }

    [Fact]
    public void Detect_EtlStructuredHeader_ReturnsEtl()
    {
        var prevMode = Settings.EtlValidation;
        Settings.EtlValidation = Settings.EtlValidationMode.MagicOnly;
        var temp = Path.GetTempFileName();
        var etl = temp + ".etl";
        try
        {
            var header = new byte[128];
            header[0x00] = 0x00; header[0x01] = 0x10; header[0x02] = 0x00; header[0x03] = 0x00; // 4096 LE
            header[0x04] = 0xB8; header[0x05] = 0x01; header[0x06] = 0x00; header[0x07] = 0x00; // version 0x1B8
            header[0x30] = 0xF8; header[0x31] = 0x12; header[0x32] = 0x00; header[0x33] = 0x00; // non-zero provider/log version
            header[0x34] = 0x01; header[0x36] = 0x04; // realistic WPR-like flags
            File.WriteAllBytes(temp, header);
            File.Move(temp, etl);

            var det = FileInspector.Detect(etl);

            Assert.NotNull(det);
            Assert.Equal("etl", det!.Extension);
            Assert.Equal("Medium", det.Confidence);
        }
        finally
        {
            Settings.EtlValidation = prevMode;
            TestHelpers.SafeDelete(temp);
            TestHelpers.SafeDelete(etl);
        }
    }

    [Fact]
    public void Detect_Evtx_Header_DoesNot_Get_Overridden_As_Etl()
    {
        var prevMode = Settings.EtlValidation;
        Settings.EtlValidation = Settings.EtlValidationMode.MagicOnly;
        var temp = Path.GetTempFileName();
        var evtx = temp + ".evtx";
        try
        {
            File.WriteAllBytes(temp, new byte[] { 0x45, 0x6C, 0x66, 0x46, 0x69, 0x6C, 0x65, 0x00, 0x01, 0x00, 0x00, 0x00 });
            File.Move(temp, evtx);

            var det = FileInspector.Detect(evtx);

            Assert.NotNull(det);
            Assert.Equal("evtx", det!.Extension);
        }
        finally
        {
            Settings.EtlValidation = prevMode;
            TestHelpers.SafeDelete(temp);
            TestHelpers.SafeDelete(evtx);
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
            TestHelpers.SafeDelete(temp);
        }
    }
}
