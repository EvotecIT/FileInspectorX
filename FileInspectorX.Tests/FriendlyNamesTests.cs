using Xunit;

namespace FileInspectorX.Tests;

public class FriendlyNamesTests
{
    [Theory]
    [InlineData("ps1", "PowerShell script")]
    [InlineData("psm1", "PowerShell module")]
    [InlineData("psd1", "PowerShell data file")]
    [InlineData("js", "JavaScript file")]
    [InlineData("vbs", "VBScript file")]
    [InlineData("py", "Python script")]
    public void GetTypeLabel_Returns_Friendly_Script_Label(string extension, string expected)
    {
        var detection = new ContentTypeDetectionResult
        {
            Extension = extension,
            MimeType = "text/plain"
        };

        var label = FriendlyNames.GetTypeLabel(detection, new FileAnalysis());

        Assert.Equal(expected, label);
    }

    [Fact]
    public void GetTypeLabel_Returns_PowerShell_Transcript_Log_Label()
    {
        var detection = new ContentTypeDetectionResult
        {
            Extension = "log",
            MimeType = "text/plain",
            Reason = "text:log-powershell-transcript"
        };

        var label = FriendlyNames.GetTypeLabel(detection, new FileAnalysis
        {
            SecurityFindings = new[] { "ps:transcript" }
        });

        Assert.Equal("PowerShell transcript log", label);
    }

    [Fact]
    public void GetTypeLabel_Returns_Syslog_Label_From_Detection_Reason()
    {
        var detection = new ContentTypeDetectionResult
        {
            Extension = "log",
            MimeType = "text/plain",
            Reason = "text:log-syslog"
        };

        var label = FriendlyNames.GetTypeLabel(detection, new FileAnalysis());

        Assert.Equal("Syslog text log", label);
    }

    [Fact]
    public void GetTypeLabel_Returns_Cabinet_Label()
    {
        var detection = new ContentTypeDetectionResult
        {
            Extension = "cab",
            MimeType = "application/vnd.ms-cab-compressed"
        };

        var label = FriendlyNames.GetTypeLabel(detection, new FileAnalysis());

        Assert.Equal("Windows cabinet archive", label);
    }

    [Fact]
    public void GetTypeLabel_Returns_Apk_Label_From_Zip_Subtype()
    {
        var detection = new ContentTypeDetectionResult
        {
            Extension = "zip",
            MimeType = "application/vnd.android.package-archive",
            GuessedExtension = "apk"
        };

        var label = FriendlyNames.GetTypeLabel(detection, new FileAnalysis
        {
            ContainerSubtype = "apk"
        });

        Assert.Equal("Android package (APK)", label);
    }

    [Theory]
    [InlineData("parquet", "Apache Parquet data file")]
    [InlineData("pcapng", "Packet capture (PCAPNG)")]
    [InlineData("wasm", "WebAssembly module")]
    [InlineData("heic", "HEIC image")]
    [InlineData("png", "PNG image")]
    [InlineData("p7b", "PKCS#7 certificate bundle")]
    [InlineData("mp4", "MPEG-4 video")]
    [InlineData("xz", "XZ compressed file")]
    public void GetTypeLabel_Returns_Friendly_Label_For_Additional_Specialized_Types(string extension, string expected)
    {
        var detection = new ContentTypeDetectionResult
        {
            Extension = extension,
            MimeType = "application/octet-stream"
        };

        var label = FriendlyNames.GetTypeLabel(detection, new FileAnalysis());

        Assert.Equal(expected, label);
    }
}
