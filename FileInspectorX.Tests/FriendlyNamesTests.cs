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
}
