using Xunit;

namespace FileInspectorX.Tests;

public class HeuristicsNewTests
{
    [Fact]
    public void EventXml_IsDetected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".xml");
        try {
            var xml = "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\"/></System></Event>";
            File.WriteAllText(p, xml);
            var a = FileInspector.Analyze(p);
            Assert.NotNull(a.SecurityFindings);
            Assert.Contains("event-xml", a.SecurityFindings!);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Ldif_IsDetected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".ldif");
        try {
            var txt = "ldif-version: 1\ndn: CN=Test,DC=example,DC=com\nobjectClass: top\n";
            File.WriteAllText(p, txt);
            var a = FileInspector.Analyze(p);
            Assert.Contains("ldif", a.SecurityFindings!);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void IisW3C_IsDetected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".log");
        try {
            var txt = "#Software: Microsoft Internet Information Services 10.0\n#Version: 1.0\n#Fields: date time cs-method cs-uri-stem sc-status\n2025-10-10 12:00:00 GET / 200\n";
            File.WriteAllText(p, txt);
            var a = FileInspector.Analyze(p);
            Assert.Contains("log:iis-w3c", a.SecurityFindings!);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Secrets_PrivKey_Jwt_KeyPattern_Detected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            var txt = "-----BEGIN PRIVATE KEY-----\nMIICdTCCAd2...\n-----END PRIVATE KEY-----\nheader.payload.signature\nsecret=ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890\n";
            File.WriteAllText(p, txt);
            var a = FileInspector.Analyze(p);
            Assert.Contains("secret:privkey", a.SecurityFindings!);
            Assert.Contains("secret:jwt", a.SecurityFindings!);
            Assert.Contains("secret:keypattern", a.SecurityFindings!);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }
}

