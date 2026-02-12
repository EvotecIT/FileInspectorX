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
    public void Secrets_PrivKey_Jwt_KeyPattern_Token_Detected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            var jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoyMDAwMDAwMDAwfQ.VGhpcy1pcy1qd3Qtc2ln";
            var ghp = "ghp_0123456789abcdef0123456789abcdef0123";
            var txt = "-----BEGIN PRIVATE KEY-----\nMIICdTCCAd2...\n-----END PRIVATE KEY-----\n" + jwt + "\nsecret=ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890\ngithub_token=" + ghp + "\n";
            File.WriteAllText(p, txt);
            var a = FileInspector.Analyze(p);
            Assert.Contains("secret:privkey", a.SecurityFindings!);
            Assert.Contains("secret:jwt", a.SecurityFindings!);
            Assert.Contains("secret:keypattern", a.SecurityFindings!);
            Assert.Contains("secret:token", a.SecurityFindings!);
            Assert.Contains("secret:token:github", a.SecurityFindings!);
            Assert.NotNull(a.Secrets);
            Assert.True(a.Secrets!.GitHubTokenCount >= 1);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Secrets_Jwt_DomainAndVersion_DoNotFalsePositive()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            var txt = "docs host=support.github.com version=10.20.30";
            File.WriteAllText(p, txt);
            var a = FileInspector.Analyze(p);
            Assert.DoesNotContain("secret:jwt", a.SecurityFindings ?? Array.Empty<string>());
            Assert.True(a.Secrets == null || a.Secrets.JwtLikeCount == 0);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Secrets_Counts_MultipleJwtAndKeyPatterns()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            var jwt1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZXhwIjoyMDAwMDAwMDAwfQ.c2lnbmF0dXJlMQ";
            var jwt2 = "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJhcGkiLCJpc3MiOiJ0ZXN0In0.c2lnbmF0dXJlMg";
            var ghp = "ghp_0123456789abcdef0123456789abcdef0123";
            var aws = "AKIAABCDEFGHIJKLMNOP";
            var txt = string.Join("\n", new[]
            {
                new string('#', 600),
                "note=this is plain text with embedded tokens",
                "jwt_one=" + jwt1,
                "jwt_two=" + jwt2,
                "key=ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
                "secret=ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
                "password=ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
                "github_token=" + ghp,
                "aws_access_key_id=" + aws
            });
            File.WriteAllText(p, txt);
            var a = FileInspector.Analyze(p);
            Assert.NotNull(a.Secrets);
            Assert.True(a.Secrets!.JwtLikeCount >= 2);
            Assert.True(a.Secrets!.KeyPatternCount >= 3);
            Assert.True(a.Secrets!.TokenFamilyCount >= 2);
            Assert.True(a.Secrets!.GitHubTokenCount >= 1);
            Assert.True(a.Secrets!.AwsAccessKeyIdCount >= 1);
            Assert.Contains("secret:jwt", a.SecurityFindings!);
            Assert.Contains("secret:keypattern", a.SecurityFindings!);
            Assert.Contains("secret:token", a.SecurityFindings!);
            Assert.Contains("secret:token:github", a.SecurityFindings!);
            Assert.Contains("secret:token:aws-akid", a.SecurityFindings!);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Secrets_TokenFamily_Placeholders_DoNotFalsePositive()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            var slackPrefix = "xox" + "b";
            var stripePrefix = "sk" + "_live_";
            var txt = string.Join("\n", new[]
            {
                "github_token=ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEABCD1234",
                "aws_access_key_id=AKIAEXAMPLEEXAMPLE12",
                "slack=" + slackPrefix + "-123456789012-EXAMPLEEXAMPLEEXAMPLEEXAMPLE12",
                "placeholder=" + stripePrefix + "EXAMPLEEXAMPLEEXAMPLE1234"
            });
            File.WriteAllText(p, txt);
            var a = FileInspector.Analyze(p);
            Assert.DoesNotContain("secret:token", a.SecurityFindings ?? Array.Empty<string>());
            Assert.DoesNotContain("secret:token:github", a.SecurityFindings ?? Array.Empty<string>());
            Assert.DoesNotContain("secret:token:aws-akid", a.SecurityFindings ?? Array.Empty<string>());
            Assert.True(a.Secrets == null || a.Secrets.TokenFamilyCount == 0);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Secrets_TokenFamily_AwsWithoutSecretContext_DoesNotDetect()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            File.WriteAllText(p, "identifier AKIAABCDEFGHIJKLMNOP value");
            var a = FileInspector.Analyze(p);
            Assert.DoesNotContain("secret:token", a.SecurityFindings ?? Array.Empty<string>());
            Assert.True(a.Secrets == null || a.Secrets.TokenFamilyCount == 0);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Secrets_TokenFamily_AwsWithSecretContext_IsDetected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            File.WriteAllText(p, "aws_access_key_id=AKIAABCDEFGHIJKLMNOP");
            var a = FileInspector.Analyze(p);
            Assert.Contains("secret:token", a.SecurityFindings ?? Array.Empty<string>());
            Assert.Contains("secret:token:aws-akid", a.SecurityFindings ?? Array.Empty<string>());
            Assert.NotNull(a.Secrets);
            Assert.True(a.Secrets!.TokenFamilyCount >= 1);
            Assert.True(a.Secrets!.AwsAccessKeyIdCount >= 1);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Secrets_TokenFamily_PrefixInsideWord_DoesNotDetect()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            File.WriteAllText(p, "token=Aghp_0123456789abcdef0123456789abcdef0123");
            var a = FileInspector.Analyze(p);
            Assert.DoesNotContain("secret:token", a.SecurityFindings ?? Array.Empty<string>());
            Assert.True(a.Secrets == null || a.Secrets.TokenFamilyCount == 0);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Secrets_KeyPattern_PlaceholderValues_DoNotDetect()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try
        {
            var txt = string.Join("\n", new[]
            {
                "api_key=YOUR_API_KEY_REPLACE_ME_1234567890",
                "secret=placeholder_placeholder_value_1234567890",
                "password=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            });
            File.WriteAllText(p, txt);
            var a = FileInspector.Analyze(p);
            Assert.DoesNotContain("secret:keypattern", a.SecurityFindings ?? Array.Empty<string>());
            Assert.True(a.Secrets == null || a.Secrets.KeyPatternCount == 0);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }
}
