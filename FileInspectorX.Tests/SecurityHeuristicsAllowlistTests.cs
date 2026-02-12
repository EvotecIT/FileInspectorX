using System.Diagnostics;
using Xunit;

namespace FileInspectorX.Tests;

public class SecurityHeuristicsAllowlistTests
{
    [Theory]
    [InlineData("example.com", true)]
    [InlineData("api.example.com", true)]
    [InlineData("badexample.com", false)]
    [InlineData("example.com.evil", false)]
    [InlineData("host.corp.local", true)]
    [InlineData("corp.local", true)]
    [InlineData("corp.local.evil", false)]
    [InlineData("trusted.internal", true)]
    [InlineData("svc.trusted.internal", true)]
    [InlineData("eviltrusted.internal", false)]
    public void IsHostAllowedByDomains_MatchesExpectedBoundaries(string host, bool expected)
    {
        var allowed = new[] { "example.com", "*.corp.local", ".trusted.internal" };
        var actual = SecurityHeuristics.IsHostAllowedByDomains(host, allowed);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void IsHostAllowedByDomains_HandlesEmptyInputs()
    {
        Assert.False(SecurityHeuristics.IsHostAllowedByDomains("", new[] { "example.com" }));
        Assert.False(SecurityHeuristics.IsHostAllowedByDomains("example.com", Array.Empty<string>()));
        Assert.False(SecurityHeuristics.IsHostAllowedByDomains("example.com", null));
    }

    [Fact]
    public void TryResolveHostForTest_InvalidReservedDomain_ReturnsFalseQuickly()
    {
        var host = $"does-not-exist-{Guid.NewGuid():N}.invalid";
        var sw = Stopwatch.StartNew();
        var resolved = SecurityHeuristics.TryResolveHostForTest(host, 50);
        sw.Stop();

        Assert.False(resolved);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), $"Unexpectedly slow DNS resolution path: {sw.Elapsed}.");
    }
}
