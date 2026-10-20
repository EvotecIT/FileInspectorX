using Xunit;

namespace FileInspectorX.Tests;

public sealed class DeclaredDangerRegressionTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(".")]
    public void MissingDeclaredExtensionPreservesDetectedDanger(string? declared)
    {
        var detected = new ContentTypeDetectionResult { Extension = "exe", IsDangerous = true };

        var comparison = FileInspector.CompareDeclaredDetailed(declared, detected);

        Assert.Equal("exe", comparison.DetectedExtension);
        Assert.True(comparison.IsDetectedDangerous);
        Assert.False(comparison.IsDeclaredDangerous);
        Assert.False(comparison.Mismatch);
    }

    [Fact]
    public void MissingDeclaredExtensionPreservesStrongDangerousAlternatives()
    {
        var detected = new ContentTypeDetectionResult
        {
            Extension = "txt",
            Alternatives = new[] { new ContentTypeDetectionCandidate { Extension = "ps1", Confidence = "High", Score = 95 } }
        };

        var comparison = FileInspector.CompareDeclaredDetailed(null, detected);

        Assert.True(comparison.IsDetectedDangerous);
        Assert.Equal(new[] { "ps1" }, comparison.StrongDangerousAlternativeExtensions);
    }

    [Fact]
    public void MissingDetectionPreservesDeclaredDanger()
    {
        var comparison = FileInspector.CompareDeclaredDetailed(".exe", null);

        Assert.True(comparison.IsDeclaredDangerous);
        Assert.False(comparison.IsDetectedDangerous);
    }
}
