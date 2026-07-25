using System.Text;

namespace FileInspectorX.Magika.Tests;

public sealed class MagikaFeatureExtractorTests
{
    [Fact]
    public void Extract_StripsAndPadsBeginningAndEndLikeUpstream()
    {
        var config = new MagikaModelConfig
        {
            BeginningSize = 4,
            MiddleSize = 0,
            EndSize = 4,
            BlockSize = 4096,
            PaddingToken = 256
        };

        var features = MagikaFeatureExtractor.Extract(
            Encoding.ASCII.GetBytes("  abc  "),
            config);

        Assert.Equal(new[] { 97, 98, 99, 32, 32, 97, 98, 99 }, features);
    }

    [Fact]
    public void Extract_RestoresStreamPosition()
    {
        var config = new MagikaModelConfig
        {
            BeginningSize = 4,
            MiddleSize = 0,
            EndSize = 4,
            BlockSize = 4096,
            PaddingToken = 256
        };
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes("abcdefgh"));
        stream.Position = 3;

        _ = MagikaFeatureExtractor.Extract(stream, config);

        Assert.Equal(3, stream.Position);
    }
}
