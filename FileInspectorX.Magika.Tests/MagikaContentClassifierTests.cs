using System.Text;

namespace FileInspectorX.Magika.Tests;

public sealed class MagikaContentClassifierTests
{
    [Fact]
    public void Predict_ClassifiesCSharpWithoutUsingAFileName()
    {
        const string source = """
            using System;
            namespace Demo;
            public sealed class Sample
            {
                public static void Main() => Console.WriteLine("hello");
            }
            """;
        using var classifier = new MagikaContentClassifier();

        var prediction = classifier.Predict(Encoding.UTF8.GetBytes(source));

        Assert.Equal("cs", prediction.RawLabel);
        Assert.Equal("cs", prediction.OutputLabel);
        Assert.Equal("cs", prediction.Extension);
        Assert.True(prediction.Probability >= 0.5);
    }

    [Fact]
    public void Predict_UsesRuleForTinyUtf8Input()
    {
        using var classifier = new MagikaContentClassifier();

        var prediction = classifier.Predict(Encoding.UTF8.GetBytes("hello"));

        Assert.Equal("txt", prediction.OutputLabel);
        Assert.Equal(1, prediction.Probability);
    }

    [Fact]
    public void Predict_RestoresStreamPosition()
    {
        using var classifier = new MagikaContentClassifier();
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(
            "function greet(name) { console.log(`hello ${name}`); }\ngreet('world');"));
        stream.Position = 7;

        var prediction = classifier.Predict(stream);

        Assert.Equal(7, stream.Position);
        Assert.Equal("javascript", prediction.RawLabel);
    }
}
