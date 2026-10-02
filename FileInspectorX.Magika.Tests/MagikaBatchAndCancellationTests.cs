using System.Text;

namespace FileInspectorX.Magika.Tests;

public sealed class MagikaBatchAndCancellationTests
{
    [Fact]
    public void PredictBatch_PreservesMixedRulesOrderAcrossChunkBoundariesAndOptionSnapshot()
    {
        var options = new MagikaClassifierOptions { IntraOpThreadCount = 1, PredictionMode = MagikaPredictionMode.BestGuess };
        using var classifier = new MagikaContentClassifier(options);
        options.PredictionMode = MagikaPredictionMode.HighConfidence;
        options.IntraOpThreadCount = -1;
        var model = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes("using System; public sealed class Demo { public static void Main() { } }"));
        var inputs = Enumerable.Range(0, 70).Select(index => (index % 4) switch
        {
            0 => ReadOnlyMemory<byte>.Empty,
            1 => new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes("hello")),
            2 => new ReadOnlyMemory<byte>(new byte[] { 0xFF }),
            _ => model
        }).ToArray();
        var batch = classifier.PredictBatch(inputs);
        Assert.Equal(inputs.Length, batch.Count);
        for (int index = 0; index < inputs.Length; index++)
        {
            var scalar = classifier.Predict(inputs[index]);
            Assert.Equal(scalar.RawLabel, batch[index].RawLabel);
            Assert.Equal(scalar.OutputLabel, batch[index].OutputLabel);
            Assert.Equal("BestGuess", batch[index].PredictionMode);
            Assert.InRange(Math.Abs(scalar.Probability - batch[index].Probability), 0, 0.005);
        }
        Assert.Empty(classifier.PredictBatch(Array.Empty<ReadOnlyMemory<byte>>()));
        Assert.Throws<ArgumentOutOfRangeException>(() => new MagikaContentClassifier(new MagikaClassifierOptions { IntraOpThreadCount = -1 }));
    }

    [Fact]
    public void Predict_ObservesCancellationInRulesBatchesAndFragmentedReadsWithoutOwningStream()
    {
        using var classifier = new MagikaContentClassifier(new MagikaClassifierOptions { IntraOpThreadCount = 1 });
        Assert.IsAssignableFrom<ICancellableLearnedContentClassifier>(classifier);
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        Assert.Throws<OperationCanceledException>(() => classifier.Predict(ReadOnlyMemory<byte>.Empty, canceled.Token));
        Assert.Throws<OperationCanceledException>(() => classifier.PredictBatch(Array.Empty<ReadOnlyMemory<byte>>(), canceled.Token));
        using var inFlight = new CancellationTokenSource();
        using var stream = new CancelingReadStream(new byte[8192], inFlight);
        stream.Position = 17;
        Assert.Throws<OperationCanceledException>(() => classifier.Predict(stream, inFlight.Token));
        Assert.Equal(17, stream.Position);
        Assert.True(stream.CanRead);
        Assert.Equal("txt", classifier.Predict(Encoding.UTF8.GetBytes("hello")).OutputLabel);
    }

    [Fact]
    public async Task PredictBatch_ConcurrentCancellationDoesNotTerminateOtherPredictions()
    {
        using var classifier = new MagikaContentClassifier(new MagikaClassifierOptions { IntraOpThreadCount = 1 });
        var input = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes("using System; public sealed class Demo { public static void Main() { } }"));
        var inputs = Enumerable.Repeat(input, 4096).ToArray();
        using var cancellation = new CancellationTokenSource();
        using var start = new ManualResetEventSlim();
        var canceled = Task.Run(() =>
        {
            start.Set();
            Assert.Throws<OperationCanceledException>(() => classifier.PredictBatch(inputs, cancellation.Token));
        });
        Assert.True(start.Wait(TimeSpan.FromSeconds(10)));
        cancellation.Cancel();
        var valid = classifier.PredictBatch(new[] { input, input });
        await canceled;
        Assert.All(valid, prediction => Assert.Equal("cs", prediction.OutputLabel));
    }

    private sealed class CancelingReadStream : MemoryStream
    {
        private readonly CancellationTokenSource _source;
        internal CancelingReadStream(byte[] bytes, CancellationTokenSource source) : base(bytes, writable: false) => _source = source;
        public override int Read(byte[] buffer, int offset, int count)
        {
            int read = base.Read(buffer, offset, Math.Min(count, 3));
            _source.Cancel();
            return read;
        }
    }
}
