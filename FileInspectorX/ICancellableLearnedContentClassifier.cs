using System.Threading;

namespace FileInspectorX;

/// <summary>Optional learned provider that cooperatively cancels in-flight prediction.</summary>
public interface ICancellableLearnedContentClassifier : ILearnedContentClassifier
{
    /// <summary>Predicts from complete memory input while observing the operation's cancellation token.</summary>
    LearnedContentPrediction Predict(ReadOnlyMemory<byte> content, CancellationToken cancellationToken);

    /// <summary>Predicts from a seekable stream, preserving its position, while observing cancellation.</summary>
    LearnedContentPrediction Predict(Stream content, CancellationToken cancellationToken);
}
