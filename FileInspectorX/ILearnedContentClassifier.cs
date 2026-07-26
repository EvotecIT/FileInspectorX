using System.IO;

namespace FileInspectorX;

/// <summary>
/// Contract implemented by optional learned content-classification packages.
/// Implementations must leave seekable streams at their original position.
/// </summary>
public interface ILearnedContentClassifier
{
    /// <summary>Predicts a content label from an in-memory buffer.</summary>
    /// <param name="content">Complete content to classify.</param>
    LearnedContentPrediction Predict(ReadOnlyMemory<byte> content);

    /// <summary>Predicts a content label from a readable, seekable stream.</summary>
    /// <param name="content">Complete content to classify.</param>
    LearnedContentPrediction Predict(Stream content);
}
