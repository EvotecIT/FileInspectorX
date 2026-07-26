namespace FileInspectorX;

/// <summary>
/// Marks a learned classifier whose <see cref="ILearnedContentClassifier.Predict(ReadOnlyMemory{byte})"/>
/// and <see cref="ILearnedContentClassifier.Predict(Stream)"/> methods may be invoked concurrently.
/// Classifiers that do not implement this contract are serialized per instance.
/// </summary>
public interface IConcurrentLearnedContentClassifier : ILearnedContentClassifier
{
}
