using Xunit;

namespace FileInspectorX.Tests;

[CollectionDefinition(nameof(DetectionSettingsCollection), DisableParallelization = true)]
public sealed class DetectionSettingsCollection : ICollectionFixture<DetectionSettingsFixture>
{
}

public sealed class DetectionSettingsFixture
{
}
