using Xunit;

namespace FileInspectorX.Tests;

// This collection serializes tests that temporarily lower Settings.DetectionReadBudgetBytes.
[CollectionDefinition(nameof(DetectionSettingsCollection), DisableParallelization = true)]
public sealed class DetectionSettingsCollection : ICollectionFixture<DetectionSettingsFixture>
{
}

public sealed class DetectionSettingsFixture
{
}
