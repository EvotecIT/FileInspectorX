using System.Runtime.InteropServices;

using Xunit;

namespace FileInspectorX.Tests;

public class ShellPropertiesTests
{
    [Fact]
    public void ReadShellProperties_Graceful_OnAllPlatforms()
    {
        var path = Path.GetTempFileName();
        try
        {
            var props = FileInspector.ReadShellProperties(path);
            Assert.NotNull(props);
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                Assert.Empty(props);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void ShellPropertiesView_UsesSnapshotWhenAvailable()
    {
        var analysis = new FileAnalysis
        {
            ShellProperties = new List<ShellProperty>
            {
                new ShellProperty { DisplayName = "Title", Value = "Test" }
            }
        };

        var rows = analysis.ToShellPropertiesView("C:\\does-not-exist.txt").ToList();
        Assert.Single(rows);
        Assert.Equal("Title", rows[0].Property);
        Assert.Equal("Test", rows[0].Value);
    }
}
