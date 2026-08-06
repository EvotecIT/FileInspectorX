using System;
using System.IO;

namespace FileInspectorX.Tests;

public class PowerShellMetadataRegressionTests
{
    [Xunit.Fact]
    public void UnknownShebangDoesNotSuppressPowerShellCmdletMetadata()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".ps1");
        try
        {
            File.WriteAllText(path, "#!/opt/custom/interpreter\nGet-Item .\n");

            var analysis = FileInspector.Analyze(path);

            Xunit.Assert.Equal("unknown", analysis.ScriptLanguage);
            Xunit.Assert.Equal("powershell", analysis.TextSubtype);
            Xunit.Assert.Contains("get-item", analysis.ScriptCmdlets ?? Array.Empty<string>());
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }
}
