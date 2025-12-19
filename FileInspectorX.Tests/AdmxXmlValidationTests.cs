using Xunit;
using FI = FileInspectorX.FileInspector;

namespace FileInspectorX.Tests;

public class AdmxXmlValidationTests
{
    [Fact]
    public void Detect_Invalid_Admx_Xml_Is_Marked_Malformed()
    {
        var p = Path.Combine(Path.GetTempPath(), "bad-" + Guid.NewGuid().ToString("N") + ".admx");
        try
        {
            File.WriteAllText(p, "<?xml version=\"1.0\" encoding=\"utf-8\"?><policyDefinitions><policy></policy");
            var r = FI.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("admx", r!.Extension);
            Assert.Contains("xml:malformed", r.Reason);
            Assert.Equal("Low", r.Confidence);
        }
        finally
        {
            try { if (File.Exists(p)) File.Delete(p); } catch { }
        }
    }
}
