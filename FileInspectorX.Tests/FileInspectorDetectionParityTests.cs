using FileInspectorX;
using Xunit;

namespace FileInspectorX.Tests;

public class FileInspectorDetectionParityTests
{
    [Fact]
    public void DetectSpan_TarHeader_DetectsTar()
    {
        var data = new byte[265];
        var sig = System.Text.Encoding.ASCII.GetBytes("ustar");
        System.Array.Copy(sig, 0, data, 257, sig.Length);
        var det = FileInspector.Detect(data);
        Assert.NotNull(det);
        Assert.Equal("tar", det!.Extension);
    }

    [Fact]
    public void DetectSpan_CabHeader_DetectsCab()
    {
        var data = new byte[] { (byte)'M', (byte)'S', (byte)'C', (byte)'F' };
        var det = FileInspector.Detect(data);
        Assert.NotNull(det);
        Assert.Equal("cab", det!.Extension);
    }
}
