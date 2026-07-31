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
        var data = CreateCab();
        var det = FileInspector.Detect(data);
        Assert.NotNull(det);
        Assert.Equal("cab", det!.Extension);
    }

    private static byte[] CreateCab()
    {
        var data = new byte[36];
        System.Text.Encoding.ASCII.GetBytes("MSCF").CopyTo(data, 0);
        BitConverter.GetBytes(36u).CopyTo(data, 8);
        BitConverter.GetBytes(36u).CopyTo(data, 16);
        data[24] = 3;
        data[25] = 1;
        BitConverter.GetBytes((ushort)1).CopyTo(data, 26);
        BitConverter.GetBytes((ushort)1).CopyTo(data, 28);
        return data;
    }
}
