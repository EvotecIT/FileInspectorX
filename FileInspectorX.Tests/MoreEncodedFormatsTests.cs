using Xunit;

namespace FileInspectorX.Tests;

public class MoreEncodedFormatsTests
{
    [Fact]
    public void Ascii85_WithMarkers_IsDetected()
    {
        // Canonical ASCII85 sample for the string "Hello\n": <~87cURD]j7BEbo80~>
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try
        {
            File.WriteAllText(p, "<~87cURD]j7BEbo80~>\n");
            var a = FileInspector.Analyze(p);
            Assert.NotNull(a);
            Assert.Equal("b85", a.Detection!.Extension);
            Assert.Equal("base85", a.EncodedKind);
            // Inner detection may be null for plain text payload; only assert encoding detection
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Uuencode_Simple_Block_Inner_Exe_Detected()
    {
        // UUEncode a single 3-byte tuple: 0x4D,0x5A,0x00 (MZ + NUL) => length '#' (35), then tuple '#35H '
        var uu = string.Join("\n", new[]{
            "begin 644 test.bin",
            "#35H ",
            "end",
            string.Empty
        });
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try
        {
            File.WriteAllText(p, uu);
            var a = FileInspector.Analyze(p);
            Assert.NotNull(a);
            Assert.Equal("uu", a.Detection!.Extension);
            Assert.Equal("uuencode", a.EncodedKind);
            Assert.NotNull(a.EncodedInnerDetection);
            Assert.Equal("exe", a.EncodedInnerDetection!.Extension);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }
}

