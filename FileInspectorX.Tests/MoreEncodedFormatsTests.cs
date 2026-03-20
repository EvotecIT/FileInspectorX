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
        var uu = EncodeUu(new byte[] { 0x4D, 0x5A, 0x00 }, "test.bin");
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

    [Fact]
    public void Uuencode_MultiLine_Block_Inner_Exe_Detected()
    {
        var payload = Enumerable.Repeat(new byte[] { 0x4D, 0x5A, 0x00 }, 40).SelectMany(x => x).ToArray();
        var uu = EncodeUu(payload, "test.bin");
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

    private static string EncodeUu(byte[] data, string fileName)
    {
        var lines = new List<string> { $"begin 644 {fileName}" };
        for (int offset = 0; offset < data.Length; offset += 45)
        {
            int count = Math.Min(45, data.Length - offset);
            var line = new System.Text.StringBuilder();
            line.Append(ToUuChar(count));
            for (int i = 0; i < count; i += 3)
            {
                byte b1 = data[offset + i];
                byte b2 = i + 1 < count ? data[offset + i + 1] : (byte)0;
                byte b3 = i + 2 < count ? data[offset + i + 2] : (byte)0;

                int c1 = (b1 >> 2) & 0x3F;
                int c2 = ((b1 << 4) | (b2 >> 4)) & 0x3F;
                int c3 = ((b2 << 2) | (b3 >> 6)) & 0x3F;
                int c4 = b3 & 0x3F;
                line.Append(ToUuChar(c1));
                line.Append(ToUuChar(c2));
                line.Append(ToUuChar(c3));
                line.Append(ToUuChar(c4));
            }

            lines.Add(line.ToString());
        }

        lines.Add("`");
        lines.Add("end");
        lines.Add(string.Empty);
        return string.Join("\n", lines);

        static char ToUuChar(int value)
        {
            value &= 0x3F;
            return value == 0 ? '`' : (char)(value + 32);
        }
    }
}

