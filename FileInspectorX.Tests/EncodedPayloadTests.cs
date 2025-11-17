using Xunit;

namespace FileInspectorX.Tests;

public class EncodedPayloadTests {
    private static byte[] MinimalMZ()
    {
        // Minimal bytes to trigger MZ detection (no real PE required)
        return new byte[] { 0x4D, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    }

    [Fact]
    public void Base64_Encoded_Exe_Inner_Detected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            var mz = Enumerable.Repeat(MinimalMZ(), 32).SelectMany(b => b).ToArray(); // ensure long enough for detection
            var b64 = Convert.ToBase64String(mz);
            File.WriteAllText(p, b64);
            var a = FileInspector.Analyze(p);
            Assert.NotNull(a);
            Assert.Equal("b64", a.Detection!.Extension);
            Assert.Equal("base64", a.EncodedKind);
            Assert.NotNull(a.EncodedInnerDetection);
            Assert.Equal("exe", a.EncodedInnerDetection!.Extension);
            Assert.True(a.Flags.HasFlag(ContentFlags.EncodedBase64));
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Hex_Encoded_Exe_Inner_Detected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            var mz = Enumerable.Repeat(MinimalMZ(), 40).SelectMany(b => b).ToArray(); // ensure long enough for detection
            var hex = string.Concat(mz.Select(b => b.ToString("X2")));
            File.WriteAllText(p, hex);
            var a = FileInspector.Analyze(p);
            Assert.NotNull(a);
            Assert.Equal("hex", a.Detection!.Extension);
            Assert.Equal("hex", a.EncodedKind);
            Assert.NotNull(a.EncodedInnerDetection);
            Assert.Equal("exe", a.EncodedInnerDetection!.Extension);
            Assert.True(a.Flags.HasFlag(ContentFlags.EncodedHex));
        } finally { if (File.Exists(p)) File.Delete(p); }
    }
}
