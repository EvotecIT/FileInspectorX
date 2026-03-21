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
    public void Wrapped_Base64_Encoded_Exe_Inner_Detected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            var mz = Enumerable.Repeat(MinimalMZ(), 32).SelectMany(b => b).ToArray();
            var b64 = Convert.ToBase64String(mz);
            var wrapped = string.Join(Environment.NewLine, Chunk(b64, 76));
            File.WriteAllText(p, wrapped);
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

    [Fact]
    public void WhitespaceSeparated_Hex_Encoded_Exe_Inner_Detected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            var mz = Enumerable.Repeat(MinimalMZ(), 40).SelectMany(b => b).ToArray();
            var hexPairs = mz.Select(b => b.ToString("X2")).ToArray();
            var wrapped = string.Join(Environment.NewLine,
                Chunk(hexPairs, 16).Select(line => string.Join(" ", line)));
            File.WriteAllText(p, wrapped);
            var a = FileInspector.Analyze(p);
            Assert.NotNull(a);
            Assert.Equal("hex", a.Detection!.Extension);
            Assert.Equal("hex", a.EncodedKind);
            Assert.NotNull(a.EncodedInnerDetection);
            Assert.Equal("exe", a.EncodedInnerDetection!.Extension);
            Assert.True(a.Flags.HasFlag(ContentFlags.EncodedHex));
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void QuotedPrintable_Encoded_Exe_Inner_Detected()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        try {
            var mz = Enumerable.Repeat(MinimalMZ(), 24).SelectMany(b => b).ToArray();
            var qp = EncodeQuotedPrintable(mz, 60);
            File.WriteAllText(p, qp);
            var a = FileInspector.Analyze(p);
            Assert.NotNull(a);
            Assert.Equal("qp", a.Detection!.Extension);
            Assert.Equal("quoted-printable", a.EncodedKind);
            Assert.NotNull(a.EncodedInnerDetection);
            Assert.Equal("exe", a.EncodedInnerDetection!.Extension);
            Assert.Contains("enc:qp", a.SecurityFindings ?? Array.Empty<string>());
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    private static IEnumerable<string> Chunk(string value, int size)
    {
        for (int i = 0; i < value.Length; i += size)
        {
            yield return value.Substring(i, Math.Min(size, value.Length - i));
        }
    }

    private static IEnumerable<string[]> Chunk(string[] values, int size)
    {
        for (int i = 0; i < values.Length; i += size)
        {
            int take = Math.Min(size, values.Length - i);
            var chunk = new string[take];
            Array.Copy(values, i, chunk, 0, take);
            yield return chunk;
        }
    }

    private static string EncodeQuotedPrintable(byte[] data, int maxLineLength)
    {
        var line = new System.Text.StringBuilder();
        var output = new System.Text.StringBuilder();
        for (int i = 0; i < data.Length; i++)
        {
            string token = "=" + data[i].ToString("X2");
            if (line.Length + token.Length > maxLineLength)
            {
                output.Append(line).Append('=').Append(Environment.NewLine);
                line.Clear();
            }

            line.Append(token);
        }

        output.Append(line);
        return output.ToString();
    }
}
