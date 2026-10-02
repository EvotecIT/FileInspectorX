using System.IO.Compression;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace FileInspectorX;

public static partial class FileInspector
{
    private static bool TryDecodeEncodedHead(string path, string ext, out byte[] decoded, out string encKind)
    {
        decoded = Array.Empty<byte>(); encKind = ext switch { "hex" => "hex", "b85" => "base85", "uu" => "uuencode", "qp" => "quoted-printable", _ => "base64" };
        try {
            using var fs = File.OpenRead(path);
            int toRead = (int)Math.Min(Settings.EncodedProbeReadBytes, fs.Length);
            var buf = new byte[toRead]; int nr = fs.Read(buf, 0, toRead);
            if (nr <= 0) return false;
            ReadOnlySpan<byte> span = new ReadOnlySpan<byte>(buf, 0, nr);
            // Handle UTF-16 BOMs minimally
            string headStr;
            if (nr >= 2 && buf[0] == 0xFF && buf[1] == 0xFE) headStr = System.Text.Encoding.Unicode.GetString(buf, 0, nr);
            else if (nr >= 2 && buf[0] == 0xFE && buf[1] == 0xFF) headStr = System.Text.Encoding.BigEndianUnicode.GetString(buf, 0, nr);
            else headStr = System.Text.Encoding.UTF8.GetString(buf, 0, nr);

            if (ext == "b64")
            {
                // Prefer PEM armor block if present
                string? core = null;
                int bi = headStr.IndexOf("-----BEGIN ", StringComparison.Ordinal);
                if (bi >= 0)
                {
                    int start = headStr.IndexOf('\n', bi);
                    int ei = headStr.IndexOf("-----END ", StringComparison.Ordinal);
                    if (start >= 0 && ei > start) core = headStr.Substring(start + 1, ei - (start + 1));
                }
                if (core is null)
                {
                    // Fallback: take the longest normalized run of base64/url-safe characters,
                    // allowing MIME-style wrapping/whitespace inside the block.
                    int bestLen = 0;
                    var best = new System.Text.StringBuilder();
                    var current = new System.Text.StringBuilder();
                    for (int i = 0; i < headStr.Length; i++)
                    {
                        char ch = headStr[i];
                        bool ws = ch == '\r' || ch == '\n' || ch == '\t' || ch == ' ';
                        bool ok = (ch >= 'A' && ch <= 'Z') ||
                                  (ch >= 'a' && ch <= 'z') ||
                                  (ch >= '0' && ch <= '9') ||
                                  ch == '+' || ch == '/' || ch == '=' || ch == '-' || ch == '_';
                        if (ok)
                        {
                            current.Append(ch == '-' ? '+' : (ch == '_' ? '/' : ch));
                        }
                        else if (ws && current.Length > 0)
                        {
                            continue;
                        }
                        else
                        {
                            if (current.Length > bestLen)
                            {
                                best.Clear();
                                best.Append(current);
                                bestLen = current.Length;
                            }

                            current.Clear();
                        }
                    }
                    if (current.Length > bestLen)
                    {
                        best.Clear();
                        best.Append(current);
                        bestLen = current.Length;
                    }
                    if (bestLen >= 128) core = best.ToString();
                }
                if (string.IsNullOrWhiteSpace(core)) return false;
                // Strip non-base64 and normalize URL-safe
                System.Text.StringBuilder sb = new System.Text.StringBuilder((core ?? string.Empty).Length);
                foreach (var ch in core!)
                {
                    if (ch == '-' ) sb.Append('+');
                    else if (ch == '_' ) sb.Append('/');
                    else if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '+' || ch == '/' || ch == '=') sb.Append(ch);
                }
                string b64 = sb.ToString();
                // Pad to multiple of 4
                int mod = b64.Length % 4; if (mod != 0) b64 = b64.PadRight(b64.Length + (4 - mod), '=');
                try {
                    var raw = Convert.FromBase64String(b64);
                    decoded = raw.Length > Settings.EncodedDecodeMaxBytes ? raw.Take(Settings.EncodedDecodeMaxBytes).ToArray() : raw;
                    return decoded.Length > 0;
                } catch { return false; }
            }
            else if (ext == "hex")
            {
                // Extract longest normalized run of hex digits, allowing whitespace-separated dumps.
                int bestLen = 0;
                var best = new System.Text.StringBuilder();
                var current = new System.Text.StringBuilder();
                for (int i = 0; i < headStr.Length; i++)
                {
                    char ch = headStr[i];
                    bool ws = ch == '\r' || ch == '\n' || ch == '\t' || ch == ' ';
                    bool hx = (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f');
                    if (hx)
                    {
                        current.Append(ch);
                    }
                    else if (ws && current.Length > 0)
                    {
                        continue;
                    }
                    else
                    {
                        if (current.Length > bestLen)
                        {
                            best.Clear();
                            best.Append(current);
                            bestLen = current.Length;
                        }

                        current.Clear();
                    }
                }
                if (current.Length > bestLen)
                {
                    best.Clear();
                    best.Append(current);
                    bestLen = current.Length;
                }
                if (bestLen < 160) return false; // need at least 80 bytes
                string hex = best.ToString();
                // Decode pairs
                List<byte> outBytes = new List<byte>(Math.Min(Settings.EncodedDecodeMaxBytes, hex.Length/2));
                int j = 0; int maxOut = Settings.EncodedDecodeMaxBytes;
                for (int i = 0; i + 1 < hex.Length && j < maxOut; )
                {
                    char a = hex[i++]; char b = hex[i++];
                    if (!IsHex(a) || !IsHex(b)) continue;
                    byte val = (byte)((HexVal(a) << 4) | HexVal(b)); outBytes.Add(val); j++;
                }
                decoded = outBytes.ToArray();
                return decoded.Length > 0;
            }
            else if (ext == "b85")
            {
                // Extract data between <~ and ~>
                int a = headStr.IndexOf("<~", StringComparison.Ordinal);
                int b = a >= 0 ? headStr.IndexOf("~>", a + 2, StringComparison.Ordinal) : -1;
                if (a < 0 || b <= a + 2) return false;
                string core = headStr.Substring(a + 2, b - (a + 2));
                try {
                    var raw = DecodeAscii85(core);
                    decoded = raw.Length > Settings.EncodedDecodeMaxBytes ? raw.Take(Settings.EncodedDecodeMaxBytes).ToArray() : raw;
                    return decoded.Length > 0;
                } catch { return false; }
            }
            else if (ext == "uu")
            {
                // Find begin..end and decode a bounded sample
                var lines = headStr.Replace("\r", string.Empty).Split('\n');
                int i = Array.FindIndex(lines, l => l.StartsWith("begin ", StringComparison.OrdinalIgnoreCase));
                if (i < 0) return false;
                var outBytes = new List<byte>(Settings.EncodedDecodeMaxBytes);
                for (int k = i + 1; k < lines.Length && outBytes.Count < Settings.EncodedDecodeMaxBytes; k++)
                {
                    var line = lines[k];
                    if (line.Equals("end", StringComparison.OrdinalIgnoreCase)) break;
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    int len = ((line[0] - 32) & 63);
                    if (len <= 0) continue;
                    int pos = 1;
                    int lineWritten = 0;
                    while (pos + 3 < line.Length && outBytes.Count < Settings.EncodedDecodeMaxBytes)
                    {
                        int v1 = (line[pos++] - 32) & 63;
                        int v2 = (line[pos++] - 32) & 63;
                        int v3 = (line[pos++] - 32) & 63;
                        int v4 = (line[pos++] - 32) & 63;
                        byte b1 = (byte)((v1 << 2) | (v2 >> 4));
                        byte b2 = (byte)(((v2 & 0xF) << 4) | (v3 >> 2));
                        byte b3 = (byte)(((v3 & 0x3) << 6) | v4);
                        if (outBytes.Count < Settings.EncodedDecodeMaxBytes && lineWritten < len) { outBytes.Add(b1); lineWritten++; }
                        if (outBytes.Count < Settings.EncodedDecodeMaxBytes && lineWritten < len) { outBytes.Add(b2); lineWritten++; }
                        if (outBytes.Count < Settings.EncodedDecodeMaxBytes && lineWritten < len) { outBytes.Add(b3); lineWritten++; }
                    }
                }
                decoded = outBytes.ToArray();
                return decoded.Length > 0;
            }
            else if (ext == "qp")
            {
                var outBytes = new List<byte>(Math.Min(Settings.EncodedDecodeMaxBytes, headStr.Length));
                for (int i = 0; i < headStr.Length && outBytes.Count < Settings.EncodedDecodeMaxBytes; i++)
                {
                    char ch = headStr[i];
                    if (ch == '=')
                    {
                        if (i + 2 < headStr.Length && IsHex(headStr[i + 1]) && IsHex(headStr[i + 2]))
                        {
                            byte val = (byte)((HexVal(headStr[i + 1]) << 4) | HexVal(headStr[i + 2]));
                            outBytes.Add(val);
                            i += 2;
                            continue;
                        }

                        if (i + 1 < headStr.Length && headStr[i + 1] == '\n')
                        {
                            i += 1;
                            continue;
                        }

                        if (i + 2 < headStr.Length && headStr[i + 1] == '\r' && headStr[i + 2] == '\n')
                        {
                            i += 2;
                            continue;
                        }
                    }

                    if (ch == '\r' || ch == '\n')
                    {
                        continue;
                    }

                    if (ch <= 0xFF)
                    {
                        outBytes.Add((byte)ch);
                    }
                    else
                    {
                        foreach (var b in System.Text.Encoding.UTF8.GetBytes(new[] { ch }))
                        {
                            if (outBytes.Count >= Settings.EncodedDecodeMaxBytes) break;
                            outBytes.Add(b);
                        }
                    }
                }

                decoded = outBytes.ToArray();
                return decoded.Length > 0;
            }
            return false;
        } catch { decoded = Array.Empty<byte>(); return false; }

        static bool IsHex(char c) => (c>='0'&&c<='9')||(c>='A'&&c<='F')||(c>='a'&&c<='f');
        static int HexVal(char c) => c<= '9' ? (c - '0') : (c <= 'F' ? (c - 'A' + 10) : (c - 'a' + 10));
        static byte[] DecodeAscii85(string core)
        {
            // Implements a minimal Adobe ASCII85 decoder with 'z' shortcut; ignores whitespace
            var bytes = new List<byte>();
            int count = 0; uint tuple = 0;
            foreach (char ch in core)
            {
                if (char.IsWhiteSpace(ch)) continue;
                if (ch == 'z' && count == 0) { bytes.AddRange(new byte[]{0,0,0,0}); continue; }
                if (ch < '!' || ch > 'u') continue; // ignore out-of-range
                tuple = checked(tuple * 85 + (uint)(ch - '!'));
                count++;
                if (count == 5)
                {
                    bytes.Add((byte)((tuple >> 24) & 0xFF));
                    bytes.Add((byte)((tuple >> 16) & 0xFF));
                    bytes.Add((byte)((tuple >> 8) & 0xFF));
                    bytes.Add((byte)(tuple & 0xFF));
                    tuple = 0; count = 0;
                }
            }
            if (count > 1)
            {
                // pad with 'u' (84) and emit count-1 bytes
                for (int i = count; i < 5; i++) tuple = checked(tuple * 85 + 84);
                bytes.Add((byte)((tuple >> 24) & 0xFF));
                if (count >= 3) bytes.Add((byte)((tuple >> 16) & 0xFF));
                if (count >= 4) bytes.Add((byte)((tuple >> 8) & 0xFF));
            }
            return bytes.ToArray();
        }
    }
}
