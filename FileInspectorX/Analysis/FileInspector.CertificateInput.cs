using System.IO.Compression;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace FileInspectorX;

public static partial class FileInspector
{
    private static bool TryLoadCertificateFromFile(InspectionInput input, string ext, out X509Certificate2 cert)
    {
        var path = input.Name;
        cert = null!;
        try
        {
            if (string.Equals(ext, "pem", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(ext, "crt", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(ext, "cer", StringComparison.OrdinalIgnoreCase))
            {
                if (!TryReadPemCertificateBlock(input, out var pemBlock, out var derBytes))
                {
                    if (string.Equals(ext, "pem", StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // .crt/.cer may still be DER-encoded, so fall through to the bounded raw-byte import below.
                }
                else
                {
#if NET5_0_OR_GREATER
                    try
                    {
                        cert = X509Certificate2.CreateFromPem(pemBlock);
                        return cert != null;
                    }
                    catch
                    {
                        // Fall back to DER import below when PEM parsing is unavailable or rejects the block.
                    }
#endif
                    cert = new X509Certificate2(derBytes);
                    return cert != null;
                }
            }

            if (!TryReadFileBytesWithinBudget(input, GetCertificateParseReadBudgetBytes(), out var rawBytes))
            {
                return false;
            }

            cert = new X509Certificate2(rawBytes);
            return cert != null;
        }
        catch { return false; }
    }

    private static int GetCertificateParseReadBudgetBytes()
    {
        long budget = OperationSettings.DetectionReadBudgetBytes;
        if (budget <= 0) budget = 1_000_000;
        if (budget > 8L * 1024L * 1024L) budget = 8L * 1024L * 1024L;
        return (int)Math.Max(256, budget);
    }

    private static bool TryReadFileBytesWithinBudget(InspectionInput input, int maxBytes, out byte[] data)
    {
        var path = input.Name;
        data = Array.Empty<byte>();
        try
        {
            using var fs = input.OpenRead();
            long length = fs.Length;
            if (length <= 0 || length > maxBytes)
            {
                return false;
            }

            data = new byte[(int)length];
            var offset = 0;
            while (offset < data.Length)
            {
                var read = fs.Read(data, offset, data.Length - offset);
                if (read <= 0) break;
                offset += read;
            }

            if (offset <= 0)
            {
                data = Array.Empty<byte>();
                return false;
            }

            if (offset != data.Length)
            {
                Array.Resize(ref data, offset);
            }

            return true;
        }
        catch
        {
            data = Array.Empty<byte>();
            return false;
        }
    }

    private static bool TryReadPemCertificateBlock(InspectionInput input, out string pemBlock, out byte[] derBytes)
    {
        var path = input.Name;
        pemBlock = string.Empty;
        derBytes = Array.Empty<byte>();
        try
        {
            var text = ReadHeadText(input, GetCertificateParseReadBudgetBytes());
            if (string.IsNullOrWhiteSpace(text))
            {
                return false;
            }

            const string begin = "-----BEGIN CERTIFICATE-----";
            const string end = "-----END CERTIFICATE-----";
            int start = text.IndexOf(begin, StringComparison.OrdinalIgnoreCase);
            int endIndex = text.IndexOf(end, StringComparison.OrdinalIgnoreCase);
            if (start < 0 || endIndex <= start)
            {
                return false;
            }

            var pemEnd = endIndex + end.Length;
            pemBlock = text.Substring(start, pemEnd - start);
            var b64 = text.Substring(start + begin.Length, endIndex - (start + begin.Length))
                .Replace("\r", string.Empty)
                .Replace("\n", string.Empty)
                .Trim();
            derBytes = System.Convert.FromBase64String(b64);
            return derBytes.Length > 0;
        }
        catch
        {
            pemBlock = string.Empty;
            derBytes = Array.Empty<byte>();
            return false;
        }
    }

}
