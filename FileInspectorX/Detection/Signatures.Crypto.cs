namespace FileInspectorX;

/// <summary>
/// Crypto-related lightweight detectors: OpenPGP (binary), DER X.509 and PKCS#12.
/// </summary>
internal static partial class Signatures
{
    internal static bool TryMatchOpenPgpBinary(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 2) return false;
        byte b0 = src[0];
        // Require new-format packet header (avoids colliding with formats like PNG 0x89...)
        if ((b0 & 0xC0) != 0xC0) return false; // bit7+bit6 must be set
        int tag = (b0 & 0x3F);
        // Only consider common BOF tags
        switch (tag) { case 1: case 3: case 9: case 11: case 12: break; default: return false; }
        // Basic length plausibility
        byte b1 = src[1];
        if (b1 == 255 && src.Length < 6) return false;
        // Treat as OpenPGP binary. Many tags map to encrypted/literal data; use generic encrypted MIME.
        result = new ContentTypeDetectionResult
        {
            Extension = "gpg",
            MimeType = "application/pgp-encrypted",
            Confidence = "Low",
            Reason = $"pgp:binary(tag={tag})"
        };
        return true;
    }

    internal static bool TryMatchPkcs12(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 16) return false;
        // Basic ASN.1 SEQUENCE start
        if (src[0] != 0x30) return false;
        // Look for OID 1.2.840.113549.1.12.10.1.* in the first 256 bytes: 2A 86 48 86 F7 0D 01 0C 0A 01
        byte[] pfxOid = new byte[] { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01 };
        int window = Math.Min(src.Length, 256);
        for (int i = 0; i <= window - pfxOid.Length; i++)
        {
            if (src.Slice(i, pfxOid.Length).SequenceEqual(pfxOid))
            {
                result = new ContentTypeDetectionResult { Extension = "p12", MimeType = "application/x-pkcs12", Confidence = "Low", Reason = "asn1:pkcs12" };
                return true;
            }
        }
        return false;
    }

    internal static bool TryMatchDerCertificate(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 8) return false;
        if (src[0] != 0x30) return false; // SEQUENCE
        // Check long-form length
        int i = 1;
        int len = src[i++];
        if ((len & 0x80) != 0)
        {
            int n = len & 0x7F; if (n <= 0 || n > 3 || src.Length < 2 + n) return false; i += n;
        }
        // Heuristic: presence of common OID prefixes for signature algorithms within the first 128 bytes
        byte[] rsaPrefix = new byte[] { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01 }; // 1.2.840.113549.1.1
        byte[] ecdsaPrefix = new byte[] { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04 }; // 1.2.840.10045.4 (ECDSA)
        int w = Math.Min(src.Length, 128);
        bool hasAlg = ContainsSeq(src.Slice(0, w), rsaPrefix) || ContainsSeq(src.Slice(0, w), ecdsaPrefix);
        if (!hasAlg) return false;
        result = new ContentTypeDetectionResult { Extension = "cer", MimeType = "application/pkix-cert", Confidence = "Low", Reason = "asn1:der-cert" };
        return true;

        static bool ContainsSeq(ReadOnlySpan<byte> hay, byte[] needle)
        {
            for (int k = 0; k <= hay.Length - needle.Length; k++)
                if (hay.Slice(k, needle.Length).SequenceEqual(needle)) return true;
            return false;
        }
    }
}
