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
        => TryMatchPkcs12(new ReadOnlyMemory<byte>(src.ToArray()), out result);

    internal static bool TryMatchPkcs12(ReadOnlyMemory<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!Asn1DetectionHelpers.TryReadPfxAuthSafe(src, out var version, out var contentTypeOid, out _))
        {
            return false;
        }

        if (version < 3)
        {
            return false;
        }

        if (!string.Equals(contentTypeOid, "1.2.840.113549.1.7.1", StringComparison.Ordinal))
        {
            return false;
        }

        result = new ContentTypeDetectionResult
        {
            Extension = "p12",
            MimeType = "application/x-pkcs12",
            Confidence = "Low",
            Reason = "asn1:pkcs12"
        };
        return true;
    }

    internal static bool TryMatchPkcs7SignedData(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchPkcs7SignedData(new ReadOnlyMemory<byte>(src.ToArray()), out result);

    internal static bool TryMatchPkcs7SignedData(ReadOnlyMemory<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!Asn1DetectionHelpers.TryMatchTopLevelContentInfo(src, "1.2.840.113549.1.7.2"))
        {
            return false;
        }

        result = new ContentTypeDetectionResult
        {
            Extension = "p7b",
            MimeType = "application/pkcs7-mime",
            Confidence = "Low",
            Reason = "asn1:pkcs7-signed-data"
        };
        return true;
    }

    internal static bool TryMatchDerCertificate(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchDerCertificate(new ReadOnlyMemory<byte>(src.ToArray()), out result);

    internal static bool TryMatchDerCertificate(ReadOnlyMemory<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!Asn1DetectionHelpers.TryMatchDerCertificateEnvelope(src))
        {
            return false;
        }

        result = new ContentTypeDetectionResult
        {
            Extension = "cer",
            MimeType = "application/pkix-cert",
            Confidence = "Low",
            Reason = "asn1:der-cert"
        };
        return true;
    }
}
