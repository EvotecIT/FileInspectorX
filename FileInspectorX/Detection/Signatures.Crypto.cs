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
        if (src[0] != 0x30) return false;

        try
        {
            var reader = new System.Formats.Asn1.AsnReader(src.ToArray(), System.Formats.Asn1.AsnEncodingRules.BER);
            var pfx = reader.ReadSequence();

            if (!pfx.TryReadInt32(out var version) || version < 3)
            {
                return false;
            }

            var authSafe = pfx.ReadSequence();
            var contentType = authSafe.ReadObjectIdentifier();
            if (!string.Equals(contentType, "1.2.840.113549.1.7.1", StringComparison.Ordinal))
            {
                return false;
            }

            if (!authSafe.HasData)
            {
                return false;
            }

            var contentTag = authSafe.PeekTag();
            if (contentTag.TagClass != System.Formats.Asn1.TagClass.ContextSpecific ||
                contentTag.TagValue != 0 ||
                !contentTag.IsConstructed)
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
        catch
        {
            return false;
        }
    }

    internal static bool TryMatchPkcs7SignedData(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 16) return false;
        if (src[0] != 0x30) return false; // ASN.1 SEQUENCE

        try
        {
            var reader = new System.Formats.Asn1.AsnReader(src.ToArray(), System.Formats.Asn1.AsnEncodingRules.BER);
            var contentInfo = reader.ReadSequence();
            var contentType = contentInfo.ReadObjectIdentifier();
            if (!string.Equals(contentType, "1.2.840.113549.1.7.2", StringComparison.Ordinal))
            {
                return false;
            }

            if (!contentInfo.HasData)
            {
                return false;
            }

            var contentTag = contentInfo.PeekTag();
            if (contentTag.TagClass != System.Formats.Asn1.TagClass.ContextSpecific ||
                contentTag.TagValue != 0 ||
                !contentTag.IsConstructed)
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
        catch
        {
            return false;
        }
    }

    internal static bool TryMatchDerCertificate(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 16) return false;
        if (src[0] != 0x30) return false; // SEQUENCE

        try
        {
            var reader = new System.Formats.Asn1.AsnReader(src.ToArray(), System.Formats.Asn1.AsnEncodingRules.BER);
            var certificate = reader.ReadSequence();

            var tbsCertificate = certificate.ReadSequence();
            if (tbsCertificate.HasData)
            {
                var firstTag = tbsCertificate.PeekTag();
                if (firstTag.TagClass == System.Formats.Asn1.TagClass.ContextSpecific &&
                    firstTag.TagValue == 0 &&
                    firstTag.IsConstructed)
                {
                    tbsCertificate.ReadSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0, isConstructed: true));
                }
            }

            tbsCertificate.ReadIntegerBytes(); // serialNumber

            var tbsSignatureAlgorithm = tbsCertificate.ReadSequence();
            var tbsSignatureOid = tbsSignatureAlgorithm.ReadObjectIdentifier();
            if (string.IsNullOrWhiteSpace(tbsSignatureOid))
            {
                return false;
            }

            tbsCertificate.ReadSequence(); // issuer
            tbsCertificate.ReadSequence(); // validity
            tbsCertificate.ReadSequence(); // subject
            tbsCertificate.ReadSequence(); // subjectPublicKeyInfo

            var certificateSignatureAlgorithm = certificate.ReadSequence();
            var certificateSignatureOid = certificateSignatureAlgorithm.ReadObjectIdentifier();
            if (!string.Equals(tbsSignatureOid, certificateSignatureOid, StringComparison.Ordinal))
            {
                return false;
            }

            var signatureValue = certificate.ReadBitString(out _);
            if (signatureValue.Length == 0)
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
        catch
        {
            return false;
        }
    }
}
