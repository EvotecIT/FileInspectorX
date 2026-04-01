namespace FileInspectorX;

internal static class Asn1DetectionHelpers
{
    private static readonly System.Formats.Asn1.Asn1Tag ExplicitContextSpecificZero =
        new(System.Formats.Asn1.TagClass.ContextSpecific, 0, isConstructed: true);

    internal static bool TryMatchTopLevelContentInfo(ReadOnlyMemory<byte> src, string expectedContentTypeOid)
    {
        if (!TryReadTopLevelContentInfo(src, out var contentTypeOid, out _))
        {
            return false;
        }

        return string.Equals(contentTypeOid, expectedContentTypeOid, StringComparison.Ordinal);
    }

    internal static bool TryReadTopLevelContentInfo(
        ReadOnlyMemory<byte> src,
        out string? contentTypeOid,
        out System.ReadOnlyMemory<byte> explicitContent)
    {
        contentTypeOid = null;
        explicitContent = default;

        try
        {
            if (!TryReadTopLevelSequence(src, out var contentInfo))
            {
                return false;
            }

            contentTypeOid = contentInfo.ReadObjectIdentifier();
            if (string.IsNullOrWhiteSpace(contentTypeOid))
            {
                return false;
            }

            if (!TryReadExplicitContextSpecificZero(contentInfo, out explicitContent))
            {
                return false;
            }

            return !contentInfo.HasData;
        }
        catch
        {
            contentTypeOid = null;
            explicitContent = default;
            return false;
        }
    }

    internal static bool TryReadPfxAuthSafe(
        ReadOnlyMemory<byte> src,
        out int version,
        out string? authSafeContentTypeOid,
        out System.ReadOnlyMemory<byte> explicitAuthSafeContent)
    {
        version = 0;
        authSafeContentTypeOid = null;
        explicitAuthSafeContent = default;

        try
        {
            if (!TryReadTopLevelSequence(src, out var pfx))
            {
                return false;
            }

            if (!pfx.TryReadInt32(out version))
            {
                return false;
            }

            var authSafe = pfx.ReadSequence();
            authSafeContentTypeOid = authSafe.ReadObjectIdentifier();
            if (string.IsNullOrWhiteSpace(authSafeContentTypeOid))
            {
                return false;
            }

            if (!TryReadExplicitContextSpecificZero(authSafe, out explicitAuthSafeContent))
            {
                return false;
            }

            if (authSafe.HasData)
            {
                return false;
            }

            if (pfx.HasData)
            {
                pfx.ReadEncodedValue();
            }

            return !pfx.HasData;
        }
        catch
        {
            version = 0;
            authSafeContentTypeOid = null;
            explicitAuthSafeContent = default;
            return false;
        }
    }

    internal static bool TryMatchDerCertificateEnvelope(ReadOnlyMemory<byte> src)
    {
        try
        {
            if (!TryReadTopLevelSequence(src, out var certificate))
            {
                return false;
            }

            var tbsCertificate = certificate.ReadSequence();
            if (tbsCertificate.HasData)
            {
                var firstTag = tbsCertificate.PeekTag();
                if (firstTag.TagClass == System.Formats.Asn1.TagClass.ContextSpecific &&
                    firstTag.TagValue == 0 &&
                    firstTag.IsConstructed)
                {
                    tbsCertificate.ReadSequence(ExplicitContextSpecificZero);
                }
            }

            tbsCertificate.ReadIntegerBytes();

            if (!TryReadAlgorithmIdentifierOid(tbsCertificate, out var tbsSignatureOid))
            {
                return false;
            }

            tbsCertificate.ReadSequence();
            tbsCertificate.ReadSequence();
            tbsCertificate.ReadSequence();
            tbsCertificate.ReadSequence();
            if (!TryReadAlgorithmIdentifierOid(certificate, out var certificateSignatureOid))
            {
                return false;
            }

            if (!string.Equals(tbsSignatureOid, certificateSignatureOid, StringComparison.Ordinal))
            {
                return false;
            }

            var signatureValue = certificate.ReadBitString(out _);
            if (signatureValue.Length == 0)
            {
                return false;
            }

            while (tbsCertificate.HasData)
            {
                var optionalTag = tbsCertificate.PeekTag();
                if (optionalTag.TagClass != System.Formats.Asn1.TagClass.ContextSpecific ||
                    optionalTag.TagValue < 1 ||
                    optionalTag.TagValue > 3)
                {
                    return false;
                }

                tbsCertificate.ReadEncodedValue();
            }

            return !certificate.HasData;
        }
        catch
        {
            return false;
        }
    }

    internal static bool TryMatchTopLevelContentInfo(ReadOnlySpan<byte> src, string expectedContentTypeOid)
        => TryMatchTopLevelContentInfo(new ReadOnlyMemory<byte>(src.ToArray()), expectedContentTypeOid);

    internal static bool TryReadPfxAuthSafe(
        ReadOnlySpan<byte> src,
        out int version,
        out string? authSafeContentTypeOid,
        out System.ReadOnlyMemory<byte> explicitAuthSafeContent)
        => TryReadPfxAuthSafe(new ReadOnlyMemory<byte>(src.ToArray()), out version, out authSafeContentTypeOid, out explicitAuthSafeContent);

    internal static bool TryMatchDerCertificateEnvelope(ReadOnlySpan<byte> src)
        => TryMatchDerCertificateEnvelope(new ReadOnlyMemory<byte>(src.ToArray()));

    private static bool TryReadTopLevelSequence(ReadOnlyMemory<byte> src, out System.Formats.Asn1.AsnReader sequence)
    {
        sequence = null!;
        if (src.Length < 2 || src.Span[0] != 0x30)
        {
            return false;
        }

        try
        {
            var reader = new System.Formats.Asn1.AsnReader(src, System.Formats.Asn1.AsnEncodingRules.BER);
            sequence = reader.ReadSequence();
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryReadExplicitContextSpecificZero(
        System.Formats.Asn1.AsnReader reader,
        out System.ReadOnlyMemory<byte> explicitContent)
    {
        explicitContent = default;
        if (!reader.HasData)
        {
            return false;
        }

        var contentTag = reader.PeekTag();
        if (contentTag.TagClass != System.Formats.Asn1.TagClass.ContextSpecific ||
            contentTag.TagValue != 0 ||
            !contentTag.IsConstructed)
        {
            return false;
        }

        explicitContent = reader.ReadEncodedValue();
        return true;
    }

    private static bool TryReadAlgorithmIdentifierOid(System.Formats.Asn1.AsnReader reader, out string? oid)
    {
        oid = null;
        var algorithmIdentifier = reader.ReadSequence();
        oid = algorithmIdentifier.ReadObjectIdentifier();
        return !string.IsNullOrWhiteSpace(oid);
    }
}
