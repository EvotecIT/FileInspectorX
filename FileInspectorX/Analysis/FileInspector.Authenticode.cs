using System.Runtime.InteropServices;

namespace FileInspectorX;

public static partial class FileInspector
{
    private static void TryPopulateAuthenticode(string path, FileAnalysis res)
    {
        res.Authenticode = null;
        try {
            if (!PeReader.TryReadPe(path, out var pe) || pe.SecuritySize == 0 || pe.SecurityOffset == 0) return;
            var ai = new AuthenticodeInfo { Present = true, VerificationNote = "Envelope + chain only; file hash not recomputed." };
            res.Flags |= ContentFlags.PeHasAuthenticode;

#if NET8_0_OR_GREATER || NET472
            try {
                using var fs = File.OpenRead(path);
                fs.Seek((long)pe.SecurityOffset, SeekOrigin.Begin);
                using var br = new BinaryReader(fs);
                uint wclen = br.ReadUInt32();
                ushort wcrev = br.ReadUInt16();
                ushort wctype = br.ReadUInt16();
                int pkcsLen = (int)Math.Max(0, wclen - 8);
                var pkcs = br.ReadBytes(Math.Min(pkcsLen, (int)(pe.SecuritySize - 8)));

                // Parse PKCS#7 SignedData
                var cms = new System.Security.Cryptography.Pkcs.SignedCms();
                cms.Decode(pkcs);
                ai.DigestAlgorithm = cms.SignerInfos.Count > 0 ? cms.SignerInfos[0].DigestAlgorithm?.FriendlyName : null;

                // Envelope signature check (cryptographic only)
                bool sigOk;
                try { cms.CheckSignature(true); sigOk = true; } catch { sigOk = false; }
                ai.EnvelopeSignatureValid = sigOk;

                // Extract signer cert
                var signer = cms.SignerInfos.Count > 0 ? cms.SignerInfos[0] : null;
                var cert = signer?.Certificate;
                if (cert != null) {
                    ai.SignerSubject = cert.Subject;
                    ai.SignerIssuer = cert.Issuer;
                    FillCertFields(cert, ai);
                    ai.NotBefore = cert.NotBefore; ai.NotAfter = cert.NotAfter;
                    ai.SignerThumbprint = cert.Thumbprint;
                    ai.SignerSerialHex = cert.SerialNumber;
                    ai.SignatureAlgorithm = cert.SignatureAlgorithm?.FriendlyName;

                    // Chain build (best-effort, no revocation)
                    try {
                        var chain = new System.Security.Cryptography.X509Certificates.X509Chain();
                        chain.ChainPolicy.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
                        chain.ChainPolicy.VerificationFlags = System.Security.Cryptography.X509Certificates.X509VerificationFlags.NoFlag;
                        bool ok = chain.Build(cert);
                        ai.ChainValid = ok;
                        if (ok) res.Flags |= ContentFlags.PeAuthenticodeChainValid;
                        try { ai.IsSelfSigned = string.Equals(cert.Subject, cert.Issuer, StringComparison.OrdinalIgnoreCase); } catch { }
                    } catch { }
                }

                // File digest (cross-platform recomputation)
                try {
                    if (cms.ContentInfo?.Content != null && cms.ContentInfo.Content.Length > 0) {
                        if (TryGetAuthenticodeContentDigest(cms.ContentInfo.Content, out var fileDigestOid, out var fileDigestBytes)) {
                            ai.FileDigestAlgorithmOid = fileDigestOid;
                            ai.FileDigestAlgorithm = OidToFriendly(fileDigestOid);
                            var recomputed = ComputePeImageDigest(path, pe, fileDigestOid);
                            if (recomputed != null) ai.FileHashMatches = ByteEquals(recomputed, fileDigestBytes);
                        }
                    }
                } catch { }

                // Timestamp (countersignature)
                try {
                    if (signer != null && signer.CounterSignerInfos != null && signer.CounterSignerInfos.Count > 0) {
                        var tsa = signer.CounterSignerInfos[0];
                        res.Flags |= ContentFlags.PeAuthenticodeHasTimestamp;
                        ai.TimestampPresent = true;
                        ai.TimestampAuthority = tsa.Certificate?.Subject;
                        // Find signing time attribute
                        foreach (var ua in tsa.SignedAttributes) {
                            if (ua.Oid?.Value == "1.2.840.113549.1.9.5" && ua.Values.Count > 0) {
                                if (ua.Values[0] is System.Security.Cryptography.AsnEncodedData ad) {
                                    try {
                                        var sts = new System.Security.Cryptography.Pkcs.Pkcs9SigningTime();
                                        sts.CopyFrom(ad);
                                        ai.TimestampTime = new DateTimeOffset(sts.SigningTime);
                                    } catch { }
                                }
                            }
                        }
                    }
                } catch { }
            } catch { }
#endif
            res.Authenticode = ai;
            // Windows policy verification (full policy + catalog support)
            if (Settings.VerifyAuthenticodeWithWinTrust) TryVerifyAuthenticodeWinTrust(path, res);
        } catch { }
    }

    private static void FillCertFields(System.Security.Cryptography.X509Certificates.X509Certificate2 cert, AuthenticodeInfo ai)
    {
        try {
            static string? GetRdn(System.Security.Cryptography.X509Certificates.X500DistinguishedName dn, string key)
            {
                var s = dn?.Name ?? string.Empty;
                if (string.IsNullOrEmpty(s)) return null;
                foreach (var part in s.Split(','))
                {
                    var kv = part.Trim();
                    int eq = kv.IndexOf('='); if (eq <= 0) continue;
                    var k = kv.Substring(0, eq).Trim(); var v = kv.Substring(eq + 1).Trim();
                    if (k.Equals(key, StringComparison.OrdinalIgnoreCase)) return v;
                }
                return null;
            }
            ai.SignerSubjectCN = GetRdn(cert.SubjectName, "CN");
            ai.SignerSubjectO  = GetRdn(cert.SubjectName, "O");
            ai.IssuerCN = GetRdn(cert.IssuerName, "CN");
            ai.IssuerO  = GetRdn(cert.IssuerName, "O");
        } catch { }
    }

    private static bool TryGetAuthenticodeContentDigest(byte[] content, out string oid, out byte[] digest)
    {
        oid = string.Empty; digest = Array.Empty<byte>();
        try {
            var reader = new System.Formats.Asn1.AsnReader(new ReadOnlyMemory<byte>(content), System.Formats.Asn1.AsnEncodingRules.BER);
            var seq = reader.ReadSequence();
            // data: SpcAttributeTypeAndOptionalValue (skip)
            seq.ReadEncodedValue();
            // messageDigest: DigestInfo
            var di = seq.ReadSequence();
            var alg = di.ReadSequence();
            oid = alg.ReadObjectIdentifier();
            if (alg.HasData) alg.ReadEncodedValue(); // parameters (ignored)
            digest = di.ReadOctetString();
            di.ThrowIfNotEmpty();
            seq.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();
            return !string.IsNullOrEmpty(oid) && digest.Length > 0;
        } catch { return false; }
    }

    private static byte[]? ComputePeImageDigest(string path, PeInfo pe, string digestOid)
    {
        try {
            using var algo = CreateHashAlgorithm(digestOid);
            if (algo == null) return null;
            using var fs = File.OpenRead(path);
            long fileLen = fs.Length;
            long certOff = pe.SecurityOffset;
            long certEnd = certOff + pe.SecuritySize;
            if (certOff <= 0 || certEnd <= certOff || certEnd > fileLen) { certOff = fileLen; certEnd = fileLen; }
            long csumOff = pe.ChecksumFileOffset;
            // Hash from 0..csumOff
            HashRange(fs, algo, 0, Math.Max(0, csumOff));
            // Hash 4 zero bytes for checksum
            algo.TransformBlock(new byte[4], 0, 4, null, 0);
            // Hash from csumOff+4 up to certOff
            HashRange(fs, algo, csumOff + 4, Math.Max(0, certOff - (csumOff + 4)));
            // Skip certificate table and hash any trailing bytes
            if (certEnd < fileLen) HashRange(fs, algo, certEnd, fileLen - certEnd);
            algo.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            return algo.Hash;
        } catch { return null; }
    }

    private static void HashRange(FileStream fs, System.Security.Cryptography.HashAlgorithm algo, long start, long length)
    {
        if (length <= 0) return;
        fs.Seek(start, SeekOrigin.Begin);
        var buf = new byte[64 * 1024];
        long remaining = length;
        while (remaining > 0) {
            int toRead = (int)Math.Min(buf.Length, remaining);
            int n = fs.Read(buf, 0, toRead);
            if (n <= 0) break;
            algo.TransformBlock(buf, 0, n, null, 0);
            remaining -= n;
        }
    }

    private static System.Security.Cryptography.HashAlgorithm? CreateHashAlgorithm(string oid)
    {
        try {
            return oid switch {
                "1.3.14.3.2.26" => System.Security.Cryptography.SHA1.Create(),
                "2.16.840.1.101.3.4.2.1" => System.Security.Cryptography.SHA256.Create(),
                "2.16.840.1.101.3.4.2.2" => System.Security.Cryptography.SHA384.Create(),
                "2.16.840.1.101.3.4.2.3" => System.Security.Cryptography.SHA512.Create(),
                _ => System.Security.Cryptography.SHA256.Create(),
            };
        } catch { return null; }
    }

    private static string OidToFriendly(string oid) => oid switch {
        "1.3.14.3.2.26" => "SHA1",
        "2.16.840.1.101.3.4.2.1" => "SHA256",
        "2.16.840.1.101.3.4.2.2" => "SHA384",
        "2.16.840.1.101.3.4.2.3" => "SHA512",
        _ => oid
    };

    private static bool ByteEquals(byte[] a, byte[] b)
    {
        if (a == null || b == null || a.Length != b.Length) return false;
        int acc = 0; for (int i = 0; i < a.Length; i++) acc |= a[i] ^ b[i];
        return acc == 0;
    }
}
