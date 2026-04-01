using Xunit;
using FI = FileInspectorX.FileInspector;

namespace FileInspectorX.Tests;

[Collection(nameof(DetectionSettingsCollection))]
public class CryptoDetectionsTests
{
    [Fact]
    public void Detect_OpenPgp_Binary_Header()
    {
        var p = Path.GetTempFileName();
        try
        {
            // New-format packet: bit7=1, bit6=1, tag=9 (Symmetrically Encrypted Data)
            // Length one-octet = 5
            var buf = new byte[] { 0xC0 | 9, 0x05, 0,0,0,0,0 };
            File.WriteAllBytes(p, buf);
            var res = FI.Detect(p);
            Assert.NotNull(res);
            Assert.Equal("gpg", res!.Extension);
            Assert.Equal("application/pgp-encrypted", res.MimeType);
            Assert.StartsWith("pgp:binary", res.Reason);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Detect_Pkcs12_By_TopLevel_Pfx_Shape()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".p12");
        try
        {
            using var rsa = System.Security.Cryptography.RSA.Create(2048);
            var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                "CN=FileInspectorX PFX Test",
                rsa,
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                System.Security.Cryptography.RSASignaturePadding.Pkcs1);
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(7));
            File.WriteAllBytes(p, certificate.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pkcs12));

            var res = FI.Detect(p);
            Assert.NotNull(res);
            Assert.Equal("p12", res!.Extension);
            Assert.Equal("application/x-pkcs12", res.MimeType);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Detect_Pkcs12_DoesNotMatch_When_DataOid_Is_Not_TopLevel_ContentType()
    {
        byte[] contentInfoOidLookalike = File.ReadAllBytes(
            TestHelpers.GetFixturePath("crypto", "pkcs12-contenttype-lookalike.p12"));

        var detection = FI.Detect(contentInfoOidLookalike);

        Assert.True(detection == null || !string.Equals(detection.Extension, "p12", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Detect_Pkcs12_DoesNotMatch_When_AuthSafe_Wrapper_Is_Missing()
    {
        byte[] missingAuthSafeWrapper = File.ReadAllBytes(
            TestHelpers.GetFixturePath("crypto", "pkcs12-missing-authsafe-wrapper.p12"));

        var detection = FI.Detect(missingAuthSafeWrapper);

        Assert.True(detection == null || !string.Equals(detection.Extension, "p12", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Detect_Pkcs12_DoesNotMatch_When_Pfx_Version_Is_Not_V3()
    {
        byte[] nonStandardVersion =
        [
            0x30, 0x12,
            0x02, 0x01, 0x64,
            0x30, 0x0D,
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
            0xA0, 0x00
        ];

        var detection = FI.Detect(nonStandardVersion);

        Assert.True(detection == null || !string.Equals(detection.Extension, "p12", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Detect_Der_X509_By_CertificateShape()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".cer");
        try
        {
            using var rsa = System.Security.Cryptography.RSA.Create(2048);
            var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                "CN=FileInspectorX DER Test",
                rsa,
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                System.Security.Cryptography.RSASignaturePadding.Pkcs1);
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(7));
            File.WriteAllBytes(p, certificate.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert));

            var res = FI.Detect(p);
            Assert.NotNull(res);
            Assert.Equal("cer", res!.Extension);
            Assert.Equal("application/pkix-cert", res.MimeType);

            // Friendly type check via Analyze->ReportView
            var rv = FileInspectorX.ReportView.From(FI.Analyze(p));
            Assert.Equal("X.509 certificate", rv.DetectedTypeFriendly);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Detect_Pgp_Ascii_Message()
    {
        var p = Path.GetTempFileName();
        try
        {
            File.WriteAllText(p, "-----BEGIN PGP MESSAGE-----\nVersion: Test\n\nABCD\n-----END PGP MESSAGE-----\n");
            var res = FI.Detect(p);
            Assert.NotNull(res);
            Assert.Equal("asc", res!.Extension);
            Assert.Equal("application/pgp-encrypted", res.MimeType);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Detect_Pem_Certificate_Ascii()
    {
        var p = Path.GetTempFileName();
        try
        {
            var text = "-----BEGIN CERTIFICATE-----\nMIIB...FAKE...CERT\n-----END CERTIFICATE-----\n";
            File.WriteAllText(p, text);
            var res = FI.Detect(p);
            Assert.NotNull(res);
            Assert.Equal("crt", res!.Extension);
            Assert.Equal("application/pkix-cert", res.MimeType);
            Assert.StartsWith("text:pem-cert", res.Reason);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Detect_Pem_PrivateKey_Not_Yaml()
    {
        var p = Path.GetTempFileName();
        try
        {
            var text = "-----BEGIN PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,0123456789ABCDEF\nABCDEF==\n-----END PRIVATE KEY-----\n";
            File.WriteAllText(p, text);
            var res = FI.Detect(p);
            Assert.NotNull(res);
            Assert.Equal("key", res!.Extension);
            Assert.Equal("application/x-pem-key", res.MimeType);
            Assert.NotEqual("yml", res.Extension);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Detect_Pgp_Ascii_PrivateKey()
    {
        var p = Path.GetTempFileName();
        try
        {
            File.WriteAllText(p, "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: Test\n\nABCD\n-----END PGP PRIVATE KEY BLOCK-----\n");
            var res = FI.Detect(p);
            Assert.NotNull(res);
            Assert.Equal("asc", res!.Extension);
            Assert.Equal("application/pgp-keys", res.MimeType);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Detect_DerCertificate_DoesNotMatch_When_RsaOid_Appears_Inside_Unrelated_Blob()
    {
        byte[] rsaOidLookalike = File.ReadAllBytes(
            TestHelpers.GetFixturePath("crypto", "der-cert-rsa-oid-lookalike.cer"));

        var detection = FI.Detect(rsaOidLookalike);

        Assert.True(detection == null || !string.Equals(detection.Extension, "cer", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Detect_DerCertificate_DoesNotMatch_When_TopLevel_CertificateShape_Is_Incomplete()
    {
        byte[] incompleteCertificateEnvelope = File.ReadAllBytes(
            TestHelpers.GetFixturePath("crypto", "der-cert-incomplete-envelope.cer"));

        var detection = FI.Detect(incompleteCertificateEnvelope);

        Assert.True(detection == null || !string.Equals(detection.Extension, "cer", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Detect_Pkcs7SignedData_DoesNotMatch_When_Oid_Is_Not_TopLevel_ContentType()
    {
        byte[] signedDataOidLookalike = File.ReadAllBytes(
            TestHelpers.GetFixturePath("crypto", "pkcs7-signeddata-oid-lookalike.p7b"));

        var detection = FI.Detect(signedDataOidLookalike);

        Assert.True(detection == null || !string.Equals(detection.Extension, "p7b", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Detect_Pkcs7SignedData_DoesNotMatch_When_ContentWrapper_Is_Missing()
    {
        byte[] missingExplicitWrapper = File.ReadAllBytes(
            TestHelpers.GetFixturePath("crypto", "pkcs7-missing-explicit-wrapper.p7b"));

        var detection = FI.Detect(missingExplicitWrapper);

        Assert.True(detection == null || !string.Equals(detection.Extension, "p7b", StringComparison.OrdinalIgnoreCase));
    }

#if NET8_0_OR_GREATER
    [Fact]
    public void Analyze_PemCertificate_UsesBoundedHeadRead()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".pem");
        var originalBudget = FileInspectorX.Settings.DetectionReadBudgetBytes;
        try
        {
            using var rsa = System.Security.Cryptography.RSA.Create(2048);
            var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                "CN=FileInspectorX Test",
                rsa,
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                System.Security.Cryptography.RSASignaturePadding.Pkcs1);
            var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(7));
            var pem = certificate.ExportCertificatePem();
            File.WriteAllText(p, pem + string.Concat(Enumerable.Repeat("\nTRAILER-CONTENT\n", 256)));

            FileInspectorX.Settings.DetectionReadBudgetBytes = pem.Length + 128;
            var analysis = FI.Analyze(p);

            Assert.NotNull(analysis.Certificate);
            Assert.Contains("CN=FileInspectorX Test", analysis.Certificate!.Subject ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            FileInspectorX.Settings.DetectionReadBudgetBytes = originalBudget;
            if (File.Exists(p)) File.Delete(p);
        }
    }

    [Fact]
    public void Analyze_P7bCertificateBundle_ParsesWithinBudget()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".p7b");
        var originalBudget = FileInspectorX.Settings.DetectionReadBudgetBytes;
        try
        {
            var encodedBundle = CreateSignedCmsBundle("CN=FileInspectorX Bundle");
            File.WriteAllBytes(p, encodedBundle);

            FileInspectorX.Settings.DetectionReadBudgetBytes = encodedBundle.Length + 128;

            var detection = FI.Detect(p);
            Assert.NotNull(detection);
            Assert.Equal("p7b", detection!.Extension);

            var analysis = FI.Analyze(p);

            Assert.True((analysis.CertificateBundleCount ?? 0) >= 1);
            Assert.Contains(
                analysis.CertificateBundleSubjects ?? Array.Empty<string>(),
                subject => subject.Contains("CN=FileInspectorX Bundle", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            FileInspectorX.Settings.DetectionReadBudgetBytes = originalBudget;
            if (File.Exists(p)) File.Delete(p);
        }
    }

    [Fact]
    public void Analyze_P7bCertificateBundle_SkipsParsingWhenFileExceedsBudget()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".p7b");
        var originalBudget = FileInspectorX.Settings.DetectionReadBudgetBytes;
        try
        {
            var encodedBundle = CreateSignedCmsBundle("CN=FileInspectorX Oversized Bundle");
            var oversizedBytes = new byte[encodedBundle.Length + 4096];
            Buffer.BlockCopy(encodedBundle, 0, oversizedBytes, 0, encodedBundle.Length);
            File.WriteAllBytes(p, oversizedBytes);

            FileInspectorX.Settings.DetectionReadBudgetBytes = Math.Max(256, encodedBundle.Length / 2);

            var detection = FI.Detect(p);
            Assert.NotNull(detection);
            Assert.Equal("p7b", detection!.Extension);

            var analysis = FI.Analyze(p);

            Assert.Null(analysis.CertificateBundleCount);
            Assert.True(analysis.CertificateBundleSubjects == null || analysis.CertificateBundleSubjects.Count == 0);
        }
        finally
        {
            FileInspectorX.Settings.DetectionReadBudgetBytes = originalBudget;
            if (File.Exists(p)) File.Delete(p);
        }
    }

    [Fact]
    public void Analyze_SpcCertificateBundle_PreservesDeclaredExtension_And_ParsesWithinBudget()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".spc");
        var originalBudget = FileInspectorX.Settings.DetectionReadBudgetBytes;
        try
        {
            var encodedBundle = CreateSignedCmsBundle("CN=FileInspectorX SPC Bundle");
            File.WriteAllBytes(p, encodedBundle);

            FileInspectorX.Settings.DetectionReadBudgetBytes = encodedBundle.Length + 128;

            var detection = FI.Detect(p);
            Assert.NotNull(detection);
            Assert.Equal("spc", detection!.Extension);
            Assert.Equal("application/x-pkcs7-certificates", detection.MimeType);
            Assert.Contains("bias:decl:spc", detection.Reason, StringComparison.OrdinalIgnoreCase);

            var analysis = FI.Analyze(p);

            Assert.True((analysis.CertificateBundleCount ?? 0) >= 1);
            Assert.Contains(
                analysis.CertificateBundleSubjects ?? Array.Empty<string>(),
                subject => subject.Contains("CN=FileInspectorX SPC Bundle", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            FileInspectorX.Settings.DetectionReadBudgetBytes = originalBudget;
            if (File.Exists(p)) File.Delete(p);
        }
    }

    [Fact]
    public void Analyze_P7sSignedData_PreservesDeclaredExtension_And_ParsesWithinBudget()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".p7s");
        var originalBudget = FileInspectorX.Settings.DetectionReadBudgetBytes;
        try
        {
            var encodedBundle = CreateSignedCmsBundle("CN=FileInspectorX P7S Bundle");
            File.WriteAllBytes(p, encodedBundle);

            FileInspectorX.Settings.DetectionReadBudgetBytes = encodedBundle.Length + 128;

            var detection = FI.Detect(p);
            Assert.NotNull(detection);
            Assert.Equal("p7s", detection!.Extension);
            Assert.Equal("application/pkcs7-signature", detection.MimeType);
            Assert.Contains("bias:decl:p7s", detection.Reason, StringComparison.OrdinalIgnoreCase);

            var analysis = FI.Analyze(p);

            Assert.True((analysis.CertificateBundleCount ?? 0) >= 1);
            Assert.Contains(
                analysis.CertificateBundleSubjects ?? Array.Empty<string>(),
                subject => subject.Contains("CN=FileInspectorX P7S Bundle", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            FileInspectorX.Settings.DetectionReadBudgetBytes = originalBudget;
            if (File.Exists(p)) File.Delete(p);
        }
    }

    [Fact]
    public void Detect_DerCertificate_DoesNotCollideWithPkcs7SignedData()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".cer");
        try
        {
            using var rsa = System.Security.Cryptography.RSA.Create(2048);
            var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                "CN=FileInspectorX DER Test",
                rsa,
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                System.Security.Cryptography.RSASignaturePadding.Pkcs1);
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(7));
            File.WriteAllBytes(p, certificate.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert));

            var detection = FI.Detect(p);

            Assert.NotNull(detection);
            Assert.Equal("cer", detection!.Extension);
            Assert.Equal("application/pkix-cert", detection.MimeType);
            Assert.StartsWith("asn1:der-cert", detection.Reason);
        }
        finally
        {
            if (File.Exists(p)) File.Delete(p);
        }
    }

    private static byte[] CreateSignedCmsBundle(string subjectName)
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            subjectName,
            rsa,
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(7));

        var content = new System.Security.Cryptography.Pkcs.ContentInfo(new byte[] { 0x46, 0x49, 0x58 });
        var cms = new System.Security.Cryptography.Pkcs.SignedCms(content, detached: true);
        var signer = new System.Security.Cryptography.Pkcs.CmsSigner(
            System.Security.Cryptography.Pkcs.SubjectIdentifierType.IssuerAndSerialNumber,
            certificate)
        {
            IncludeOption = System.Security.Cryptography.X509Certificates.X509IncludeOption.EndCertOnly
        };
        cms.ComputeSignature(signer);
        return cms.Encode();
    }
#endif
}
