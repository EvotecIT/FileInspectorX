using Xunit;
using FI = FileInspectorX.FileInspector;

namespace FileInspectorX.Tests;

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
    public void Detect_Pkcs12_By_Oid_Prefix()
    {
        var p = Path.GetTempFileName();
        try
        {
            // ASN.1 SEQUENCE (0x30), long-form length 0x82 0x01 0x00 (~256)
            // Embed OID 1.2.840.113549.1.12.10.1.* as bytes
            var pfxOid = new byte[] { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01 };
            var buf = new byte[64];
            buf[0] = 0x30; buf[1] = 0x82; buf[2] = 0x01; buf[3] = 0x00;
            Array.Copy(pfxOid, 0, buf, 16, pfxOid.Length);
            File.WriteAllBytes(p, buf);
            var res = FI.Detect(p);
            Assert.NotNull(res);
            Assert.Equal("p12", res!.Extension);
            Assert.Equal("application/x-pkcs12", res.MimeType);
        }
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Detect_Der_X509_Heuristic()
    {
        var p = Path.GetTempFileName();
        try
        {
            // ASN.1 SEQUENCE (0x30), short length sufficient
            // Include RSA OID prefix bytes within first 128 bytes
            var rsa = new byte[] { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01 };
            var buf = new byte[64];
            buf[0] = 0x30; buf[1] = 0x30; // seq len
            Array.Copy(rsa, 0, buf, 10, rsa.Length);
            File.WriteAllBytes(p, buf);
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
}
