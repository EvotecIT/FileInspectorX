#if NET8_0_OR_GREATER
using System.Formats.Asn1;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

/// <summary>Protects reports from network access triggered by an untrusted certificate's issuer URL.</summary>
public sealed class CertificateNetworkPolicyTests
{
    [Fact]
    public async Task ReportsKeepIssuerLookupOfflineForCertificatesPePackagesAndArchiveChildren()
    {
        await using var issuer = new IssuerEndpoint();
        using var issuerKey = RSA.Create(2048);
        var issuerRequest = new CertificateRequest("CN=Offline issuer " + Guid.NewGuid(), issuerKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        issuerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        issuerRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        using var issuerCertificate = issuerRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(2));
        using var signerKey = RSA.Create(2048);
        var signerRequest = new CertificateRequest("CN=Offline report signer", signerKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        signerRequest.CertificateExtensions.Add(IssuerAccess(issuer.Url));
        using var publicCertificate = signerRequest.Create(issuerCertificate, DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1), RandomNumberGenerator.GetBytes(16));
        using var signer = publicCertificate.CopyWithPrivateKey(signerKey);
        var cms = new SignedCms(new ContentInfo(Encoding.ASCII.GetBytes("synthetic signed content")));
        // Keep only the leaf in the envelope so its missing issuer would require AIA retrieval.
        cms.ComputeSignature(new CmsSigner(signer) { IncludeOption = X509IncludeOption.EndCertOnly });
        var signedData = cms.Encode();
        var pe = SignedPe(signedData);
        var p7x = Encoding.ASCII.GetBytes("PKCX").Concat(signedData).ToArray();
        var package = Zip(("AppxManifest.xml", Encoding.UTF8.GetBytes("<Package/>")), ("AppxSignature.p7x", p7x));

        InspectionReport Report(byte[] bytes, string name, bool deep = false)
        {
            // Reports enforce offline validation even when a supplied legacy options object permits downloads.
            var supplied = new FileInspector.DetectionOptions
            {
                IncludeAuthenticode = true, IncludeAssessment = false, IncludeReferences = false,
                Settings = InspectionSettings.CaptureDefaults() with { DeepContainerScanEnabled = deep }
            };
            using var input = new MemoryStream(bytes);
            var report = FileInspector.AnalyzeReport(input, name, new InspectionReportOptions { Detection = supplied });
            Assert.False(supplied.OfflineCertificateValidation);
            return report;
        }

        var certificateReport = Report(signer.RawData, "upload.cer");
        Assert.Equal(signer.Thumbprint, certificateReport.Analysis.Certificate!.Thumbprint);
        Assert.False(certificateReport.Analysis.Certificate.ChainTrusted);
        var executableReport = Report(pe, "upload.exe");
        Assert.True(executableReport.Analysis.Authenticode!.EnvelopeSignatureValid);
        Assert.False(executableReport.Analysis.Authenticode.ChainValid);
        var packageReport = Report(package, "upload.msix");
        Assert.True(packageReport.Analysis.Authenticode!.EnvelopeSignatureValid);
        Assert.False(packageReport.Analysis.Authenticode.ChainValid);
        var archiveReport = Report(Zip(("nested.exe", pe)), "upload.zip", deep: true);
        Assert.Equal(1, archiveReport.Analysis.InnerSignedExecutables);
        // Accept-loop health also drains the listener after synchronous chain checks have completed.
        Assert.Equal(0, issuer.Requests);
        await issuer.CheckHealthAsync();
        Assert.Equal(1, issuer.Requests);
    }

    [Fact]
    public async Task DefaultReportsUseOfflineCertificateValidation()
    {
        await using var issuer = new IssuerEndpoint();
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=Default offline report", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(IssuerAccess(issuer.Url));
        using var certificate = request.Create(new X500DistinguishedName("CN=Missing issuer " + Guid.NewGuid()),
            X509SignatureGenerator.CreateForRSA(key, RSASignaturePadding.Pkcs1), DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1), RandomNumberGenerator.GetBytes(16));
        using var input = new MemoryStream(certificate.RawData);
        var report = FileInspector.AnalyzeReport(input, "upload.cer");
        Assert.Equal(certificate.Thumbprint, report.Analysis.Certificate!.Thumbprint);
        Assert.False(report.Analysis.Certificate.ChainTrusted);
        Assert.Equal(0, issuer.Requests);
        await issuer.CheckHealthAsync();
        Assert.Equal(1, issuer.Requests);
    }

    private static X509Extension IssuerAccess(string url)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier("1.3.6.1.5.5.7.48.2");
            writer.WriteCharacterString(UniversalTagNumber.IA5String, url, new Asn1Tag(TagClass.ContextSpecific, 6));
        }
        return new X509Extension("1.3.6.1.5.5.7.1.1", writer.Encode(), critical: false);
    }

    private static byte[] SignedPe(byte[] signedData)
    {
        var bytes = TestHelpers.CreateMinimalPe();
        int certificateSize = (signedData.Length + 8 + 7) & ~7;
        Array.Resize(ref bytes, 512 + certificateSize);
        BitConverter.GetBytes(16u).CopyTo(bytes, 0xF4);
        BitConverter.GetBytes(512u).CopyTo(bytes, 0x118);
        BitConverter.GetBytes((uint)certificateSize).CopyTo(bytes, 0x11C);
        BitConverter.GetBytes((uint)(signedData.Length + 8)).CopyTo(bytes, 512);
        BitConverter.GetBytes((ushort)0x0200).CopyTo(bytes, 516);
        BitConverter.GetBytes((ushort)2).CopyTo(bytes, 518);
        signedData.CopyTo(bytes, 520);
        return bytes;
    }

    private static byte[] Zip(params (string Name, byte[] Bytes)[] entries)
    {
        using var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, true))
            foreach (var entry in entries)
            {
                using var content = archive.CreateEntry(entry.Name, CompressionLevel.NoCompression).Open();
                content.Write(entry.Bytes, 0, entry.Bytes.Length);
            }
        return output.ToArray();
    }

    // Returns a rejection rather than any certificate, avoiding persistent issuer-cache changes.
    private sealed class IssuerEndpoint : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _accept;
        private int _requests;
        internal int Requests => Volatile.Read(ref _requests);
        internal string Url { get; }

        internal IssuerEndpoint()
        {
            _listener.Start();
            Url = "http://127.0.0.1:" + ((IPEndPoint)_listener.LocalEndpoint).Port + "/issuer.cer";
            _accept = AcceptAsync();
        }

        private async Task AcceptAsync()
        {
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    using var client = await _listener.AcceptTcpClientAsync(_stop.Token);
                    Interlocked.Increment(ref _requests);
                    var response = Encoding.ASCII.GetBytes("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    await client.GetStream().WriteAsync(response, _stop.Token);
                }
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
            catch (SocketException) when (_stop.IsCancellationRequested) { }
        }

        internal async Task CheckHealthAsync()
        {
            using var client = new TcpClient();
            var endpoint = (IPEndPoint)_listener.LocalEndpoint;
            await client.ConnectAsync(endpoint.Address, endpoint.Port);
            var response = new byte[256];
            Assert.True(await client.GetStream().ReadAsync(response).AsTask().WaitAsync(TimeSpan.FromSeconds(5)) > 0);
        }

        public async ValueTask DisposeAsync()
        {
            _stop.Cancel(); _listener.Stop();
            await _accept;
            _stop.Dispose();
        }
    }
}
#endif
