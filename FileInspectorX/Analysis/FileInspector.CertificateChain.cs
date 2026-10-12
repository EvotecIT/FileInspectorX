using System.Security.Cryptography.X509Certificates;

namespace FileInspectorX;

public static partial class FileInspector
{
    /// <summary>Uses one network policy for certificate, PE and package signer chain checks.</summary>
    private static bool? TryBuildCertificateChain(X509Certificate2 certificate, DetectionOptions? options,
        FileAnalysis analysis, out string? rootSubject)
    {
        rootSubject = null;
        bool offline = options?.OfflineCertificateValidation == true;
#if !NET5_0_OR_GREATER
        // These target contracts have no supported AIA download-control API. Do not silently
        // perform an online chain build for a caller that explicitly requested offline analysis.
        if (offline)
        {
            analysis.AnalysisComplete = false;
            analysis.AnalysisIssues = MergeAnalysisIssues(analysis.AnalysisIssues,
                new[] { "cert:offline-chain-validation-unavailable" });
            return null;
        }
#endif
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
#if NET5_0_OR_GREATER
            chain.ChainPolicy.DisableCertificateDownloads = offline;
#endif
            bool trusted = chain.Build(certificate);
            if (trusted && chain.ChainElements.Count > 0)
                rootSubject = chain.ChainElements[chain.ChainElements.Count - 1].Certificate.Subject;
            return trusted;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not OperationCanceledException)
        { return null; }
    }
}
