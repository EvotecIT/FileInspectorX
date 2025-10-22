namespace FileInspectorX;

public static partial class FileInspector
{
    /// <summary>
    /// Verifies Windows Authenticode policy (WinVerifyTrust) for a given file path.
    /// Returns true when trusted, false when explicitly not trusted, and null when not applicable
    /// (e.g. no signature present or platform does not support WinVerifyTrust).
    /// </summary>
    public static bool? VerifyAuthenticodePolicy(string path)
    {
        try
        {
            var a = Analyze(path);
            // If WinTrust integration is available and ran, prefer it
            if (a?.Authenticode != null)
            {
                if (a.Authenticode.IsTrustedWindowsPolicy.HasValue)
                    return a.Authenticode.IsTrustedWindowsPolicy.Value;
                // If no explicit WinTrust result but signature present, fall back to chain validity
                if (a.Authenticode.Present)
                    return a.Authenticode.ChainValid == true;
            }
            // No signature or not applicable
            return null;
        }
        catch
        {
            return null;
        }
    }
}
