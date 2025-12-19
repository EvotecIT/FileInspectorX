using System.IO;
using System.Runtime.InteropServices;
using FileInspectorX;
using Xunit;

namespace FileInspectorX.Tests;

public class WinTrustHelperTests
{
    private const int VerificationIterations = 200; // stress repeated calls to cover caching/interop stability

    [Fact]
    public void VerifyFileSignature_UnsignedFile_NotTrusted_And_DoesNotThrow()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return;

        var temp = Path.GetTempFileName();
        try
        {
            // Write a small random file to ensure it's not signed
            File.WriteAllBytes(temp, new byte[] { 0x01, 0x02, 0x03, 0x04 });
            for (int i = 0; i < VerificationIterations; i++)
            {
                bool? trusted = FileInspector.VerifyAuthenticodePolicy(temp);
                // Unsigned files should not be trusted; API may return null (no signature) or false.
                Assert.False(trusted == true);
            }
        }
        finally
        {
            TestHelpers.SafeDelete(temp);
        }
    }
}

