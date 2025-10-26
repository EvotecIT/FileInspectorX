// ReSharper disable CheckNamespace
#if NET472
using System.IO;

namespace FileInspectorX.Tests.Compat
{
    /// <summary>
    /// Polyfills to smooth differences on .NET Framework when tests use newer APIs.
    /// Compiled only for NET472 target.
    /// </summary>
    public static class Net472StreamPolyfills
    {
        public static void Write(this Stream stream, byte[] buffer)
        {
            stream.Write(buffer, 0, buffer?.Length ?? 0);
        }

        public static void Write(this FileStream stream, byte[] buffer)
        {
            stream.Write(buffer, 0, buffer?.Length ?? 0);
        }
    }
}
#endif

