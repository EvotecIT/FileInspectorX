#if FILEINSPECTORX_MAGIKA
using System;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace FileInspectorX.PowerShell
{
    /// <summary>
    /// Loads the ONNX native companion from the packaged runtime-specific directory before
    /// PowerShell's assembly loader can fall back to an unrelated machine-wide copy.
    /// </summary>
    internal static class MagikaNativeRuntimeLoader
    {
        private const int RtldNow = 2;
        private const int RtldGlobal = 0x100;
        private static readonly object LoadSync = new();
        private static bool _loaded;

        internal static void EnsureLoaded()
        {
            lock (LoadSync)
            {
                if (_loaded)
                    return;

                var assemblyDirectory = Path.GetDirectoryName(
                    typeof(MagikaNativeRuntimeLoader).GetTypeInfo().Assembly.Location);
                if (string.IsNullOrWhiteSpace(assemblyDirectory))
                    throw new InvalidOperationException("The PowerShell module assembly directory is unavailable.");

                var architecture = RuntimeInformation.ProcessArchitecture switch
                {
                    Architecture.X64 => "x64",
                    Architecture.Arm64 => "arm64",
                    _ => throw new PlatformNotSupportedException(
                        $"Magika is not packaged for {RuntimeInformation.ProcessArchitecture} processes.")
                };

                string runtime;
                string libraryName;
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    runtime = "win-" + architecture;
                    libraryName = "onnxruntime.dll";
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    runtime = "linux-" + architecture;
                    libraryName = "libonnxruntime.so";
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    runtime = "osx-" + architecture;
                    libraryName = "libonnxruntime.dylib";
                }
                else
                {
                    throw new PlatformNotSupportedException(
                        $"Magika is not packaged for {RuntimeInformation.OSDescription}.");
                }

                var nativePath = Path.Combine(
                    assemblyDirectory,
                    "runtimes",
                    runtime,
                    "native",
                    libraryName);
                if (!File.Exists(nativePath))
                    nativePath = Path.Combine(assemblyDirectory, libraryName);
                if (!File.Exists(nativePath))
                    throw new FileNotFoundException("The Magika ONNX native runtime is missing.", nativePath);

                Load(nativePath);
                _loaded = true;
            }
        }

        private static void Load(string path)
        {
            IntPtr handle;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                handle = LoadLibraryWindows(path);
                if (handle == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return;
            }

            handle = RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
                ? DlopenMac(path, RtldNow | RtldGlobal)
                : DlopenLinux(path, RtldNow | RtldGlobal);
            if (handle == IntPtr.Zero)
                throw new InvalidOperationException("The Magika ONNX native runtime could not be loaded.");
        }

        [DllImport("kernel32", EntryPoint = "LoadLibraryW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibraryWindows(string path);

        [DllImport("libdl.so.2", EntryPoint = "dlopen")]
        private static extern IntPtr DlopenLinux(string path, int flags);

        [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "dlopen")]
        private static extern IntPtr DlopenMac(string path, int flags);
    }
}
#endif
