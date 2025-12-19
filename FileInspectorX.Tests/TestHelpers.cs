using System;
using System.IO;

namespace FileInspectorX.Tests;

internal static class TestHelpers
{
    internal static void SafeDelete(string path)
    {
        try
        {
            if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
                File.Delete(path);
        }
        catch { }
    }
}
