using System;
using System.IO;

namespace FileInspectorX.Tests;

internal static class TestHelpers
{
    internal static string GetFixturePath(params string[] relativeParts)
    {
        if (relativeParts == null || relativeParts.Length == 0)
            throw new ArgumentException("At least one fixture path part is required.", nameof(relativeParts));

        var parts = new string[relativeParts.Length + 2];
        parts[0] = AppContext.BaseDirectory;
        parts[1] = "Fixtures";
        Array.Copy(relativeParts, 0, parts, 2, relativeParts.Length);
        var path = Path.Combine(parts);
        if (!File.Exists(path))
            throw new FileNotFoundException("Fixture file was not copied to the test output directory.", path);
        return path;
    }

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
