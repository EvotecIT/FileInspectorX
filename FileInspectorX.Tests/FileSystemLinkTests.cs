using System.Diagnostics;
using System.Runtime.InteropServices;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class FileSystemLinkTests
{
    [Theory]
    [InlineData(0xA000000Cu, true)] // Symbolic link.
    [InlineData(0xA0000003u, true)] // Junction/mount point.
    [InlineData(0x9000001Au, false)] // Cloud placeholder.
    [InlineData(0x9000101Au, false)] // Cloud placeholder family member.
    [InlineData(0x80000021u, false)] // OneDrive.
    [InlineData(0x80000017u, false)] // Windows Overlay Filter.
    public void StorageReparseTagsRemainDistinctFromLinks(uint tag, bool isLink)
        => Assert.Equal(isLink, FileSystemLinks.IsNameSurrogate(tag));

    [Fact]
    public void RecursiveScanSkipsWindowsJunctionCycles()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        var directory = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "FileInspectorX-" + Guid.NewGuid().ToString("N")));
        string junction = Path.Combine(directory.FullName, "again");
        try
        {
            File.WriteAllText(Path.Combine(directory.FullName, "one.txt"), "hello");
            var start = new ProcessStartInfo("cmd.exe", "/c mklink /J \"" + junction + "\" \"" + directory.FullName + "\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            using var process = Process.Start(start)!;
            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();
            Assert.True(process.WaitForExit(10000), "Junction creation did not complete.");
            Assert.True(process.ExitCode == 0, output + error);
            Assert.True(FileSystemLinks.IsLink(junction, File.GetAttributes(junction)));
            Assert.Single(FileInspector.AnalyzeDirectory(directory.FullName, SearchOption.AllDirectories).Take(10));
        }
        finally
        {
            if (Directory.Exists(junction)) Directory.Delete(junction);
            directory.Delete(true);
        }
    }
}
