using System.Runtime.InteropServices;
using Xunit;

namespace FileInspectorX.Tests;

public class MsiInstallerMetadataTests
{
    [Theory]
    [InlineData("Intel;1033")]
    [InlineData("x64;1033")]
    [InlineData("Arm64;1033")]
    public void Analyze_ReadsInstallerPropertiesWithoutChangingPackage(string template)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".msi");
        try
        {
            CreatePackage(path, template);
            var original = File.ReadAllBytes(path);
            var options = new FileInspector.DetectionOptions
            {
                IncludeInstaller = true,
                IncludeAuthenticode = false,
                IncludePermissions = false,
                Settings = InspectionSettings.CaptureDefaults() with
                {
                    EnableMsiSummaryInfo = true,
                    EnableMsiCustomActions = true
                }
            };

            var analysis = FileInspector.Analyze(path, options);
            Assert.Equal("msi", analysis.Detection?.Extension);
            Assert.NotNull(analysis.Installer);
            Assert.Equal(InstallerKind.Msi, analysis.Installer!.Kind);
            Assert.Equal("Metadata Test " + template, analysis.Installer.Name);
            Assert.Equal("Contoso Caf\u00e9", analysis.Installer.Manufacturer);
            Assert.Equal("7.6.4", analysis.Installer.Version);
            Assert.Equal("{2D024F6B-4041-460E-BB13-92B340D69A17}", analysis.Installer.ProductCode);
            Assert.Equal("{9265C29A-DF40-449E-A01C-B792D6BBC8CC}", analysis.Installer.UpgradeCode);
            Assert.Equal("PerMachine", analysis.Installer.Scope);
            Assert.Equal("https://example.com/support", analysis.Installer.HelpLink);
            Assert.Equal("Metadata Author", analysis.Installer.Author);
            Assert.Equal("{ACBB58A4-8510-4E5D-A259-D754ADFD80DC}", analysis.Installer.PackageCode);
            Assert.Equal(1, analysis.Installer.MsiCustomActions?.CountExe);
            Assert.Equal(1, analysis.Installer.MsiCustomActions?.CountDll);
            Assert.Equal(original, File.ReadAllBytes(path));

            options.IncludeInstaller = false;
            Assert.Null(FileInspector.Inspect(path, options).Installer);
        }
        finally { File.Delete(path); }
    }

    // Create an actual Windows Installer database; nothing is installed or registered.
    private static void CreatePackage(string path, string template)
    {
        Check(MsiOpenDatabaseW(path, new IntPtr(3), out var database)); // MSIDBOPEN_CREATE
        try
        {
            Execute(database, "CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) LOCALIZABLE PRIMARY KEY `Property`)");
            var values = new Dictionary<string, string>
            {
                ["ProductName"] = "Metadata Test " + template,
                ["Manufacturer"] = "Contoso Caf\u00e9",
                ["ProductVersion"] = "7.6.4",
                ["ProductCode"] = "{2D024F6B-4041-460E-BB13-92B340D69A17}",
                ["UpgradeCode"] = "{9265C29A-DF40-449E-A01C-B792D6BBC8CC}",
                ["ALLUSERS"] = "1",
                ["ARPHELPLINK"] = "https://example.com/support"
            };
            foreach (var pair in values)
                Execute(database, $"INSERT INTO `Property` (`Property`, `Value`) VALUES ('{pair.Key}', '{pair.Value}')");

            Execute(database, "CREATE TABLE `CustomAction` (`Action` CHAR(72) NOT NULL, `Type` SHORT NOT NULL, `Source` CHAR(72), `Target` CHAR(255) PRIMARY KEY `Action`)");
            Execute(database, "INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('ExampleExe', 2, 'Example', 'Argument')");
            Execute(database, "INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('ExampleDll', 1, 'Example', 'EntryPoint')");
            Check(MsiGetSummaryInformationW(database, null, 3, out var summary));
            try
            {
                // VT_LPSTR summary template supplies the package target architecture.
                Check(MsiSummaryInfoSetPropertyW(summary, 7, 30, 0, IntPtr.Zero, template));
                Check(MsiSummaryInfoSetPropertyW(summary, 4, 30, 0, IntPtr.Zero, "Metadata Author"));
                Check(MsiSummaryInfoSetPropertyW(summary, 9, 30, 0, IntPtr.Zero, "{ACBB58A4-8510-4E5D-A259-D754ADFD80DC}"));
                Check(MsiSummaryInfoPersist(summary));
            }
            finally { Check(MsiCloseHandle(summary)); }
            Check(MsiDatabaseCommit(database));
        }
        finally { Check(MsiCloseHandle(database)); }
    }

    private static void Execute(uint database, string query)
    {
        Check(MsiDatabaseOpenViewW(database, query, out var view));
        try { Check(MsiViewExecute(view, 0)); }
        finally { Check(MsiCloseHandle(view)); }
    }

    private static void Check(uint result) => Assert.Equal(0u, result);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint MsiOpenDatabaseW(string path, IntPtr persist, out uint database);
    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint MsiDatabaseOpenViewW(uint database, string query, out uint view);
    [DllImport("msi.dll", ExactSpelling = true)]
    private static extern uint MsiViewExecute(uint view, uint record);
    [DllImport("msi.dll", ExactSpelling = true)]
    private static extern uint MsiDatabaseCommit(uint database);
    [DllImport("msi.dll", ExactSpelling = true)]
    private static extern uint MsiCloseHandle(uint handle);
    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint MsiGetSummaryInformationW(uint database, string? path, uint count, out uint summary);
    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint MsiSummaryInfoSetPropertyW(uint summary, uint property, uint type, int value, IntPtr fileTime, string text);
    [DllImport("msi.dll", ExactSpelling = true)]
    private static extern uint MsiSummaryInfoPersist(uint summary);
}
