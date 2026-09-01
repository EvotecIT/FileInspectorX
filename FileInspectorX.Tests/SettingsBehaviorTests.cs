using System.Collections.Generic;
using System.Diagnostics;
#if NET8_0_OR_GREATER
using System.Reflection;
using System.Runtime.Loader;
#endif
using System.Threading;
using FileInspectorX;

namespace FileInspectorX.Tests;

[Xunit.Collection(nameof(DetectionSettingsCollection))]
public class SettingsBehaviorTests
{
#if NET8_0_OR_GREATER
    [Xunit.Fact]
    public void Breadcrumbs_DoNotRequireProcessAssembly()
    {
        var logPath = Path.Combine(Path.GetTempPath(), $"FileInspectorX.Breadcrumbs.{Guid.NewGuid():N}.log");
        var loadContext = new ProcessRejectingLoadContext();
        try
        {
            var assembly = loadContext.LoadFromAssemblyPath(typeof(FileInspector).Assembly.Location);
            var settings = assembly.GetType("FileInspectorX.Settings", throwOnError: true)!;
            settings.GetProperty("BreadcrumbsEnabled")!.SetValue(null, true);
            settings.GetProperty("BreadcrumbsPath")!.SetValue(null, logPath);
            var breadcrumbs = assembly.GetType("FileInspectorX.Breadcrumbs", throwOnError: true)!;
            var write = breadcrumbs.GetMethod("Write", BindingFlags.Static | BindingFlags.NonPublic)!;

            write.Invoke(null, new object?[] { "ISOLATED_TEST", null, null });

            Xunit.Assert.Contains($"PID={Environment.ProcessId}", File.ReadAllText(logPath), StringComparison.Ordinal);
        }
        finally
        {
            loadContext.Unload();
            File.Delete(logPath);
        }
    }
#endif

    [Xunit.Fact]
    public void JsonValidationCore_TimesOut_When_StopwatchExpired()
    {
        var sw = Stopwatch.StartNew();
        var spinner = new SpinWait();
        while (sw.ElapsedTicks <= 1) spinner.SpinOnce();

        var ok = JsonStructureValidator.TryValidateCoreForTest("{\"a\":1}", sw, 1L, out var timedOut);
        Xunit.Assert.False(ok);
        Xunit.Assert.True(timedOut);
    }

    [Xunit.Fact]
    public void JsonValidationCore_Rejects_Invalid_Object_Syntax()
    {
        var ok = JsonStructureValidator.TryValidateCoreForTest("{\"a\":,}", null, 0L, out var timedOut);
        Xunit.Assert.False(ok);
        Xunit.Assert.False(timedOut);
    }

    [Xunit.Theory]
    [Xunit.InlineData("{\"a\":01}")]
    [Xunit.InlineData("{\"a\":\"bad\\xescape\"}")]
    [Xunit.InlineData("{\"a\":1} trailing")]
    public void JsonValidationCore_Rejects_Strict_Invalid_Syntax_Cases(string json)
    {
        var ok = JsonStructureValidator.TryValidateCoreForTest(json, null, 0L, out var timedOut);
        Xunit.Assert.False(ok);
        Xunit.Assert.False(timedOut);
    }

    [Xunit.Fact]
    public void JsonValidationCore_Accepts_Exponent_And_Escaped_Unicode()
    {
        var ok = JsonStructureValidator.TryValidateCoreForTest(
            "{\"value\":-1.25e+2,\"label\":\"hi \\u263A\"}",
            null,
            0L,
            out var timedOut);
        Xunit.Assert.True(ok);
        Xunit.Assert.False(timedOut);
    }

    [Xunit.Fact]
    public void JsonValidationCore_Rejects_Nesting_Beyond_Configured_Maximum()
    {
        var previous = Settings.JsonStructuralValidationMaxDepth;
        try
        {
            Settings.JsonStructuralValidationMaxDepth = 4;
            var allowed = JsonStructureValidator.TryValidateCoreForTest("[[[[]]]]", null, 0L, out var allowedTimedOut);
            var rejected = JsonStructureValidator.TryValidateCoreForTest("[[[[[]]]]]", null, 0L, out var rejectedTimedOut);

            Xunit.Assert.True(allowed);
            Xunit.Assert.False(allowedTimedOut);
            Xunit.Assert.False(rejected);
            Xunit.Assert.False(rejectedTimedOut);
        }
        finally
        {
            Settings.JsonStructuralValidationMaxDepth = previous;
        }
    }

    [Xunit.Fact]
    public void DangerousExtensionsOverrideMode_Merge_Keeps_Defaults()
    {
        var prevOverride = Settings.DangerousExtensionsOverride;
        var prevMode = Settings.DangerousExtensionsOverrideMode;
        try
        {
            Settings.DangerousExtensionsOverride = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "ps1" };
            Settings.DangerousExtensionsOverrideMode = DangerousExtensionsOverrideMode.Replace;
            Xunit.Assert.False(DangerousExtensions.IsDangerous("exe"));
            Xunit.Assert.True(DangerousExtensions.IsDangerous("ps1"));

            Settings.DangerousExtensionsOverrideMode = DangerousExtensionsOverrideMode.Merge;
            Xunit.Assert.True(DangerousExtensions.IsDangerous("exe"));
            Xunit.Assert.True(DangerousExtensions.IsDangerous("ps1"));
        }
        finally
        {
            Settings.DangerousExtensionsOverride = prevOverride;
            Settings.DangerousExtensionsOverrideMode = prevMode;
        }
    }

#if NET8_0_OR_GREATER
    private sealed class ProcessRejectingLoadContext() : AssemblyLoadContext(isCollectible: true)
    {
        protected override Assembly? Load(AssemblyName assemblyName)
        {
            if (string.Equals(assemblyName.Name, "System.Diagnostics.Process", StringComparison.Ordinal))
                throw new FileNotFoundException("Process assembly is unavailable in the isolated test context.", assemblyName.Name);

            return null;
        }
    }
#endif
}
