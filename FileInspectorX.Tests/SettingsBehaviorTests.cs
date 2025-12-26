using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using FileInspectorX;

namespace FileInspectorX.Tests;

public class SettingsBehaviorTests
{
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
}
