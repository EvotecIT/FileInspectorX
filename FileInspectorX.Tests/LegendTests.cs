using System;
using System.Collections.Generic;
using Xunit;

namespace FileInspectorX.Tests;

public class LegendTests
{
    [Fact]
    public void HumanizeFlagsCsv_ShortAndLong_Work()
    {
        var csv = "Macros,ZipEnc,DotNet";
        var shortText = FileInspectorX.Legend.HumanizeFlagsCsv(csv, FileInspectorX.HumanizeStyle.Short);
        var longText  = FileInspectorX.Legend.HumanizeFlagsCsv(csv, FileInspectorX.HumanizeStyle.Long);
        Assert.Contains("Contains Macros", shortText);
        Assert.Contains("Archive Encrypted Entries", shortText);
        Assert.Contains(".NET Assembly", shortText);
        Assert.Contains("OOXML document contains vbaProject.bin", longText);
        Assert.Contains("Archive contains password-protected items", longText);
    }

    [Fact]
    public void HumanizeFindings_ExpandsToolAndCodes()
    {
        var list = new List<string> { "tool:PingCastle", "toolhash:ABC123", "ps:iex" };
        var shortText = FileInspectorX.Legend.HumanizeFindings(list, FileInspectorX.HumanizeStyle.Short);
        var longText  = FileInspectorX.Legend.HumanizeFindings(list, FileInspectorX.HumanizeStyle.Long);
        Assert.Contains("Tool: PingCastle", shortText);
        Assert.Contains("Tool (hash): ABC123", shortText);
        Assert.Contains("PowerShell IEX", shortText);
        Assert.Contains("Known tool detected by name: PingCastle", longText);
        Assert.Contains("Known tool matched by hash: ABC123", longText);
        Assert.Contains("Invoke-Expression", longText);
    }

    [Fact]
    public void GetLegends_ReturnEntries()
    {
        var flags = FileInspectorX.Legend.GetAnalysisFlagLegend();
        var heur  = FileInspectorX.Legend.GetHeuristicsLegend();
        Assert.NotEmpty(flags);
        Assert.Contains(flags, f => f.Code.Equals("Macros", StringComparison.OrdinalIgnoreCase));
        Assert.NotEmpty(heur);
        Assert.Contains(heur, h => h.Code.Equals("ps:encoded", StringComparison.OrdinalIgnoreCase));
    }
}

