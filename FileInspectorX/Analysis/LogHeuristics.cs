namespace FileInspectorX;

/// <summary>
/// Shared log-format heuristics used by both detection and analysis paths.
/// Expects lowercase input for string-based checks.
/// </summary>
internal static class LogHeuristics
{
    internal static bool LooksLikeDefenderTextLog(string lower, bool logCues)
    {
        bool hasMpcmd = lower.Contains("mpcmdrun");
        bool hasDefenderName = lower.Contains("windows defender") || lower.Contains("microsoft defender");
        bool hasProvider = lower.Contains("microsoft-windows-windows defender");
        bool hasAntivirus = lower.Contains("antivirus");
        bool hasAntimalware = lower.Contains("antimalware");
        bool hasThreat = lower.Contains("threat");
        bool hasRemediation = lower.Contains("remediation") || lower.Contains("quarantine");
        bool hasSecurityIntel = lower.Contains("security intelligence") || lower.Contains("signature version") || lower.Contains("engine version") || lower.Contains("platform version");
        bool eventExport = (lower.Contains("log name:") && lower.Contains("event id:")) ||
                           (lower.Contains("source:") && lower.Contains("task category:") && lower.Contains("level:"));
        int cues = 0;
        if (hasMpcmd) cues += 2;
        if (hasProvider) cues += 2;
        if (hasDefenderName) cues++;
        if (hasAntivirus) cues++;
        if (hasAntimalware) cues++;
        if (hasThreat) cues++;
        if (hasRemediation) cues++;
        if (hasSecurityIntel) cues++;
        if (eventExport && (hasProvider || hasDefenderName)) cues += 2;

        bool strongMarker = hasProvider || hasAntivirus || hasAntimalware || hasSecurityIntel || eventExport;
        if (!strongMarker) return false;
        if (!logCues && !eventExport && !hasMpcmd && !hasProvider) return false;
        if (hasMpcmd) return cues >= 4;
        return cues >= 3;
    }

    internal static bool LooksLikeDnsLog(string lower)
    {
        if (!lower.Contains("dns server log")) return false;
        return lower.Contains("log file created at") || lower.Contains("packet");
    }

    internal static bool LooksLikeFirewallLog(string lower)
    {
        bool hasSoftware = lower.Contains("#software: microsoft windows firewall") || lower.Contains("#software: windows firewall") || lower.Contains("microsoft windows firewall");
        if (!hasSoftware) return false;
        if (!lower.Contains("#fields:")) return false;
        return lower.Contains("date") && lower.Contains("time");
    }

    internal static bool LooksLikeNetlogonLog(string lower, bool logCues)
    {
        int netCount = CountOccurrences(lower, "netlogon", maxCount: 2);
        bool hasNetr = lower.Contains("netrlogon");
        bool hasSecure = lower.Contains("secure channel");
        bool hasSam = lower.Contains("sam logon");
        int cues = 0;
        if (logCues) cues++;
        if (netCount > 0) cues++;
        if (netCount >= 2) cues++;
        if (hasNetr) cues += 2;
        if (hasSecure) cues++;
        if (hasSam) cues++;
        return cues >= 3 || (cues >= 2 && (hasNetr || hasSecure || hasSam));
    }

    internal static bool LooksLikeEventViewerTextExport(string lower)
    {
        int labels = 0;
        if (lower.Contains("log name:")) labels++;
        if (lower.Contains("source:")) labels++;
        if (lower.Contains("event id:")) labels++;
        if (lower.Contains("task category:")) labels++;
        if (lower.Contains("level:")) labels++;
        if (lower.Contains("keywords:")) labels++;
        if (lower.Contains("user:")) labels++;
        if (lower.Contains("computer:")) labels++;
        if (lower.Contains("description:")) labels++;
        if (lower.Contains("date:")) labels++;
        return labels >= 3 && (lower.Contains("event id:") || lower.Contains("log name:"));
    }

    internal static bool LooksLikeDhcpLog(string lower)
    {
        if (!lower.Contains("#software: microsoft dhcp server")) return false;
        if (!lower.Contains("#fields:")) return false;
        return lower.Contains("#version:") || lower.Contains("#date:");
    }

    internal static bool LooksLikeExchangeMessageTrackingLog(string lower)
    {
        bool hasSoftware = lower.Contains("#software: microsoft exchange");
        bool hasLogType = lower.Contains("#log-type: message tracking log") || lower.Contains("message tracking log file");
        bool hasFields = lower.Contains("#fields:");
        if (!hasLogType || !hasFields) return false;
        return hasSoftware || lower.Contains("#version:");
    }

    internal static bool LooksLikeSqlErrorLog(string lower, bool logCues)
    {
        bool hasSql = lower.Contains("sql server");
        bool hasStarting = lower.Contains("sql server is starting");
        bool hasErrorlog = lower.Contains("errorlog");
        bool hasSpid = lower.Contains("spid");
        bool hasProcId = lower.Contains("server process id");
        int cues = 0;
        if (logCues) cues++;
        if (hasSql) cues++;
        if (hasStarting) cues++;
        if (hasErrorlog) cues++;
        if (hasSpid) cues++;
        if (hasProcId) cues++;
        if (!hasSql && !hasStarting) return false;
        if (!(hasSpid || hasProcId)) return false;
        return cues >= 2;
    }

    internal static bool LooksLikeNpsRadiusLog(string lower)
    {
        bool hasSoftware = lower.Contains("#software: microsoft internet authentication service") || lower.Contains("#software: microsoft network policy server");
        if (!hasSoftware) return false;
        if (!lower.Contains("#fields:")) return false;
        return lower.Contains("#version:") || lower.Contains("#date:");
    }

    internal static bool LooksLikeSqlAgentLog(string lower, bool logCues)
    {
        bool hasAgent = lower.Contains("sqlserveragent") || lower.Contains("sql server agent");
        if (!hasAgent) return false;
        int cues = 0;
        if (lower.Contains("sqlserveragent")) cues++;
        if (lower.Contains("startup") || lower.Contains("started") || lower.Contains("starting")) cues++;
        if (lower.Contains("version")) cues++;
        if (lower.Contains("job")) cues++;
        if (lower.Contains("service")) cues++;
        if (logCues) cues++;
        return cues >= 2;
    }

    private static int CountOccurrences(string hay, string needle, int maxCount)
    {
        int count = 0;
        int idx = 0;
        while (idx < hay.Length && count < maxCount)
        {
            idx = hay.IndexOf(needle, idx, StringComparison.Ordinal);
            if (idx < 0) break;
            count++;
            idx += needle.Length;
        }
        return count;
    }
}
