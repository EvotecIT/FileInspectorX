using Xunit;
using FI = FileInspectorX.FileInspector;

namespace FileInspectorX.Tests;

public class TextLogDetectionsTests
{
    [Fact]
    public void Detect_Dns_Server_Log()
    {
        var p = Path.GetTempFileName();
        try
        {
            var text = "DNS Server Log File\nLog file created at: 2025-10-24\n\n";
            File.WriteAllText(p, text);
            var r = FI.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("log", r!.Extension);
            Assert.Equal("text:log-dns", r.Reason);
            var rv = FileInspectorX.ReportView.From(FI.Analyze(p));
            Assert.Equal("Windows DNS Server log", FileInspectorX.FriendlyNames.GetTypeLabel(r, FI.Analyze(p)) ?? string.Empty);
        }
        finally { TestHelpers.SafeDelete(p); }
    }

    [Fact]
    public void Detect_Windows_Firewall_Log()
    {
        var p = Path.GetTempFileName();
        try
        {
            var text = "#Software: Microsoft Windows Firewall\n#Version: 1.5\n#Fields: date time action protocol src-ip dst-ip\n";
            File.WriteAllText(p, text);
            var r = FI.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("log", r!.Extension);
            Assert.Equal("text:log-firewall", r.Reason);
        }
        finally { TestHelpers.SafeDelete(p); }
    }

    [Fact]
    public void Detect_Netlogon_Log()
    {
        var p = Path.GetTempFileName();
        try
        {
            var text = "Netlogon service started\nSecure channel to domain established by Netlogon\n";
            File.WriteAllText(p, text);
            var r = FI.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("log", r!.Extension);
            Assert.Equal("text:log-netlogon", r.Reason);
        }
        finally { TestHelpers.SafeDelete(p); }
    }

    [Fact]
    public void Detect_Event_Viewer_Text_Export()
    {
        var p = Path.GetTempFileName();
        try
        {
            var text = "Log Name: System\nSource: Service Control Manager\nEvent ID: 7036\nTask Category: None\nLevel: Information\n";
            File.WriteAllText(p, text);
            var r = FI.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("log", r!.Extension);
            Assert.Equal("text:event-txt", r.Reason);
        }
        finally { TestHelpers.SafeDelete(p); }
    }

    [Fact]
    public void Detect_Dhcp_Audit_Log()
    {
        var p = Path.GetTempFileName();
        try
        {
            var text = "#Software: Microsoft DHCP Server\n#Version: 5.2\n#Fields: Date, Time, ID, Description\n";
            File.WriteAllText(p, text);
            var r = FI.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("log", r!.Extension);
            Assert.Equal("text:log-dhcp", r.Reason);
        }
        finally { TestHelpers.SafeDelete(p); }
    }

    [Fact]
    public void Detect_Exchange_Message_Tracking_Log()
    {
        var p = Path.GetTempFileName();
        try
        {
            var text = "#Software: Microsoft Exchange Server\n#Version: 15.2\n#Log-type: Message Tracking Log\n#Fields: date-time,client-ip,server-hostname\n";
            File.WriteAllText(p, text);
            var r = FI.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("log", r!.Extension);
            Assert.Equal("text:log-exchange", r.Reason);
        }
        finally { TestHelpers.SafeDelete(p); }
    }

    [Fact]
    public void Detect_SQL_Server_ErrorLog()
    {
        var p = Path.GetTempFileName();
        try
        {
            var text = "SQL Server is starting at...\nServer process ID is 1234\nspid5s     Recovery is writing...\n";
            File.WriteAllText(p, text);
            var r = FI.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("log", r!.Extension);
            Assert.Equal("text:log-sql-errorlog", r.Reason);
        }
        finally { TestHelpers.SafeDelete(p); }
    }

    [Fact]
    public void Detect_Windows_Defender_Text_Log()
    {
        var p = Path.GetTempFileName();
        try
        {
            var text = "Microsoft Defender Antivirus Command Line Utility (MpCmdRun.exe)\nScan Started\n";
            File.WriteAllText(p, text);
            var r = FI.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("log", r!.Extension);
            Assert.Equal("text:log-defender", r.Reason);
        }
        finally { TestHelpers.SafeDelete(p); }
    }

    [Theory]
    [InlineData("mpcmdrun.exe started", false)]
    [InlineData("MpCmdRun.exe\nMicrosoft Defender Antivirus\nThreat detected", true)]
    public void Detect_Defender_Cue_Thresholds(string content, bool expected)
    {
        var p = Path.GetTempFileName();
        try
        {
            File.WriteAllText(p, content);
            var r = FI.Detect(p);
            if (expected)
            {
                Assert.NotNull(r);
                Assert.Equal("text:log-defender", r!.Reason);
            }
            else
            {
                Assert.True(r == null || r.Reason != "text:log-defender");
            }
        }
        finally { TestHelpers.SafeDelete(p); }
    }

    [Theory]
    [InlineData("INFO Antivirus\nThreat detected", false)]
    [InlineData("INFO Antivirus\nThreat detected\nWindows Defender", true)]
    public void Detect_Defender_Cue_Boundary_ProviderOnly(string content, bool expected)
    {
        var p = Path.GetTempFileName();
        try
        {
            File.WriteAllText(p, content);
            var r = FI.Detect(p);
            if (expected)
            {
                Assert.NotNull(r);
                Assert.Equal("text:log-defender", r!.Reason);
            }
            else
            {
                Assert.True(r == null || r.Reason != "text:log-defender");
            }
        }
        finally { TestHelpers.SafeDelete(p); }
    }

    [Fact]
    public void Detect_Defender_Mention_Does_Not_Force_Defender_Log()
    {
        var p = Path.GetTempFileName();
        try
        {
            var text = "Windows Defender service started\nGeneral info only\n";
            File.WriteAllText(p, text);
            var r = FI.Detect(p);
            Assert.True(r == null || r.Reason != "text:log-defender");
        }
        finally { TestHelpers.SafeDelete(p); }
    }

    [Fact]
    public void Detect_Defender_MpCmdRun_Mention_Does_Not_Force_Defender_Log()
    {
        var p = Path.GetTempFileName();
        try
        {
            var text = "MpCmdRun.exe located at C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\n" +
                       "Windows Defender scanning enabled\n" +
                       "Threats found: 0\n";
            File.WriteAllText(p, text);
            var r = FI.Detect(p);
            Assert.True(r == null || r.Reason != "text:log-defender");
        }
        finally { TestHelpers.SafeDelete(p); }
    }

    [Fact]
    public void Detect_Nps_Radius_Log()
    {
        var p = Path.GetTempFileName();
        try
        {
            var text = "#Software: Microsoft Internet Authentication Service\n#Version: 1.0\n#Fields: date time computername service requestid\n";
            File.WriteAllText(p, text);
            var r = FI.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("log", r!.Extension);
            Assert.Equal("text:log-nps", r.Reason);
        }
        finally { TestHelpers.SafeDelete(p); }
    }

    [Fact]
    public void Detect_SQL_Server_Agent_Log()
    {
        var p = Path.GetTempFileName();
        try
        {
            var text = "Microsoft (R) SQLServerAgent version\nSQLServerAgent startup complete\n";
            File.WriteAllText(p, text);
            var r = FI.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("log", r!.Extension);
            Assert.Equal("text:log-sqlagent", r.Reason);
        }
        finally { TestHelpers.SafeDelete(p); }
    }

    [Fact]
    public void Detect_Bracketed_Info_Log()
    {
        var p = Path.GetTempFileName();
        try
        {
            var text = "[Info  - 6:53:20 PM] OmniSharp.Extensions.JsonRpc.InputHandler: Starting\n" +
                       "[Info  - 6:53:20 PM] OmniSharp.Extensions.LanguageServer.Shared.LspRequestRouter: Finished\n";
            File.WriteAllText(p, text);
            var r = FI.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("log", r!.Extension);
        }
        finally { TestHelpers.SafeDelete(p); }
    }

    [Fact]
    public void Detect_Syslog_Text_Log()
    {
        var p = Path.GetTempFileName();
        try
        {
            var text = "Mar 13 10:15:22 host01 sshd[1234]: Failed password for invalid user admin from 10.0.0.5 port 22 ssh2\n" +
                       "Mar 13 10:15:24 host01 sshd[1234]: Connection closed by invalid user admin 10.0.0.5 port 22 [preauth]\n";
            File.WriteAllText(p, text);
            var r = FI.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("log", r!.Extension);
            Assert.Equal("text:log-syslog", r.Reason);
        }
        finally { TestHelpers.SafeDelete(p); }
    }

    [Fact]
    public void Detect_PowerShell_Transcript_Log()
    {
        var p = Path.GetTempFileName();
        try
        {
            var text = "**********************\n" +
                       "Windows PowerShell transcript start\n" +
                       "Start time: 20260313101522\n" +
                       "Username: CONTOSO\\operator\n" +
                       "Machine: HOST01 (Microsoft Windows NT 10.0.19045.0)\n" +
                       "**********************\n";
            File.WriteAllText(p, text);
            var r = FI.Detect(p);
            Assert.NotNull(r);
            Assert.Equal("log", r!.Extension);
            Assert.Equal("text:log-powershell-transcript", r.Reason);
        }
        finally { TestHelpers.SafeDelete(p); }
    }

    [Fact]
    public void Detect_Timestamped_Service_Log_With_Embedded_Levels_Uses_Medium_Log_Confidence()
    {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".log");
        try
        {
            var text =
                "2026-03-17T18:00:00 INFO Startup complete for worker C:\\TierBridge\\agent\\worker.exe\r\n" +
                "2026-03-17T18:00:01 WARN Fetching https://contoso.example/bootstrap.json\r\n" +
                "2026-03-17T18:00:02 WARN Fetching https://cdn.contoso.example/app.js for worker update\r\n" +
                "2026-03-17T18:00:03 ERROR Retry scheduled for \\\\fileserver\\drop\\package.zip\r\n" +
                "2026-03-17T18:00:04 INFO Upload path C:\\TierBridge\\Upload checked successfully\r\n";

            File.WriteAllText(p, text);

            var r = FI.Detect(p);

            Assert.NotNull(r);
            Assert.Equal("log", r!.Extension);
            Assert.Equal("Medium", r.Confidence);
            Assert.Equal("text:log-levels", r.Reason);
        }
        finally { TestHelpers.SafeDelete(p); }
    }
}
