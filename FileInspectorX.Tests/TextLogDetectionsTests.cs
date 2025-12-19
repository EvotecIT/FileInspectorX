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
        finally { if (File.Exists(p)) File.Delete(p); }
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
        finally { if (File.Exists(p)) File.Delete(p); }
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
        finally { if (File.Exists(p)) File.Delete(p); }
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
        finally { if (File.Exists(p)) File.Delete(p); }
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
        finally { if (File.Exists(p)) File.Delete(p); }
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
        finally { if (File.Exists(p)) File.Delete(p); }
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
        finally { if (File.Exists(p)) File.Delete(p); }
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
        finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Theory]
    [InlineData("mpcmdrun.exe started", false)]
    [InlineData("MpCmdRun.exe\nWindows Defender\nThreat detected", true)]
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
        finally { if (File.Exists(p)) File.Delete(p); }
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
        finally { if (File.Exists(p)) File.Delete(p); }
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
        finally { if (File.Exists(p)) File.Delete(p); }
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
        finally { if (File.Exists(p)) File.Delete(p); }
    }
}
