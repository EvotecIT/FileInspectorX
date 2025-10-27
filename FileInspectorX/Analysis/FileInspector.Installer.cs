using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Xml;

namespace FileInspectorX;

/// <summary>
/// Installer/package metadata extractors (MSIX/APPX/VSIX manifests and MSI database on Windows).
/// </summary>
public static partial class FileInspector
{
    private static void TryPopulateAppxManifest(string path, FileAnalysis res)
    {
#if NET8_0_OR_GREATER || NET472
        try {
            using var fs = File.OpenRead(path);
            using var za = new ZipArchive(fs, ZipArchiveMode.Read, leaveOpen: true);
            var entry = za.GetEntry("AppxManifest.xml");
            if (entry == null) return;
            using var s = entry.Open();
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore, IgnoreComments = true, IgnoreWhitespace = true, CloseInput = true };
            using var xr = XmlReader.Create(s, settings);
            var doc = new XmlDocument { XmlResolver = null };
            doc.Load(xr);
            var nsm = new XmlNamespaceManager(doc.NameTable);
            var ns = doc.DocumentElement?.NamespaceURI ?? string.Empty;
            if (!string.IsNullOrEmpty(ns)) nsm.AddNamespace("a", ns);
            string? GetAttr(XmlNode node, string name) => node?.Attributes?[name]?.Value;

            var idNode = !string.IsNullOrEmpty(ns) ? doc.SelectSingleNode("/a:Package/a:Identity", nsm) : doc.SelectSingleNode("/Package/Identity");
            var propsNode = !string.IsNullOrEmpty(ns) ? doc.SelectSingleNode("/a:Package/a:Properties", nsm) : doc.SelectSingleNode("/Package/Properties");
            var capsNode = !string.IsNullOrEmpty(ns) ? doc.SelectSingleNode("/a:Package/a:Capabilities", nsm) : doc.SelectSingleNode("/Package/Capabilities");
            var extsNode = !string.IsNullOrEmpty(ns) ? doc.SelectSingleNode("/a:Package/a:Extensions", nsm) : doc.SelectSingleNode("/Package/Extensions");
            if (idNode == null && propsNode == null) return;

            var info = res.Installer ?? new InstallerInfo();
            info.Kind = InstallerKind.Msix; // default; caller decides if Appx vs Msix via container subtype
            info.IdentityName = GetAttr(idNode!, "Name");
            info.Publisher = GetAttr(idNode!, "Publisher");
            info.Version = GetAttr(idNode!, "Version");
            if (propsNode != null)
            {
                var pDisp = propsNode.SelectSingleNode(!string.IsNullOrEmpty(ns) ? "a:PublisherDisplayName" : "PublisherDisplayName", nsm);
                var disp = pDisp?.InnerText?.Trim();
                if (!string.IsNullOrEmpty(disp)) info.PublisherDisplayName = disp;
            }
            // Capabilities
            try {
                if (capsNode != null)
                {
                    var caps = new List<string>(8);
                    foreach (XmlNode c in capsNode.ChildNodes)
                    {
                        if (c.NodeType != XmlNodeType.Element) continue;
                        // localname or qname; include restricted capability name if present
                        string name = c.LocalName;
                        var nAttr = c.Attributes?["Name"]?.Value;
                        if (!string.IsNullOrEmpty(nAttr)) name = name + ":" + nAttr;
                        caps.Add(name);
                    }
                    if (caps.Count > 0) info.Capabilities = caps;
                }
            } catch { }

            // Extensions (categories and protocol names)
            try {
                if (extsNode != null)
                {
                    var exts = new List<string>(8);
                    foreach (XmlNode e in extsNode.ChildNodes)
                    {
                        if (e.NodeType != XmlNodeType.Element) continue;
                        var cat = e.Attributes?["Category"]?.Value ?? e.LocalName;
                        string token = cat;
                        // Protocol name if present
                        var proto = e.SelectSingleNode(".//*[local-name()='Protocol' and @Name]@Name");
                        if (proto != null) token = token + ":" + proto.Value;
                        exts.Add(token);
                    }
                    if (exts.Count > 0) info.Extensions = exts;
                }
            } catch { }

            res.Installer = info;
        } catch { }
#endif
    }

    private static void TryPopulateVsixManifest(string path, FileAnalysis res)
    {
#if NET8_0_OR_GREATER || NET472
        try {
            using var fs = File.OpenRead(path);
            using var za = new ZipArchive(fs, ZipArchiveMode.Read, leaveOpen: true);
            var entry = za.GetEntry("extension.vsixmanifest");
            if (entry == null) return;
            using var s = entry.Open();
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore, IgnoreComments = true, IgnoreWhitespace = true, CloseInput = true };
            using var xr = XmlReader.Create(s, settings);
            var doc = new XmlDocument { XmlResolver = null };
            doc.Load(xr);
            var nsm = new XmlNamespaceManager(doc.NameTable);
            var ns = doc.DocumentElement?.NamespaceURI ?? string.Empty;
            if (!string.IsNullOrEmpty(ns)) nsm.AddNamespace("v", ns);
            XmlNode? id = !string.IsNullOrEmpty(ns) ? doc.SelectSingleNode("//v:Identity", nsm) : doc.SelectSingleNode("//Identity");
            XmlNode? disp = !string.IsNullOrEmpty(ns) ? doc.SelectSingleNode("//v:DisplayName", nsm) : doc.SelectSingleNode("//DisplayName");
            var info = res.Installer ?? new InstallerInfo();
            info.Kind = InstallerKind.Vsix;
            if (id != null)
            {
                info.Publisher = id.Attributes?["Publisher"]?.Value;
                info.IdentityName = id.Attributes?["Id"]?.Value ?? id.Attributes?["ID"]?.Value;
                info.Version = id.Attributes?["Version"]?.Value;
            }
            if (disp != null) info.Name = disp.InnerText?.Trim();
            res.Installer = info;
        } catch { }
#endif
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, object> _msiLocks = new(System.StringComparer.OrdinalIgnoreCase);
    private static readonly object _msiGlobalLock = new object();

    private static void TryPopulateMsiProperties(string path, FileAnalysis res)
    {
#if NET8_0_OR_GREATER || NET472
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        // Optional kill-switch for native MSI parsing to maximize service resilience
        try { var disable = Environment.GetEnvironmentVariable("TIERBRIDGE_DISABLE_MSI_NATIVE"); if (!string.IsNullOrEmpty(disable) && (disable.Equals("1") || disable.Equals("true", StringComparison.OrdinalIgnoreCase))) return; } catch { }
        if (!Settings.IncludeInstaller) return;
        // Only attempt when file likely is MSI: declared .msi or detection already flagged msi
        try
        {
            var ext = System.IO.Path.GetExtension(path);
            var byName = !string.IsNullOrEmpty(ext) && ext.Equals(".msi", StringComparison.OrdinalIgnoreCase);
            var byDetect = (res?.Detection?.Extension?.Equals("msi", StringComparison.OrdinalIgnoreCase) ?? false);
            if (!(byName || byDetect)) return;
        } catch { return; }

        // Serialize native MSI access per path to avoid re-entrancy issues inside msi.dll
        var locker = _msiLocks.GetOrAdd(path, _ => new object());
        lock (_msiGlobalLock)
        lock (locker)
        {
        Breadcrumbs.Write("MSI_PROPS_BEGIN", path: path);
        // Windows Installer API – read Property table (Manufacturer, ProductName, ProductCode, ProductVersion, UpgradeCode, ALLUSERS, ARP URLs)
        try {
            if (MsiOpenDatabase(path, MSIDBOPEN_READONLY, out IntPtr hDb) != 0 || hDb == IntPtr.Zero) return;
            try {
                string? Manufacturer = QueryMsiProperty(hDb, "Manufacturer");
                string? ProductName = QueryMsiProperty(hDb, "ProductName");
                string? ProductCode = QueryMsiProperty(hDb, "ProductCode");
                string? ProductVersion = QueryMsiProperty(hDb, "ProductVersion");
                string? UpgradeCode = QueryMsiProperty(hDb, "UpgradeCode");
                string? AllUsers = QueryMsiProperty(hDb, "ALLUSERS");
                string? UrlInfoAbout = QueryMsiProperty(hDb, "ARPURLINFOABOUT");
                string? UrlUpdateInfo = QueryMsiProperty(hDb, "ARPURLUPDATEINFO");
                string? HelpLink = QueryMsiProperty(hDb, "ARPHELPLINK");
                string? SupportUrl = QueryMsiProperty(hDb, "ARPSUPPORTURL");
                string? Contact = QueryMsiProperty(hDb, "ARPCONTACT");
                if (Manufacturer != null || ProductName != null || ProductCode != null)
                {
                    var info = res.Installer ?? new InstallerInfo();
                    info.Kind = InstallerKind.Msi;
                    info.Manufacturer = Manufacturer;
                    info.Name = ProductName;
                    info.ProductCode = ProductCode;
                    if (!string.IsNullOrWhiteSpace(ProductVersion)) info.Version = ProductVersion;
                    if (!string.IsNullOrWhiteSpace(UpgradeCode)) info.UpgradeCode = UpgradeCode;
                    // Scope
                    if (!string.IsNullOrWhiteSpace(AllUsers))
                    {
                        info.Scope = (AllUsers == "1" || AllUsers == "2") ? "PerMachine" : "PerUser";
                    }
                    // URLs/contacts
                    if (!string.IsNullOrWhiteSpace(UrlInfoAbout)) info.UrlInfoAbout = UrlInfoAbout;
                    if (!string.IsNullOrWhiteSpace(UrlUpdateInfo)) info.UrlUpdateInfo = UrlUpdateInfo;
                    if (!string.IsNullOrWhiteSpace(HelpLink)) info.HelpLink = HelpLink;
                    if (!string.IsNullOrWhiteSpace(SupportUrl)) info.SupportUrl = SupportUrl;
                    if (!string.IsNullOrWhiteSpace(Contact)) info.Contact = Contact;
                    res.Installer = info;
                }

                // SummaryInformation (Author, Comments) – best effort
                TryPopulateMsiSummary(hDb, res);
                // CustomActions summary (Windows-only) — opt-in via env var to maximize stability
                try {
                    var ca = Environment.GetEnvironmentVariable("TIERBRIDGE_ENABLE_MSI_CA");
                    if (!string.IsNullOrEmpty(ca) && (ca.Equals("1") || ca.Equals("true", StringComparison.OrdinalIgnoreCase)))
                        TryPopulateMsiCustomActions(hDb, res);
                } catch { }
            } finally { if (hDb != IntPtr.Zero) MsiCloseHandle(hDb); Breadcrumbs.Write("MSI_PROPS_END", path: path); }
        } catch (Exception ex) { Breadcrumbs.Write("MSI_PROPS_ERROR", message: ex.GetType().Name+":"+ex.Message, path: path); }
        }

#endif
    }

#if NET8_0_OR_GREATER || NET472
    // P/Invoke (class scope)
    private const string MSIDBOPEN_READONLY = "MSIDBOPEN_READONLY";

    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiOpenDatabaseW")]
    private static extern int MsiOpenDatabase(string szDatabasePath, string? szPersist, out IntPtr phDatabase);
    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiDatabaseOpenViewW")]
    private static extern int MsiDatabaseOpenView(IntPtr hDatabase, string szQuery, out IntPtr phView);
    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiViewExecute")]
    private static extern int MsiViewExecute(IntPtr hView, IntPtr hRecord);
    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiViewFetch")]
    private static extern int MsiViewFetch(IntPtr hView, out IntPtr phRecord);
    // Two overloads: one for size-query (null buffer) and one for actual copy
    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiRecordGetStringW")]
    private static extern int MsiRecordGetStringPtr(IntPtr hRecord, int iField, IntPtr szValueBuf, ref int pcchValueBuf);
    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiRecordGetStringW")]
    private static extern int MsiRecordGetStringBuf(IntPtr hRecord, int iField, System.Text.StringBuilder szValueBuf, ref int pcchValueBuf);
    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiCloseHandle")]
    private static extern int MsiCloseHandle(IntPtr hAny);
    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiGetSummaryInformationW")]
    private static extern int MsiGetSummaryInformation(IntPtr hDatabase, string? szDatabasePath, uint uiUpdateCount, out IntPtr phSummaryInfo);
    [DllImport("msi.dll", CharSet = CharSet.Unicode, SetLastError = false, EntryPoint = "MsiSummaryInfoGetPropertyW")]
    private static extern int MsiSummaryInfoGetProperty(IntPtr hSummaryInfo, uint uiProperty, out uint puiDataType, out int piValue, System.Text.StringBuilder szValueBuf, ref uint pcchValueBuf);

    private static string? QueryMsiProperty(IntPtr hDb, string property)
    {
        IntPtr hView = IntPtr.Zero, hRec = IntPtr.Zero;
        try {
            if (MsiDatabaseOpenView(hDb, $"SELECT `Value` FROM `Property` WHERE `Property`='{property}'", out hView) != 0) return null;
            if (MsiViewExecute(hView, IntPtr.Zero) != 0) return null;
            if (MsiViewFetch(hView, out hRec) != 0 || hRec == IntPtr.Zero) return null;
            int sz = 0; _ = MsiRecordGetStringPtr(hRec, 1, IntPtr.Zero, ref sz);
            if (sz <= 0) return null;
            var sb = new System.Text.StringBuilder(sz + 1);
            if (MsiRecordGetStringBuf(hRec, 1, sb, ref sz) != 0) return null;
            return sb.ToString();
        } finally {
            if (hRec != IntPtr.Zero) MsiCloseHandle(hRec);
            if (hView != IntPtr.Zero) MsiCloseHandle(hView);
        }
    }

    private static void TryPopulateMsiSummary(IntPtr hDb, FileAnalysis res)
    {
        const uint PID_AUTHOR = 4; const uint PID_COMMENTS = 6; const uint PID_REVNUMBER = 9;
        IntPtr hSum = IntPtr.Zero;
        try {
            if (MsiGetSummaryInformation(hDb, null, 0, out hSum) != 0 || hSum == IntPtr.Zero) return;
            string? author = GetSummaryString(hSum, PID_AUTHOR);
            string? comments = GetSummaryString(hSum, PID_COMMENTS);
            string? rev = GetSummaryString(hSum, PID_REVNUMBER);
            if (!string.IsNullOrEmpty(author) || !string.IsNullOrEmpty(comments))
            {
                var info = res.Installer ?? new InstallerInfo();
                info.Kind = InstallerKind.Msi;
                if (!string.IsNullOrEmpty(author)) info.Author = author;
                if (!string.IsNullOrEmpty(comments)) info.Comments = comments;
                res.Installer = info;
            }
            if (!string.IsNullOrWhiteSpace(rev))
            {
                var info = res.Installer ?? new InstallerInfo();
                info.Kind = InstallerKind.Msi;
                info.PackageCode = rev;
                res.Installer = info;
            }
        } finally { if (hSum != IntPtr.Zero) MsiCloseHandle(hSum); }
    }

    private static string? GetSummaryString(IntPtr hSum, uint pid)
    {
        uint type = 0; int iVal = 0; uint cch = 0;
        MsiSummaryInfoGetProperty(hSum, pid, out type, out iVal, null!, ref cch);
        if (cch == 0) return null;
        var sb = new System.Text.StringBuilder((int)cch + 1);
        if (MsiSummaryInfoGetProperty(hSum, pid, out type, out iVal, sb, ref cch) != 0) return null;
        return sb.ToString();
    }

    private static void TryPopulateMsiCustomActions(IntPtr hDb, FileAnalysis res)
    {
        IntPtr hView = IntPtr.Zero, hRec = IntPtr.Zero;
        try {
            if (MsiDatabaseOpenView(hDb, "SELECT `Type`,`Source`,`Target` FROM `CustomAction`", out hView) != 0) return;
            if (MsiViewExecute(hView, IntPtr.Zero) != 0) return;
            int exe=0, dll=0, script=0, other=0; var samples = new List<string>(6);
            while (MsiViewFetch(hView, out hRec) == 0 && hRec != IntPtr.Zero)
            {
                string? sType = GetStringField(hRec, 1);
                int type = 0; _ = int.TryParse(sType, out type);
                string src = GetStringField(hRec, 2) ?? string.Empty;
                string tgt = GetStringField(hRec, 3) ?? string.Empty;
                int kind = type & 0x0007;
                switch (kind)
                {
                    case 1: dll++; break;
                    case 2: exe++; break;
                    case 5: case 6: script++; break;
                    default: other++; break;
                }
                if (samples.Count < 5) samples.Add($"{kind}:{src}/{tgt}");
            }
            if (exe+dll+script+other > 0)
            {
                var info = res.Installer ?? new InstallerInfo();
                info.Kind = InstallerKind.Msi;
                info.MsiCustomActions = new MsiCustomActionSummary { CountExe = exe, CountDll = dll, CountScript = script, CountOther = other, Samples = samples };
                res.Installer = info;
            }
        } catch { }
        finally { if (hRec != IntPtr.Zero) MsiCloseHandle(hRec); if (hView != IntPtr.Zero) MsiCloseHandle(hView); }

        static string? GetStringField(IntPtr rec, int idx)
        {
            int cch = 0; _ = MsiRecordGetStringPtr(rec, idx, IntPtr.Zero, ref cch);
            if (cch <= 0) return null;
            var sb = new System.Text.StringBuilder(cch + 1);
            if (MsiRecordGetStringBuf(rec, idx, sb, ref cch) != 0) return null; return sb.ToString();
        }
    }
#endif
}
