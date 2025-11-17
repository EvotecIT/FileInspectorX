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
        if (!Settings.IncludeInstaller) return;
        // Only attempt when file likely is MSI: declared .msi or detection already flagged msi
        try
        {
            var ext = System.IO.Path.GetExtension(path);
            var byName = !string.IsNullOrEmpty(ext) && ext.Equals(".msi", StringComparison.OrdinalIgnoreCase);
            // 'res' is a required parameter here; avoid null-conditional on it to preserve non-null flow
            var byDetect = (res.Detection?.Extension?.Equals("msi", StringComparison.OrdinalIgnoreCase) ?? false);
            if (!(byName || byDetect)) return;
        } catch { return; }

        // Serialize native MSI access per path to avoid re-entrancy issues inside msi.dll
        var locker = _msiLocks.GetOrAdd(path, _ => new object());
        lock (_msiGlobalLock)
        lock (locker)
        {
        Breadcrumbs.Write("MSI_PROPS_BEGIN", path: path);
        try {
            InspectorMetrics.Msi.IncAttempt();
            MsiNative.SuppressUI();
            if (!MsiNative.TryOpenDatabase(path, out var hDb)) return;
            using (hDb)
            {
                // Guard: ensure standard Property table exists
                if (!HasTable(hDb, "Property")) { Breadcrumbs.Write("MSI_NO_PROPERTY_TABLE", path: path); InspectorMetrics.Msi.IncSkipped(); return; }
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
                // CustomActions summary (Windows-only) — opt-in via Settings.EnableMsiCustomActions for stability
                try { if (Settings.EnableMsiCustomActions && HasTable(hDb, "CustomAction")) TryPopulateMsiCustomActions(hDb, res); } catch { }
                InspectorMetrics.Msi.IncSuccess();
            }
            Breadcrumbs.Write("MSI_PROPS_END", path: path);
        } catch (Exception ex) {
            var last = MsiNative.GetLastErrorString();
            Breadcrumbs.Write("MSI_PROPS_ERROR", message: ex.GetType().Name+":"+ex.Message + (string.IsNullOrEmpty(last)?string.Empty:(";"+last)), path: path);
            InspectorMetrics.Msi.IncFail();
        }
        }

#endif
    }

#if NET8_0_OR_GREATER || NET472
    // P/Invoke (class scope)
    private const string MSIDBOPEN_READONLY = "MSIDBOPEN_READONLY";

    // P/Invoke moved to MsiNative with SafeHandles

    private static string? QueryMsiProperty(MsiNative.SafeMsiHandle hDb, string property)
    {
        if (!MsiNative.TryOpenView(hDb, $"SELECT `Value` FROM `Property` WHERE `Property`='{property}'", out var hView)) { Breadcrumbs.Write("MSI_VIEW_OPEN_ERROR", message: property); return null; }
        using (hView)
        {
            if (MsiNative.MsiViewExecute(hView.DangerousGetHandle(), IntPtr.Zero) != MsiNative.ERROR_SUCCESS) { Breadcrumbs.Write("MSI_VIEW_EXEC_ERROR", message: property); return null; }
            if (MsiNative.MsiViewFetch(hView.DangerousGetHandle(), out var hRec) != MsiNative.ERROR_SUCCESS || hRec == IntPtr.Zero) { Breadcrumbs.Write("MSI_VIEW_FETCH_ERROR", message: property); return null; }
            try { return MsiNative.GetRecordString(hRec, 1); }
            finally { _ = MsiNative.CloseHandle(hRec); }
        }
    }

    private static bool HasTable(MsiNative.SafeMsiHandle hDb, string tableName)
    {
        try
        {
            if (!MsiNative.TryOpenView(hDb, $"SELECT `Name` FROM `_Tables` WHERE `Name`='{tableName}'", out var hView)) return false;
            using (hView)
            {
                if (MsiNative.MsiViewExecute(hView.DangerousGetHandle(), IntPtr.Zero) != MsiNative.ERROR_SUCCESS) return false;
                return MsiNative.MsiViewFetch(hView.DangerousGetHandle(), out var hRec) == MsiNative.ERROR_SUCCESS && hRec != IntPtr.Zero && MsiNative.CloseHandle(hRec);
            }
        }
        catch { return false; }
    }

    private static void TryPopulateMsiSummary(MsiNative.SafeMsiHandle hDb, FileAnalysis res)
    {
        const uint PID_AUTHOR = 4; const uint PID_COMMENTS = 6; const uint PID_REVNUMBER = 9;
        const uint PID_CREATE_DTM = 12; const uint PID_LASTSAVE_DTM = 13;
        if (!MsiNative.TryGetSummaryInfo(hDb, out var hSum)) return;
        using (hSum)
        {
            string? author = MsiNative.GetSummaryString(hSum, PID_AUTHOR);
            string? comments = MsiNative.GetSummaryString(hSum, PID_COMMENTS);
            string? rev = MsiNative.GetSummaryString(hSum, PID_REVNUMBER);
            string? created = MsiNative.GetSummaryString(hSum, PID_CREATE_DTM);
            string? lastSaved = MsiNative.GetSummaryString(hSum, PID_LASTSAVE_DTM);
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
            // Dates (best-effort: the API lets us format to string; parse to UTC when possible)
            if (!string.IsNullOrEmpty(created) || !string.IsNullOrEmpty(lastSaved))
            {
                var info = res.Installer ?? new InstallerInfo();
                info.Kind = InstallerKind.Msi;
                if (!string.IsNullOrEmpty(created) && DateTime.TryParse(created, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out var cdt)) info.CreatedUtc = cdt;
                if (!string.IsNullOrEmpty(lastSaved) && DateTime.TryParse(lastSaved, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out var ldt)) info.LastSavedUtc = ldt;
                res.Installer = info;
            }
        }
    }

    // Summary property retrieval moved to MsiNative.GetSummaryString

    private static void TryPopulateMsiCustomActions(MsiNative.SafeMsiHandle hDb, FileAnalysis res)
    {
        int exe=0, dll=0, script=0, other=0; var samples = new List<string>(6);
        if (!MsiNative.TryOpenView(hDb, "SELECT `Type`,`Source`,`Target` FROM `CustomAction`", out var hView)) return;
        using (hView)
        {
            if (MsiNative.MsiViewExecute(hView.DangerousGetHandle(), IntPtr.Zero) != MsiNative.ERROR_SUCCESS) return;
            while (MsiNative.MsiViewFetch(hView.DangerousGetHandle(), out var hRec) == MsiNative.ERROR_SUCCESS && hRec != IntPtr.Zero)
            {
                string? sType = MsiNative.GetRecordString(hRec, 1);
                int type = 0; _ = int.TryParse(sType, out type);
                string src = MsiNative.GetRecordString(hRec, 2) ?? string.Empty;
                string tgt = MsiNative.GetRecordString(hRec, 3) ?? string.Empty;
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
        }
    }
#endif
}

// (no extra partial declarations here)
