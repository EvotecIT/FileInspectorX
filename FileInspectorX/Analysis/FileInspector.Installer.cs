using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Xml;

namespace FileInspectorX;

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

    private static void TryPopulateMsiProperties(string path, FileAnalysis res)
    {
#if NET8_0_OR_GREATER || NET472
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        // Windows Installer API – read Property table (Manufacturer, ProductName, ProductCode)
        try {
            if (MsiOpenDatabase(path, IntPtr.Zero, out IntPtr hDb) != 0 || hDb == IntPtr.Zero) return;
            try {
                string? Manufacturer = QueryMsiProperty(hDb, "Manufacturer");
                string? ProductName = QueryMsiProperty(hDb, "ProductName");
                string? ProductCode = QueryMsiProperty(hDb, "ProductCode");
                if (Manufacturer != null || ProductName != null || ProductCode != null)
                {
                    var info = res.Installer ?? new InstallerInfo();
                    info.Kind = InstallerKind.Msi;
                    info.Manufacturer = Manufacturer;
                    info.Name = ProductName;
                    info.ProductCode = ProductCode;
                    res.Installer = info;
                }

                // SummaryInformation (Author, Comments) – best effort
                TryPopulateMsiSummary(hDb, res);
            } finally { if (hDb != IntPtr.Zero) MsiCloseHandle(hDb); }
        } catch { }

#endif
    }

#if NET8_0_OR_GREATER || NET472
    // P/Invoke (class scope)
    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    private static extern int MsiOpenDatabase(string szDatabasePath, IntPtr phPersist, out IntPtr phDatabase);
    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    private static extern int MsiDatabaseOpenView(IntPtr hDatabase, string szQuery, out IntPtr phView);
    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    private static extern int MsiViewExecute(IntPtr hView, IntPtr hRecord);
    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    private static extern int MsiViewFetch(IntPtr hView, out IntPtr phRecord);
    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    private static extern int MsiRecordGetString(IntPtr hRecord, int iField, System.Text.StringBuilder szValueBuf, ref int pcchValueBuf);
    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    private static extern int MsiCloseHandle(IntPtr hAny);
    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    private static extern int MsiGetSummaryInformation(IntPtr hDatabase, string? szDatabasePath, uint uiUpdateCount, out IntPtr phSummaryInfo);
    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    private static extern int MsiSummaryInfoGetProperty(IntPtr hSummaryInfo, uint uiProperty, out uint puiDataType, out int piValue, System.Text.StringBuilder szValueBuf, ref uint pcchValueBuf);

    private static string? QueryMsiProperty(IntPtr hDb, string property)
    {
        IntPtr hView = IntPtr.Zero, hRec = IntPtr.Zero;
        try {
            if (MsiDatabaseOpenView(hDb, $"SELECT `Value` FROM `Property` WHERE `Property`='{property}'", out hView) != 0) return null;
            if (MsiViewExecute(hView, IntPtr.Zero) != 0) return null;
            if (MsiViewFetch(hView, out hRec) != 0 || hRec == IntPtr.Zero) return null;
            int sz = 0; MsiRecordGetString(hRec, 1, null!, ref sz);
            var sb = new System.Text.StringBuilder(sz + 1);
            if (MsiRecordGetString(hRec, 1, sb, ref sz) != 0) return null;
            return sb.ToString();
        } finally {
            if (hRec != IntPtr.Zero) MsiCloseHandle(hRec);
            if (hView != IntPtr.Zero) MsiCloseHandle(hView);
        }
    }

    private static void TryPopulateMsiSummary(IntPtr hDb, FileAnalysis res)
    {
        const uint PID_AUTHOR = 4; const uint PID_COMMENTS = 6;
        IntPtr hSum = IntPtr.Zero;
        try {
            if (MsiGetSummaryInformation(hDb, null, 0, out hSum) != 0 || hSum == IntPtr.Zero) return;
            string? author = GetSummaryString(hSum, PID_AUTHOR);
            string? comments = GetSummaryString(hSum, PID_COMMENTS);
            if (!string.IsNullOrEmpty(author) || !string.IsNullOrEmpty(comments))
            {
                var info = res.Installer ?? new InstallerInfo();
                info.Kind = InstallerKind.Msi;
                if (!string.IsNullOrEmpty(author)) info.Author = author;
                if (!string.IsNullOrEmpty(comments)) info.Comments = comments;
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
#endif
}
