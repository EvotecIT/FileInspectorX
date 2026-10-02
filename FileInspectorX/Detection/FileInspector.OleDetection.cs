using System.IO.Compression;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace FileInspectorX;

public static partial class FileInspector
{
    private static ContentTypeDetectionResult? TryRefineOle2Subtype(Stream stream) {
        try {
            long pos = stream.CanSeek ? stream.Position : 0;
            if (stream.CanSeek) stream.Seek(0, SeekOrigin.Begin);
            int cap = Math.Max(8 * 1024, Math.Min(OperationSettings.DetectionReadBudgetBytes, 512 * 1024));
            var buf = new byte[cap];
            int n = ReadAvailable(stream, buf, 0, buf.Length);
            if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin);
            var ascii = System.Text.Encoding.ASCII.GetString(buf, 0, n);
            if (ascii.IndexOf("WordDocument", StringComparison.OrdinalIgnoreCase) >= 0)
                return new ContentTypeDetectionResult { Extension = "doc", MimeType = "application/msword", Confidence = "Medium", Reason = "ole2:word" };
            if (ascii.IndexOf("Workbook", StringComparison.OrdinalIgnoreCase) >= 0)
                return new ContentTypeDetectionResult { Extension = "xls", MimeType = "application/vnd.ms-excel", Confidence = "Medium", Reason = "ole2:xls" };
            if (ascii.IndexOf("PowerPoint Document", StringComparison.OrdinalIgnoreCase) >= 0)
                return new ContentTypeDetectionResult { Extension = "ppt", MimeType = "application/vnd.ms-powerpoint", Confidence = "Medium", Reason = "ole2:ppt" };
            // MSI hint: raise confidence to High when multiple typical MSI table names occur alongside SummaryInformation
            bool hasSum = ascii.IndexOf("SummaryInformation", StringComparison.OrdinalIgnoreCase) >= 0;
            int cnt = 0;
            if (ascii.IndexOf("Property", StringComparison.OrdinalIgnoreCase) >= 0) cnt++;
            if (ascii.IndexOf("Directory", StringComparison.OrdinalIgnoreCase) >= 0) cnt++;
            if (ascii.IndexOf("Media", StringComparison.OrdinalIgnoreCase) >= 0) cnt++;
            if (ascii.IndexOf("Component", StringComparison.OrdinalIgnoreCase) >= 0) cnt++;
            if (hasSum && cnt >= 2)
                return new ContentTypeDetectionResult { Extension = "msi", MimeType = "application/x-msi", Confidence = "Medium", Reason = "ole2:msi-hint;sector-chains-not-validated" };

            // Try mini CFBF directory parse for higher confidence
            if (TryGetOleDirectoryNames(stream, out var names))
            {
                if (names.Any(nm => nm.Equals("WordDocument", StringComparison.OrdinalIgnoreCase)))
                    return new ContentTypeDetectionResult { Extension = "doc", MimeType = "application/msword", Confidence = "Medium", Reason = "ole2:word-cfbf;sector-chains-partial" };
                if (names.Any(nm => nm.Equals("Workbook", StringComparison.OrdinalIgnoreCase) || nm.Equals("Book", StringComparison.OrdinalIgnoreCase)))
                    return new ContentTypeDetectionResult { Extension = "xls", MimeType = "application/vnd.ms-excel", Confidence = "Medium", Reason = "ole2:xls-cfbf;sector-chains-partial" };
                if (names.Any(nm => nm.Equals("PowerPoint Document", StringComparison.OrdinalIgnoreCase)))
                    return new ContentTypeDetectionResult { Extension = "ppt", MimeType = "application/vnd.ms-powerpoint", Confidence = "Medium", Reason = "ole2:ppt-cfbf;sector-chains-partial" };
                bool hasSummary = names.Any(nm => nm.IndexOf("SummaryInformation", StringComparison.OrdinalIgnoreCase) >= 0 || (nm.Length > 0 && nm[0] == '\u0005' && nm.IndexOf("SummaryInformation", StringComparison.OrdinalIgnoreCase) >= 1));
                int hits = 0;
                string[] msiNames = new [] { "Property", "Directory", "Feature", "Media", "Component", "File", "InstallExecuteSequence" };
                foreach (var nm in names) foreach (var t in msiNames) { if (nm.Equals(t, StringComparison.OrdinalIgnoreCase)) { hits++; break; } }
                if (hasSummary && hits >= 2)
                    return new ContentTypeDetectionResult { Extension = "msi", MimeType = "application/x-msi", Confidence = "Medium", Reason = "ole2:msi-cfbf;sector-chains-partial" };
            }
        } catch { }
        return null;
    }

    internal static bool TryGetOleDirectoryNames(Stream stream, out List<string> names)
    {
        names = new List<string>();
        long save = stream.CanSeek ? stream.Position : 0;
        try {
            if (!stream.CanSeek) return false;
            stream.Seek(0, SeekOrigin.Begin);
            var hdr = new byte[512];
            if (ReadAvailable(stream, hdr, 0, hdr.Length) != hdr.Length) return false;
            // Signature
            byte[] sig = new byte[] { 0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1 };
            for (int i = 0; i < 8; i++) if (hdr[i] != sig[i]) return false;
            int secShift = hdr[0x1E] | (hdr[0x1F] << 8);
            // CFBF permits only 512-byte (v3) and 4096-byte (v4) sectors.
            if (secShift is not (9 or 12)) return false;
            int sectorSize = 1 << secShift;
            int dirStartSid = BitConverter.ToInt32(hdr, 0x30);
            int fatCount = BitConverter.ToInt32(hdr, 0x2C);
            int readBudget = Math.Max(512, OperationSettings.DetectionReadBudgetBytes);
            int maxFatSectorsByBudget = Math.Max(1, readBudget / sectorSize);
            if (dirStartSid < 0 || fatCount <= 0) return false;
            // Read FAT sector SIDs from DIFAT in header (109 entries)
            var fatSids = new List<int>();
            for (int i = 0; i < 109; i++)
            {
                int sid = BitConverter.ToInt32(hdr, 0x4C + i*4);
                if (sid >= 0 && fatSids.Count < fatCount && fatSids.Count < maxFatSectorsByBudget) fatSids.Add(sid);
            }
            if (fatSids.Count == 0 || fatCount == 0) return false;
            // Build FAT table
            var fat = new List<int>(Math.Min(fatSids.Count * (sectorSize / 4), readBudget / 4));
            int bytesRead = 512;
            foreach (var sid in fatSids)
            {
                if (bytesRead > readBudget - sectorSize) break;
                long off = ((long)sid + 1) * sectorSize;
                if (off < 0 || off + sectorSize > stream.Length) continue;
                stream.Seek(off, SeekOrigin.Begin);
                var sec = new byte[sectorSize];
                int rn = ReadAvailable(stream, sec, 0, sec.Length);
                if (rn != sec.Length) break;
                bytesRead += rn;
                // Each FAT sector contains 32-bit entries
                for (int p = 0; p + 4 <= sec.Length; p += 4)
                    fat.Add(BitConverter.ToInt32(sec, p));
            }
            // Walk directory stream through FAT (bounded). Increase sectors for robust MSI detection.
            const int ENDOFCHAIN = unchecked((int)0xFFFFFFFE);
            int cur = dirStartSid; int maxSectors = Math.Min(64, Math.Max(1, (readBudget - bytesRead) / sectorSize)); int sectors = 0;
            while (cur >= 0 && cur < fat.Count && sectors < maxSectors)
            {
                long off = ((long)cur + 1) * sectorSize;
                if (off < 0 || off + sectorSize > stream.Length) break;
                stream.Seek(off, SeekOrigin.Begin);
                var dirSec = new byte[sectorSize];
                if (ReadAvailable(stream, dirSec, 0, dirSec.Length) != dirSec.Length) break;
                // Parse 128-byte directory entries
                for (int p = 0; p + 128 <= dirSec.Length; p += 128)
                {
                    int nameLen = dirSec[p + 0x40] | (dirSec[p + 0x41] << 8); // bytes
                    byte objectType = dirSec[p + 0x42];
                    if (objectType is 1 or 2 or 5 && nameLen >= 2 && nameLen <= 64 && (nameLen & 1) == 0 &&
                        dirSec[p + nameLen - 2] == 0 && dirSec[p + nameLen - 1] == 0)
                    {
                        int bytes = nameLen - 2; // exclude terminating null
                        if (bytes > 0 && bytes <= 128)
                        {
                            try {
                                string nm = Encoding.Unicode.GetString(dirSec, p, bytes);
                                if (!string.IsNullOrWhiteSpace(nm)) names.Add(nm);
                            } catch { }
                        }
                    }
                }
                int next = fat[cur];
                if (next == ENDOFCHAIN) break;
                cur = next; sectors++;
            }
            return names.Count > 0;
        } catch { return false; }
        finally { if (stream.CanSeek) stream.Seek(save, SeekOrigin.Begin); }
    }

}
