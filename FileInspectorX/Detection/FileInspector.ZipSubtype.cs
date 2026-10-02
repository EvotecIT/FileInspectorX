using System.IO.Compression;

namespace FileInspectorX;

public static partial class FileInspector
{
    // One bounded archive instance serves OOXML recognition and the remaining ZIP subtypes.
    private static ContentTypeDetectionResult? RefineZip(Stream stream, ContentTypeDetectionResult? result)
    {
        if (!stream.CanSeek) return result;
        long position = stream.Position;
        try
        {
            var budget = ArchiveInspectionBudget.FromSettings();
            if (!budget.CheckCentralDirectory(stream, out _)) return result;
            stream.Position = 0;
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
            if (archive.GetEntry("[Content_Types].xml") != null)
            {
                if (archive.GetEntry("word/document.xml") != null) return new ContentTypeDetectionResult { Extension = "docx", MimeType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document", Confidence = "High", Reason = "ooxml:docx" };
                if (archive.GetEntry("xl/workbook.xml") != null) return new ContentTypeDetectionResult { Extension = "xlsx", MimeType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", Confidence = "High", Reason = "ooxml:xlsx" };
                if (archive.GetEntry("ppt/presentation.xml") != null) return new ContentTypeDetectionResult { Extension = "pptx", MimeType = "application/vnd.openxmlformats-officedocument.presentationml.presentation", Confidence = "High", Reason = "ooxml:pptx" };
            }
            string? guess = GuessZipSubtype(archive, budget, out var mime);
            if (result != null)
            {
                result.GuessedExtension = guess;
                if (!string.IsNullOrWhiteSpace(mime)) result.MimeType = mime!;
                else if (!string.IsNullOrWhiteSpace(guess) && MimeMaps.TryGetByExtension(guess, out var mapped) && !string.IsNullOrWhiteSpace(mapped)) result.MimeType = mapped!;
            }
            return result;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or NotSupportedException) { return result; }
        finally { stream.Position = position; }
    }

    private static unsafe ContentTypeDetectionResult? RefineZip(ReadOnlySpan<byte> data, ReadOnlyMemory<byte>? memory, ContentTypeDetectionResult? result)
    {
        if (memory.HasValue)
        {
            using var stream = new MemoryReadStream(memory.Value);
            return RefineZip(stream, result);
        }
        if (data.IsEmpty) return result;
        // The archive reader is synchronous and private. Neither it nor this read-only
        // stream escapes the fixed scope, so array, stack and native spans can be borrowed.
        fixed (byte* pointer = data)
        {
            using var stream = new UnmanagedMemoryStream(pointer, data.Length);
            return RefineZip(stream, result);
        }
    }

    private static string? GuessZipSubtype(ZipArchive za, ArchiveInspectionBudget budget, out string? mime, bool visitEntries = true) {
        mime = null;
        try {
            int entryLimit = Math.Max(0, OperationSettings.ZipSubtypeMaxEntries);
            if (entryLimit == 0)
            {
                return null;
            }
            bool hasManifest = za.GetEntry("META-INF/MANIFEST.MF") != null;
            bool hasDex = za.GetEntry("classes.dex") != null;
            bool hasAndroidMan = za.GetEntry("AndroidManifest.xml") != null;
            bool hasAppxManifest = za.GetEntry("AppxManifest.xml") != null;
            bool hasAppxSignature = za.GetEntry("AppxSignature.p7x") != null;
            bool hasPayload = false;
            bool hasInfoPlist = false;
            bool hasNuspec = false;
            int entriesSeen = 0;
            foreach (var entry in za.Entries)
            {
                if (visitEntries && !budget.TryVisitEntry())
                {
                    return null;
                }
                entriesSeen++;
                if (entriesSeen > entryLimit)
                {
                    return null;
                }
                var name = entry.FullName;
                if (!hasPayload && name.StartsWith("Payload/", StringComparison.Ordinal)) hasPayload = true;
                if (!hasInfoPlist && name.IndexOf(".app/Info.plist", System.StringComparison.Ordinal) >= 0) hasInfoPlist = true;
                if (!hasNuspec && name.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase)) hasNuspec = true;
                if (hasPayload && hasInfoPlist && hasNuspec) break;
            }

            if (hasAndroidMan || hasDex) { mime = "application/vnd.android.package-archive"; return "apk"; }
            if (hasManifest) { mime = "application/java-archive"; return "jar"; }
            if (hasPayload && hasInfoPlist) { mime = null; return "ipa"; }
            if (hasAppxManifest) { mime = "application/zip"; return hasAppxSignature ? "msix" : "appx"; }

            var mimetypeEntry = za.GetEntry("mimetype");
            if (mimetypeEntry != null) {
                var mt = (budget.ReadText(mimetypeEntry) ?? string.Empty).Trim();
                switch (mt) {
                    case "application/epub+zip": mime = mt; return "epub";
                    case "application/vnd.oasis.opendocument.text": mime = mt; return "odt";
                    case "application/vnd.oasis.opendocument.spreadsheet": mime = mt; return "ods";
                    case "application/vnd.oasis.opendocument.presentation": mime = mt; return "odp";
                    case "application/vnd.oasis.opendocument.graphics": mime = mt; return "odg";
                }
            }

            if (za.GetEntry("doc.kml") != null) { mime = "application/vnd.google-earth.kmz"; return "kmz"; }

            if (za.GetEntry("extension.vsixmanifest") != null) { mime = "application/zip"; return "vsix"; }

            if (za.GetEntry("AppManifest.xaml") != null) { mime = "application/x-silverlight-app"; return "xap"; }

            // NuGet package (nupkg): presence of a .nuspec file
            if (hasNuspec) { mime = "application/zip"; return "nupkg"; }
        } catch { }
        return null;
    }

}
