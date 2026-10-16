using System.Globalization;
using System.Threading;
using OfficeIMO;
using OfficeIMO.Archives;
using OfficeIMO.Pdf;

namespace FileInspectorX.OfficeIMO;

public sealed partial class OfficeImoContentReader
{
    private void ReadPayloads(Projection output, Func<OfficeEmbeddedPayloadInspectionOptions, OfficeEmbeddedPayloadInspection> inspect,
        NativeReadStream source, CancellationToken token)
    {
        output.SnapshotReadBytes = source.BytesRead;
        using var session = inspect(new OfficeEmbeddedPayloadInspectionOptions
        {
            MaxPayloads = NativeCount(output), MaxPayloadBytes = Expanded(output), MaxTotalPayloadBytes = Expanded(output),
            MaxReadBytes = Math.Max(0, output.Budgets.NativeReadBytes - source.BytesRead), IncludeSha256 = false
        });
        try
        {
            foreach (OfficeEmbeddedPayloadInfo payload in session.Payloads)
            {
                token.ThrowIfCancellationRequested();
                long? declared = payload.HasKnownLength ? payload.Length : null;
                bool admitted = output.Inventory(payload.Ordinal, payload.Id, payload.SuggestedFileName, declared);
                output.Fact("embedded.payload", payload.Kind.ToString(), attributes: new Dictionary<string, string>
                {
                    ["id"] = payload.Id, ["ordinal"] = payload.Ordinal.ToString(CultureInfo.InvariantCulture),
                    ["ownerPart"] = payload.OwnerPartUri, ["relationship"] = payload.RelationshipId,
                    ["part"] = payload.PartUri, ["contentType"] = payload.ContentType,
                    ["declaredBytes"] = declared?.ToString(CultureInfo.InvariantCulture) ?? "unknown"
                });
                output.PayloadReadBytes = session.ReadBytes;
                if (!_options.ReadEmbeddedMembers || !admitted || !output.CanSelect(declared))
                { output.Omit("officeimo:member-not-selected", "embedded-payloads", 1); continue; }
                using Stream bytes = session.OpenRead(payload.Ordinal, token);
                output.PayloadReadBytes = session.ReadBytes;
                output.Select(payload.Ordinal, payload.Id, bytes, token);
            }
        }
        finally { output.PayloadReadBytes = session.ReadBytes; }
    }

    private void ReadArchive(NativeReadStream source, Projection output, CancellationToken token)
    {
        output.ChargeUnknownExpansion();
        long nativeReadRemainder = output.Budgets.NativeReadBytes - source.Length;
        if (nativeReadRemainder <= 0) throw Limit("NativeReadBytes", output.Budgets.NativeReadBytes, source.Length + 1);
        using ArchiveInspection archive = ArchiveInspector.Open(source, new ArchiveInspectionOptions
        {
            MaxInputBytes = Input(output), MaxEntryCount = NativeCount(output), MaxCabinetCount = NativeCount(output),
            MaxEntryBytes = Expanded(output), MaxExpandedBytes = Math.Min(Expanded(output), nativeReadRemainder),
            MaxDecompressionWorkBytes = output.Budgets.DecompressionWorkBytes,
            MaxMetadataBytes = Expanded(output), MaxTableRows = NativeCount(output), MaxStringPoolEntries = NativeCount(output),
            MaxDirectoryRecords = NativeCount(output), MaxPathDepth = 32, MaxPathLength = 1024
        }, token);
        output.SnapshotReadBytes = source.BytesRead;
        var ordinals = new List<int>();
        long selected = 0;
        foreach (ArchiveInspectionEntry entry in archive.Entries)
        {
            token.ThrowIfCancellationRequested();
            string id = "archives:" + archive.Format + ":entry:" + entry.Ordinal.ToString(CultureInfo.InvariantCulture);
            bool admitted = output.Inventory(entry.Ordinal, id, entry.RawName, entry.Length);
            var details = new Dictionary<string, string>
            {
                ["ordinal"] = entry.Ordinal.ToString(CultureInfo.InvariantCulture), ["rawName"] = entry.RawName,
                ["rawFileName"] = entry.RawFileName ?? string.Empty, ["authoredPath"] = entry.AuthoredPath ?? string.Empty,
                ["cabinet"] = entry.CabinetName ?? string.Empty, ["cabinetOrdinal"] = entry.CabinetOrdinal?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                ["sequence"] = entry.Sequence?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                ["folderOrdinal"] = entry.FolderOrdinal?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                ["folderCompressedBytes"] = entry.FolderCompressedBytes?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                ["folderExpandedBytes"] = entry.FolderExpandedBytes?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                ["folderFrames"] = entry.FolderFrameCount?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                ["folderChecksumFrames"] = entry.FolderChecksumFrameCount?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                ["rawCompression"] = entry.RawCompression?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                ["canRead"] = entry.CanRead.ToString()
            };
            output.Fact("archives.member.compression", entry.Compression.ToString(), ReportFactOrigin.Derived, attributes: details);
            if (entry.Diagnostic != null) output.Diagnostic(entry.Diagnostic.Code, entry.Diagnostic.Message);
            if (_options.ReadEmbeddedMembers && admitted && entry.CanRead && output.CanSelect(entry.Length) &&
                ordinals.Count < output.Budgets.RemainingNestedReports && entry.Length <= output.SelectedCapacity - selected)
            { ordinals.Add(entry.Ordinal); selected = checked(selected + entry.Length); }
            else output.Omit("officeimo:member-not-selected", "archives", 1);
        }
        foreach (ArchiveStorageStream storage in archive.StorageStreams)
            output.Fact("archives.storage-stream", storage.RawName, attributes: new Dictionary<string, string>
            {
                ["ordinal"] = storage.Ordinal.ToString(CultureInfo.InvariantCulture),
                ["directoryOrder"] = storage.DirectoryOrder.ToString(CultureInfo.InvariantCulture),
                ["length"] = storage.Length.ToString(CultureInfo.InvariantCulture), ["selection"] = "inventory-only"
            });
        if (ordinals.Count == 0) return;
        using ArchiveReadBatch batch = archive.ReadMembers(ordinals, output.SelectedCapacity, token);
        output.PayloadReadBytes = archive.ReadBytes;
        output.DecompressionWorkBytes = batch.DecompressionWorkBytes;
        foreach (ArchiveReadMember member in batch.Members)
        {
            string id = "archives:" + archive.Format + ":entry:" + member.Entry.Ordinal.ToString(CultureInfo.InvariantCulture);
            output.Select(member.Entry.Ordinal, id, member.Content, token);
        }
    }

    private void ReadPdfAttachments(PdfDocument document, PdfInspectionReadResult inspection, Projection output,
        NativeReadStream source, CancellationToken token)
    {
        output.SnapshotReadBytes = source.BytesRead;
        int ordinal = 0;
        foreach (PdfAttachmentInfo attachment in inspection.SourceInfo.Attachments)
        {
            token.ThrowIfCancellationRequested();
            string id = "pdf:" + attachment.Source + ":filespec:" + attachment.FileSpecObjectNumber.ToString(CultureInfo.InvariantCulture) +
                ":stream:" + attachment.EmbeddedFileObjectNumber.ToString(CultureInfo.InvariantCulture) + ":occurrence:" + ordinal.ToString(CultureInfo.InvariantCulture);
            bool admitted = output.Inventory(ordinal, id, attachment.UnicodeFileName ?? attachment.FileName, attachment.DeclaredSizeBytes);
            output.Fact("pdf.attachment", attachment.Name, attributes: new Dictionary<string, string>
            {
                ["memberId"] = id, ["source"] = attachment.Source, ["fileSpecObject"] = attachment.FileSpecObjectNumber.ToString(CultureInfo.InvariantCulture),
                ["embeddedFileObject"] = attachment.EmbeddedFileObjectNumber.ToString(CultureInfo.InvariantCulture),
                ["encodedBytes"] = attachment.EncodedSizeBytes.ToString(CultureInfo.InvariantCulture),
                ["declaredDecodedBytes"] = attachment.DeclaredSizeBytes?.ToString(CultureInfo.InvariantCulture) ?? "unknown",
                ["decodedBytes"] = "unknown-before-selected-read", ["filter"] = attachment.Filter, ["mimeType"] = attachment.MimeType ?? string.Empty
            });
            // /Params/Size is an authored claim, never a decoding admission ceiling.
            if (_options.ReadEmbeddedMembers && admitted && output.CanSelect(null))
            {
                long maximum = Math.Min(output.Budgets.MaxEntryBytes, Math.Min(output.SelectedCapacity,
                    output.Budgets.NativeReadBytes - output.SnapshotReadBytes - output.PayloadReadBytes));
                byte[] bytes = document.Attachments.Extract(attachment, maximum, token).Bytes;
                output.PayloadReadBytes = checked(output.PayloadReadBytes + bytes.LongLength);
                using var detached = new MemoryStream(bytes, writable: false);
                output.Select(ordinal, id, detached, token);
            }
            else output.Omit("officeimo:member-not-selected", "pdf-attachments", 1);
            ordinal++;
        }
    }
}
