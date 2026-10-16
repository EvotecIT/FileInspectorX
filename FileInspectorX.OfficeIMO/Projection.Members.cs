using System.Threading;

namespace FileInspectorX.OfficeIMO;

internal sealed partial class Projection
{
    internal bool Inventory(int ordinal, string id, string name, long? declaredBytes)
    {
        if (_entries.Count >= Budgets.MaxArchiveEntries) { _limited = true; return false; }
        string? retainedId = Exact(id);
        if (retainedId == null) return false;
        string retainedName = Prefix(name, name: true);
        _entries.Add(new ReportArchiveEntry
        {
            Ordinal = ordinal, MemberId = retainedId, Name = retainedName, Kind = ReportArchiveEntryKind.File,
            DeclaredSizeBytes = declaredBytes, SizeBytes = declaredBytes ?? 0,
            NameTruncated = retainedName.Length != name.Length, SourceNameCharacters = name.Length
        });
        return true;
    }

    internal bool CanSelect(long? declaredBytes)
    {
        if (Budgets.RemainingNestedDepth <= 0 || _members.Count >= Budgets.RemainingNestedReports ||
            Budgets.MaxEntryBytes <= 0 || SelectedCapacity <= _selectedBytes)
            return false;
        long readable = Budgets.NativeReadBytes - SnapshotReadBytes - PayloadReadBytes;
        return readable > 0 && (!declaredBytes.HasValue || declaredBytes.Value <= Budgets.MaxEntryBytes &&
            declaredBytes.Value <= SelectedCapacity - _selectedBytes && declaredBytes.Value <= readable);
    }

    internal void Select(int ordinal, string id, Stream source, CancellationToken token)
    {
        ReportArchiveEntry? inventory = _entries.FirstOrDefault(entry => entry.Ordinal == ordinal && entry.MemberId == id);
        if (inventory == null) throw new InvalidOperationException("Selected native payload is absent from its admitted identity inventory.");
        long size = source.Length;
        if (size > Budgets.MaxEntryBytes || size > SelectedCapacity - _selectedBytes || size > int.MaxValue)
        { Omit("officeimo:member-selection-limit", "members", 1); return; }
        // The native source is a detached, complete, seekable payload. Admission precedes any bridge copy.
        byte[] content = new byte[(int)size];
        source.Position = 0;
        int offset = 0;
        while (offset < content.Length)
        {
            token.ThrowIfCancellationRequested();
            int read = source.Read(content, offset, Math.Min(81920, content.Length - offset));
            if (read == 0) throw new InvalidDataException("A native detached member ended before its declared complete length.");
            offset += read;
        }
        token.ThrowIfCancellationRequested();
        if (source.ReadByte() != -1) throw new InvalidDataException("A native detached member exceeds its declared complete length.");
        _members.Add(new InspectionContentMember(ordinal, inventory.MemberId!, inventory.Name, ReportArchiveEntryKind.File, inventory.DeclaredSizeBytes, content));
        _selectedBytes = checked(_selectedBytes + size); inventory.SizeBytes = size;
    }
}
