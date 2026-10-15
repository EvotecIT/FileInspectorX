using System.Diagnostics;
using Microsoft.Win32.SafeHandles;

namespace FileInspectorX.Prototypes.FileSystem;

internal sealed partial class WindowsMftVolume
{
    internal string ReadRoute { get; private set; } = "RecordApi";
    internal int VolumeReadError { get; private set; }
    internal long BulkReadCalls { get; private set; }
    internal double BulkReadMilliseconds { get; private set; }
    internal double ParseMilliseconds { get; private set; }
    internal long RawSlots { get; private set; }

    internal static bool Control(SafeFileHandle handle, uint code, byte[]? input, byte[] output, out int returned) =>
        DeviceIoControl(handle, code, input, input?.Length ?? 0, output, output.Length, out returned, IntPtr.Zero);

    internal IEnumerable<NtfsFileRecord> EnumerateBulk(string volumeRoot, CancellationToken cancellationToken, Action checkBudget)
    {
        if (MftBytes < RecordBytes || MftBytes % RecordBytes != 0) throw new IOException("Invalid MFT length.");
        using var raw = new WindowsRawMftSource(_handle, volumeRoot, this);
        ReadRoute = raw.Route; VolumeReadError = raw.VolumeReadError;
        var runs = GetMftRuns(raw, cancellationToken);
        var buffer = new byte[WindowsRawMftSource.BufferBytes];
        long position = 0;
        while (position < MftBytes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            checkBudget();
            int count = (int)Math.Min(buffer.Length, MftBytes - position);
            long clock = Stopwatch.GetTimestamp();
            ReadMapped(raw, runs, position, buffer, count, cancellationToken);
            BulkReadMilliseconds += (Stopwatch.GetTimestamp() - clock) * 1000.0 / Stopwatch.Frequency;
            BytesRead = raw.BytesRead; BulkReadCalls = raw.ReadCalls;
            for (int offset = 0; offset < count; offset += RecordBytes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                checkBudget();
                clock = Stopwatch.GetTimestamp();
                var record = NtfsFileRecordParser.ParseRaw(buffer, offset, RecordBytes, (ulong)((position + offset) / RecordBytes), SectorBytes);
                ParseMilliseconds += (Stopwatch.GetTimestamp() - clock) * 1000.0 / Stopwatch.Frequency;
                RawSlots++;
                if (record != null) yield return record;
            }
            position += count;
        }
        // Detect relocation/growth while reading. This is still not an atomic snapshot.
        var final = GetMftRuns(raw, cancellationToken);
        if (runs.Count != final.Count || runs.Where((run, i) => run.Vcn != final[i].Vcn || run.Lcn != final[i].Lcn || run.Clusters != final[i].Clusters).Any())
            throw new IOException("MFT extents changed during bulk acquisition.");
    }

    private List<NtfsDataRun> GetMftRuns(WindowsRawMftSource raw, CancellationToken token)
    {
        byte[] first = ReadLogicalRecord(0);
        var firstRecord = NtfsFileRecordParser.Parse(first, first.Length, SectorBytes);
        if ((firstRecord.Id & NtfsFileRecordParser.SlotMask) != 0 || firstRecord.BaseId != 0)
            throw new IOException("Invalid MFT bootstrap identity.");
        var runs = new List<NtfsDataRun>();
        byte[]? list = null;
        foreach (var attribute in NtfsDataRuns.Attributes(first))
        {
            int p = attribute.Offset;
            if (first[p + 9] != 0) continue;
            if (attribute.Type == 0x80) AddData(first, attribute.Offset, attribute.Length, runs);
            if (attribute.Type != 0x20) continue;
            if (list != null) throw new IOException("Duplicate MFT attribute list.");
            if (first[p + 8] == 0)
            {
                int size = checked((int)BitConverter.ToUInt32(first, p + 16));
                int offset = BitConverter.ToUInt16(first, p + 20);
                if (offset < 24 || size < 0 || size > attribute.Length - offset) throw new IOException("Invalid resident attribute list.");
                list = new byte[size]; Buffer.BlockCopy(first, p + offset, list, 0, size);
            }
            else
            {
                long size = BitConverter.ToInt64(first, p + 48);
                if (size <= 0 || size > 16 * 1024 * 1024) throw new NotSupportedException("MFT attribute-list budget exceeded.");
                var listRuns = NtfsDataRuns.Attribute(first, p, attribute.Length);
                list = new byte[(int)size]; ReadMapped(raw, listRuns, 0, list, list.Length, token);
            }
        }
        var fetched = new HashSet<ulong> { firstRecord.Id };
        if (list != null)
            for (int p = 0; p < list.Length;)
            {
                token.ThrowIfCancellationRequested();
                if (list.Length - p < 26) throw new IOException("Truncated MFT attribute-list entry.");
                int size = BitConverter.ToUInt16(list, p + 4), named = list[p + 6], nameOffset = list[p + 7];
                if (size < 26 || size > list.Length - p || named != 0 && (nameOffset < 26 || nameOffset > size - named * 2))
                    throw new IOException("Invalid MFT attribute-list entry.");
                if (BitConverter.ToUInt32(list, p) == 0x80 && named == 0)
                {
                    ulong id = BitConverter.ToUInt64(list, p + 16);
                    if (fetched.Add(id))
                    {
                        if (fetched.Count > 4096) throw new NotSupportedException("MFT layout-extension budget exceeded.");
                        byte[] extension = ReadLogicalRecord(id);
                        var decoded = NtfsFileRecordParser.Parse(extension, extension.Length, SectorBytes);
                        if (decoded.Id != id || decoded.BaseId != firstRecord.Id) throw new IOException("MFT extension identity changed.");
                        foreach (var attribute in NtfsDataRuns.Attributes(extension))
                            if (attribute.Type == 0x80 && extension[attribute.Offset + 9] == 0)
                                AddData(extension, attribute.Offset, attribute.Length, runs);
                    }
                }
                p += size;
            }
        runs.Sort((a, b) => a.Vcn.CompareTo(b.Vcn));
        long next = 0;
        foreach (var run in runs) { if (run.Vcn != next) throw new IOException("MFT mapping has a gap or overlap."); next = checked(next + run.Clusters); }
        if (runs.Count == 0 || runs[0].Lcn != MftStartCluster || checked(next * ClusterBytes) < MftBytes)
            throw new IOException("MFT mapping does not cover the declared valid metadata.");
        return runs;
    }

    private void AddData(byte[] record, int p, int length, List<NtfsDataRun> runs)
    {
        if (length < 64 || record[p + 8] != 1) throw new IOException("MFT data must be nonresident.");
        if (BitConverter.ToInt64(record, p + 16) == 0 && BitConverter.ToInt64(record, p + 48) < MftBytes)
            throw new IOException("MFT length changed during layout acquisition.");
        runs.AddRange(NtfsDataRuns.Attribute(record, p, length));
    }

    private void ReadMapped(WindowsRawMftSource raw, List<NtfsDataRun> runs, long offset, byte[] buffer, int count, CancellationToken token)
    {
        int written = 0;
        foreach (var run in runs)
        {
            long start = checked(run.Vcn * ClusterBytes), end = checked(start + run.Clusters * ClusterBytes);
            if (offset >= end) continue;
            if (offset < start) throw new IOException("Metadata stream mapping contains a gap.");
            while (written < count && offset < end)
            {
                token.ThrowIfCancellationRequested();
                int part = (int)Math.Min(Math.Min(count - written, end - offset), WindowsRawMftSource.BufferBytes - SectorBytes);
                raw.ReadVolume(checked(run.Lcn * ClusterBytes + offset - start), buffer, written, part);
                offset += part; written += part;
            }
            if (written == count) return;
        }
        throw new IOException("Metadata stream exceeds its mapped extents.");
    }
}
