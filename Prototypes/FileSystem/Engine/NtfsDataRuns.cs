namespace FileInspectorX.Prototypes.FileSystem;

/// <summary>Validated non-sparse metadata extents. Offsets are relative to the NTFS volume.</summary>
internal sealed class NtfsDataRun
{
    internal long Vcn, Lcn, Clusters;
}

internal static class NtfsDataRuns
{
    internal static List<NtfsDataRun> Decode(byte[] bytes, int offset, int end, long firstVcn, long lastVcn)
    {
        if (offset < 0 || end > bytes.Length || offset >= end || firstVcn < 0 || lastVcn < firstVcn)
            throw new IOException("Invalid mapping-pairs bounds.");
        var runs = new List<NtfsDataRun>();
        long vcn = firstVcn, lcn = 0;
        while (offset < end)
        {
            byte header = bytes[offset++];
            if (header == 0)
            {
                if (vcn != checked(lastVcn + 1)) throw new IOException("Mapping pairs do not cover their declared VCN range.");
                return runs;
            }
            int lengthBytes = header & 15, offsetBytes = header >> 4;
            if (lengthBytes < 1 || lengthBytes > 8 || offsetBytes < 1 || offsetBytes > 8 || offset > end - lengthBytes - offsetBytes)
                throw new IOException("Invalid or sparse metadata mapping pair.");
            ulong length = 0, rawDelta = 0;
            for (int i = 0; i < lengthBytes; i++) length |= (ulong)bytes[offset++] << (8 * i);
            for (int i = 0; i < offsetBytes; i++) rawDelta |= (ulong)bytes[offset++] << (8 * i);
            long delta = unchecked((long)(rawDelta << (64 - offsetBytes * 8))) >> (64 - offsetBytes * 8);
            if (length == 0 || length > long.MaxValue) throw new IOException("Invalid metadata run length.");
            lcn = checked(lcn + delta);
            if (lcn < 0) throw new IOException("Negative physical cluster address.");
            runs.Add(new NtfsDataRun { Vcn = vcn, Lcn = lcn, Clusters = (long)length });
            vcn = checked(vcn + (long)length);
            if (vcn > checked(lastVcn + 1)) throw new IOException("Metadata run exceeds its VCN range.");
        }
        throw new IOException("Missing mapping-pairs terminator.");
    }

    internal static List<NtfsDataRun> Attribute(byte[] record, int p, int length)
    {
        if (length < 64 || record[p + 8] != 1 || BitConverter.ToUInt16(record, p + 12) != 0 || record[p + 34] != 0)
            throw new NotSupportedException("MFT metadata must be nonresident, uncompressed and nonsparse.");
        int pairs = BitConverter.ToUInt16(record, p + 32);
        if (pairs < 64 || pairs >= length) throw new IOException("Invalid mapping-pairs offset.");
        return Decode(record, p + pairs, p + length, BitConverter.ToInt64(record, p + 16), BitConverter.ToInt64(record, p + 24));
    }

    internal static IEnumerable<(int Offset, int Length, uint Type)> Attributes(byte[] record)
    {
        const int start = 12;
        int size = checked((int)BitConverter.ToUInt32(record, 8));
        if (size < 48 || size > record.Length - start) throw new IOException("Invalid bootstrap record size.");
        int used = checked((int)BitConverter.ToUInt32(record, start + 24));
        int offset = BitConverter.ToUInt16(record, start + 20);
        if (used > size || offset < 48 || offset % 8 != 0) throw new IOException("Invalid bootstrap attributes.");
        while (offset <= used - 4)
        {
            int p = start + offset;
            uint type = BitConverter.ToUInt32(record, p);
            if (type == uint.MaxValue) yield break;
            if (used - offset < 24) throw new IOException("Truncated bootstrap attribute.");
            int length = checked((int)BitConverter.ToUInt32(record, p + 4));
            if (length < 24 || length % 8 != 0 || length > used - offset) throw new IOException("Invalid bootstrap attribute length.");
            yield return (p, length, type);
            offset += length;
        }
        throw new IOException("Missing bootstrap terminator.");
    }
}
