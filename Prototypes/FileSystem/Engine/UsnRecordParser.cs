using System.Text;

namespace FileInspectorX.Prototypes.FileSystem;

internal sealed class UsnNode
{
    internal ulong Id { get; }
    internal ulong ParentId { get; }
    internal string Name { get; }
    internal FileAttributes Attributes { get; }
    internal UsnNode(ulong id, ulong parentId, string name, FileAttributes attributes)
    { Id = id; ParentId = parentId; Name = name; Attributes = attributes; }
}

/// <summary>Bounds-checked Windows USN_RECORD_V2 decoder. Full 64-bit identities retain NTFS sequence numbers.</summary>
internal static class UsnRecordParser
{
    internal static IEnumerable<UsnNode> Parse(byte[] buffer, int returned, CancellationToken cancellationToken)
    {
        if (returned < 8 || returned > buffer.Length) throw new IOException("Truncated MFT enumeration header.");
        for (int offset = 8; offset < returned;)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (returned - offset < 60) throw new IOException("Truncated USN record header.");
            uint length = BitConverter.ToUInt32(buffer, offset);
            if (length < 60 || length > returned - offset || length % 8 != 0) throw new IOException("Invalid USN record length.");
            if (BitConverter.ToUInt16(buffer, offset + 4) != 2) throw new NotSupportedException("Only USN_RECORD_V2 is supported by this prototype.");
            int nameLength = BitConverter.ToUInt16(buffer, offset + 56);
            int nameOffset = BitConverter.ToUInt16(buffer, offset + 58);
            if (nameLength == 0 || nameLength % 2 != 0 || nameOffset < 60 || nameOffset > length - nameLength)
                throw new IOException("Invalid USN filename bounds.");
            var name = Encoding.Unicode.GetString(buffer, offset + nameOffset, nameLength);
            ulong id = BitConverter.ToUInt64(buffer, offset + 8);
            ulong parentId = BitConverter.ToUInt64(buffer, offset + 16);
            if ((name == "." && id != parentId) || name == ".." || name.IndexOfAny(new[] { '\\', '/', ':', '\0' }) >= 0)
                throw new IOException("Invalid USN filename component.");
            yield return new UsnNode(id, parentId,
                name, (FileAttributes)BitConverter.ToUInt32(buffer, offset + 52));
            offset += checked((int)length);
        }
    }
}
