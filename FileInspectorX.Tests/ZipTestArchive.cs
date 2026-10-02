using System.IO.Compression;
using System.Text;

namespace FileInspectorX.Tests;

// Small real archives with a ZIP64 footer, without multi-gigabyte fixtures.
// Entry data and central-directory headers are produced by ZipArchive; only
// the end records are widened using the PKWARE APPNOTE record layout.
internal static class ZipTestArchive
{
    internal static byte[] Create(params (string Name, string Content)[] entries)
    {
        using var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, true))
        {
            foreach (var item in entries)
            {
                using var writer = new StreamWriter(archive.CreateEntry(item.Name, CompressionLevel.NoCompression).Open(), new UTF8Encoding(false));
                writer.Write(item.Content);
            }
        }
        return output.ToArray();
    }

    internal static byte[] WithZip64Footer(byte[] classic, string sentinel = "all", byte[]? extension = null)
    {
        var eocd = classic.Length - 22;
        using var source = new BinaryReader(new MemoryStream(classic));
        source.BaseStream.Position = eocd + 10;
        var count = source.ReadUInt16();
        var directorySize = source.ReadUInt32();
        var directoryOffset = source.ReadUInt32();
        using var output = new MemoryStream();
        output.Write(classic, 0, eocd);
        using var writer = new BinaryWriter(output, Encoding.UTF8, true);
        writer.Write(0x06064b50u);
        writer.Write(44UL + (ulong)(extension?.Length ?? 0));
        writer.Write((ushort)45);
        writer.Write((ushort)45);
        writer.Write(0u);
        writer.Write(0u);
        writer.Write((ulong)count);
        writer.Write((ulong)count);
        writer.Write((ulong)directorySize);
        writer.Write((ulong)directoryOffset);
        if (extension != null) writer.Write(extension);
        writer.Write(0x07064b50u);
        writer.Write(0u);
        writer.Write((ulong)eocd);
        writer.Write(1u);
        writer.Write(0x06054b50u);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write(sentinel is "all" or "count" ? ushort.MaxValue : count);
        writer.Write(sentinel is "all" or "count" ? ushort.MaxValue : count);
        writer.Write(sentinel is "all" or "size" ? uint.MaxValue : directorySize);
        writer.Write(sentinel is "all" or "offset" ? uint.MaxValue : directoryOffset);
        writer.Write((ushort)0);
        return output.ToArray();
    }

    internal static void Write64(byte[] bytes, int offset, ulong value)
    {
        for (var index = 0; index < 8; index++) bytes[offset + index] = (byte)(value >> (index * 8));
    }

    internal static void Write32(byte[] bytes, int offset, uint value)
    {
        for (var index = 0; index < 4; index++) bytes[offset + index] = (byte)(value >> (index * 8));
    }

    internal static int LastSignature(byte[] bytes, uint signature)
    {
        for (var index = bytes.Length - 4; index >= 0; index--)
        {
            if ((uint)(bytes[index] | bytes[index + 1] << 8 | bytes[index + 2] << 16 | bytes[index + 3] << 24) == signature)
                return index;
        }
        throw new InvalidOperationException("Fixture signature not found.");
    }
}
