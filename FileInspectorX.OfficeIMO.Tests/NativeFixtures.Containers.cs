using System.Globalization;
using System.Text;

namespace FileInspectorX.OfficeIMO.Tests;

internal static partial class NativeFixtures
{
    // One-page synthetic PDF writer, with an optional unsupported filter and one inert attachment.
    internal static byte[] Pdf(bool unsupportedFilter = false, bool attachment = false, bool incorrectLength = false,
        string? xmp = null, bool tagged = false)
    {
        var objects = new List<byte[]>
        {
            Ascii("<< /Type /Catalog /Pages 2 0 R " + (attachment ? "/Names << /EmbeddedFiles << /Names [(payload.bin) 6 0 R] >> >> " : "") + ">>"),
            Ascii("<< /Type /Pages /Count 1 /Kids [3 0 R] >>"),
            Ascii("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 600 200] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"),
            Ascii("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"),
            PdfStream(Ascii("BT /F1 12 Tf 20 100 Td (" + Text + ") Tj ET"), unsupportedFilter ? "/Filter /UnsupportedFixtureFilter" : "", incorrectLength)
        };
        if (attachment)
        {
            objects.Add(Ascii("<< /Type /Filespec /F (payload.bin) /EF << /F 7 0 R >> >>"));
            objects.Add(PdfStream(Encoding.UTF8.GetBytes("Complete attached text"), "/Type /EmbeddedFile"));
        }
        string catalogMetadata = string.Empty;
        if (xmp != null)
        {
            catalogMetadata += "/Metadata " + (objects.Count + 1).ToString(CultureInfo.InvariantCulture) + " 0 R ";
            objects.Add(PdfStream(Encoding.UTF8.GetBytes(xmp), "/Type /Metadata /Subtype /XML"));
        }
        if (tagged)
        {
            int root = objects.Count + 1, element = root + 1;
            catalogMetadata += "/MarkInfo << /Marked true >> /StructTreeRoot " + root + " 0 R ";
            objects.Add(Ascii("<< /Type /StructTreeRoot /K [" + element + " 0 R] >>"));
            objects.Add(Ascii("<< /Type /StructElem /S /P /P " + root + " 0 R /Pg 3 0 R /K 0 >>"));
        }
        objects[0] = Ascii("<< /Type /Catalog /Pages 2 0 R " + catalogMetadata +
            (attachment ? "/Names << /EmbeddedFiles << /Names [(payload.bin) 6 0 R] >> >> " : "") + ">>");
        using var output = new MemoryStream(); Write(output, Ascii("%PDF-1.7\n"));
        var offsets = new List<long>();
        for (int index = 0; index < objects.Count; index++)
        {
            offsets.Add(output.Position); Write(output, Ascii((index + 1).ToString(CultureInfo.InvariantCulture) + " 0 obj\n"));
            Write(output, objects[index]); Write(output, Ascii("\nendobj\n"));
        }
        long xref = output.Position;
        Write(output, Ascii("xref\n0 " + (objects.Count + 1).ToString(CultureInfo.InvariantCulture) + "\n0000000000 65535 f \n"));
        foreach (long offset in offsets) Write(output, Ascii(offset.ToString("D10", CultureInfo.InvariantCulture) + " 00000 n \n"));
        Write(output, Ascii("trailer\n<< /Root 1 0 R /Size " + (objects.Count + 1).ToString(CultureInfo.InvariantCulture) + " >>\nstartxref\n" + xref.ToString(CultureInfo.InvariantCulture) + "\n%%EOF\n"));
        return output.ToArray();
    }
    private static byte[] Ascii(string value) => Encoding.ASCII.GetBytes(value);
    private static void Write(Stream stream, byte[] value) => stream.Write(value, 0, value.Length);
    private static byte[] PdfStream(byte[] value, string dictionary, bool incorrectLength = false) =>
        Ascii("<< " + dictionary + " /Length " + (incorrectLength ? 99999 : value.Length).ToString(CultureInfo.InvariantCulture) + " >>\nstream\n")
            .Concat(value).Concat(Ascii("\nendstream")).ToArray();

    // Bounded one-folder stored CAB writer; no archive reader or extractor is duplicated in this test assembly.
    internal static byte[] Cab(params (string Name, byte[] Data)[] files)
    {
        byte[][] names = files.Select(file => Encoding.ASCII.GetBytes(file.Name + "\0")).ToArray();
        int payloadOffset = 44 + 16 * files.Length + names.Sum(name => name.Length);
        byte[] data = files.SelectMany(file => file.Data).ToArray();
        using var output = new MemoryStream(); using var writer = new BinaryWriter(output);
        writer.Write(Ascii("MSCF")); writer.Write(0); writer.Write(payloadOffset + 8 + data.Length); writer.Write(0);
        writer.Write(44); writer.Write(0); writer.Write((byte)3); writer.Write((byte)1); writer.Write((ushort)1); writer.Write((ushort)files.Length);
        writer.Write((ushort)0); writer.Write((ushort)0); writer.Write((ushort)0);
        writer.Write(payloadOffset); writer.Write((ushort)1); writer.Write((ushort)0);
        int offset = 0;
        for (int index = 0; index < files.Length; index++)
        {
            writer.Write(files[index].Data.Length); writer.Write(offset); writer.Write((ushort)0); writer.Write((ushort)0); writer.Write((ushort)0); writer.Write((ushort)0);
            writer.Write(names[index]); offset += files[index].Data.Length;
        }
        writer.Write(0); writer.Write((ushort)data.Length); writer.Write((ushort)data.Length); writer.Write(data);
        return output.ToArray();
    }
}
