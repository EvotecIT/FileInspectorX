using System.Text;

namespace FileInspectorX;

internal static partial class ReportMediaReader
{
    private static int Synchsafe(byte[] data, int offset)
    {
        for (int i = 0; i < 4; i++) if ((data[offset + i] & 128) != 0) throw new InvalidDataException();
        return data[offset] << 21 | data[offset + 1] << 14 | data[offset + 2] << 7 | data[offset + 3];
    }

    private static void ReadId3(Probe probe)
    {
        var header = probe.Read(0, 10); int version = header[3], flags = header[5], size = Synchsafe(header, 6);
        long end = 10L + size;
        if (end > probe.Length) throw new InvalidDataException();
        probe.Fact("Id3.Version", version, 3, 1); probe.Fact("Id3.DeclaredTagBytes", size, 6, 4);
        if (version is not (2 or 3 or 4)) { probe.Issue("media:id3-version-unsupported"); return; }
        int reservedFlags = version == 4 ? flags & 15 : version == 3 ? flags & 31 : flags & 63;
        if (reservedFlags != 0) { probe.Issue("media:id3-header-flags-unsupported"); return; }
        if ((flags & 128) != 0 || version == 2 && (flags & 64) != 0)
        { probe.Issue("media:id3-unsynchronized-or-compressed-tag"); return; }
        long offset = 10;
        if (version >= 3 && (flags & 64) != 0)
        {
            var extended = probe.Read(offset, 4);
            long extensionSize = version == 3 ? (long)U32(extended, 0) + 4 : Synchsafe(extended, 0);
            if (extensionSize < 6 || extensionSize > end - offset) throw new InvalidDataException();
            offset += extensionSize;
        }
        int index = 0, frameHeaderSize = version == 2 ? 6 : 10, idBytes = version == 2 ? 3 : 4;
        while (offset < end)
        {
            probe.Record();
            if (end - offset < frameHeaderSize)
            {
                if (probe.Read(offset, checked((int)(end - offset))).Any(value => value != 0)) probe.Issue("media:id3-frame-tail");
                break;
            }
            var frame = probe.Read(offset, frameHeaderSize);
            if (frame.Take(idBytes).All(value => value == 0)) break;
            if (frame.Take(idBytes).Any(value => !(value is >= (byte)'A' and <= (byte)'Z' or >= (byte)'0' and <= (byte)'9')))
                throw new InvalidDataException();
            string name = Ascii(frame, 0, idBytes);
            long length = version == 2 ? frame[3] << 16 | frame[4] << 8 | frame[5] : version == 4 ? Synchsafe(frame, 4) : U32(frame, 4);
            long payload = offset + frameHeaderSize;
            if (length > end - payload) throw new InvalidDataException();
            int frameFlags = version == 2 ? 0 : frame[8] << 8 | frame[9];
            int unsupported = version == 3 ? frameFlags & 0x1FFF : frameFlags & 0x8FFF;
            if (version == 2) unsupported = 0;
            if (unsupported != 0) probe.Issue("media:id3-frame-transform-unsupported");
            else if (name.StartsWith("T", StringComparison.Ordinal) && length > 0)
            {
                if (length > int.MaxValue) throw new MetadataLimitException();
                var data = probe.Read(payload, (int)length);
                if (version < 4 && data[0] > 1) probe.Issue("media:id3-text-encoding-outside-version-profile");
                string? text = DecodeId3Text(data);
                if (text == null) probe.Issue("media:id3-text-encoding-unsupported");
                else probe.Fact("Id3." + name, text.TrimEnd('\0'), payload, data.Length,
                    "frame[" + index.ToString(System.Globalization.CultureInfo.InvariantCulture) + "]");
            }
            else if (length > 0) probe.Issue("media:id3-nontext-frame-not-inspected");
            index++; offset = payload + length;
        }
        if (version == 4 && (flags & 16) != 0)
        {
            var footer = probe.Read(end, 10);
            if (Ascii(footer, 0, 3) != "3DI" || footer[3] != version || Synchsafe(footer, 6) != size) throw new InvalidDataException();
        }
    }

    private static string? DecodeId3Text(byte[] data)
    {
        if (data.Length == 0) return string.Empty;
        switch (data[0])
        {
            case 0:
                var chars = new char[data.Length - 1]; for (int i = 0; i < chars.Length; i++) chars[i] = (char)data[i + 1];
                return new string(chars);
            case 1:
                if (data.Length < 3) throw new InvalidDataException();
                if (data[1] == 255 && data[2] == 254) return new UnicodeEncoding(false, false, true).GetString(data, 3, data.Length - 3);
                if (data[1] == 254 && data[2] == 255) return new UnicodeEncoding(true, false, true).GetString(data, 3, data.Length - 3);
                throw new InvalidDataException();
            case 2: return new UnicodeEncoding(true, false, true).GetString(data, 1, data.Length - 1);
            case 3: return new UTF8Encoding(false, true).GetString(data, 1, data.Length - 1);
            default: return null;
        }
    }
}
