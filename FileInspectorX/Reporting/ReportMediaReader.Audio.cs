using System.Text;

namespace FileInspectorX;

internal static partial class ReportMediaReader
{
    private static void ReadWave(Probe probe)
    {
        var header = probe.Read(0, 12);
        long end = (long)U32(header, 4, true) + 8;
        if (end < 12 || end > probe.Length) throw new InvalidDataException();
        if (end < probe.Length) probe.Issue("media:trailing-bytes-not-inspected");
        ushort encoding = 0, alignment = 0, width = 0, channels = 0;
        uint rate = 0, byteRate = 0;
        long dataBytes = 0, dataOffset = 0;
        bool hasFormat = false, hasData = false, duplicateFormat = false;
        for (long offset = 12; offset < end;)
        {
            probe.Record();
            var chunk = probe.Read(offset, 8);
            var name = Ascii(chunk, 0, 4); long size = U32(chunk, 4, true);
            long payload = offset + 8;
            if (size > end - payload) throw new InvalidDataException();
            if (name == "fmt ")
            {
                if (hasFormat) { duplicateFormat = true; probe.Issue("media:duplicate-wave-format"); }
                if (size < 16) throw new InvalidDataException();
                var format = probe.Read(payload, 16);
                encoding = U16(format, 0); channels = U16(format, 2); rate = U32(format, 4, true);
                byteRate = U32(format, 8, true); alignment = U16(format, 12); width = U16(format, 14);
                if (channels == 0 || rate == 0 || alignment == 0 || byteRate == 0) throw new InvalidDataException();
                probe.Fact("Wave.Encoding", encoding, payload, 2); probe.Fact("Audio.Channels", channels, payload + 2, 2);
                probe.Fact("Audio.SampleRate", rate, payload + 4, 4); probe.Fact("Audio.BitsPerSample", width, payload + 14, 2);
                hasFormat = true;
            }
            else if (name == "data") { dataBytes = checked(dataBytes + size); dataOffset = payload; hasData = true; }
            long next = payload + size + (size & 1);
            if (next > end) throw new InvalidDataException();
            offset = next;
        }
        if (!hasFormat || !hasData) throw new InvalidDataException();
        probe.Fact("Audio.DataBytes", dataBytes, dataOffset, 0, derived: true);
        if (!duplicateFormat && encoding is 1 or 3 && width > 0 && width % 8 == 0 && (long)channels * (width / 8) == alignment && (long)rate * alignment == byteRate && dataBytes % alignment == 0)
            probe.Fact("Audio.DeclaredDurationSeconds", dataBytes / (double)byteRate, dataOffset, 0, derived: true);
        else probe.Issue("media:wave-duration-profile-unsupported");
    }

    private static void ReadFlac(Probe probe)
    {
        long offset = 4; bool first = true, last = false;
        while (!last)
        {
            probe.Record(); var header = probe.Read(offset, 4); last = (header[0] & 128) != 0;
            int type = header[0] & 127, size = header[1] << 16 | header[2] << 8 | header[3];
            long payload = offset + 4;
            if (size > probe.Length - payload) throw new InvalidDataException();
            if (first && (type != 0 || size != 34)) throw new InvalidDataException();
            if (type == 0)
            {
                if (!first || size != 34) throw new InvalidDataException();
                var info = probe.Read(payload, size); var packed = U64(info, 10);
                uint rate = (uint)(packed >> 44); int channels = (int)(packed >> 41 & 7) + 1, width = (int)(packed >> 36 & 31) + 1;
                ulong samples = packed & 0xFFFFFFFFFUL;
                if (rate == 0) throw new InvalidDataException();
                probe.Fact("Audio.SampleRate", rate, payload + 10, 3); probe.Fact("Audio.Channels", channels, payload + 12, 1);
                probe.Fact("Audio.BitsPerSample", width, payload + 12, 2); probe.Fact("Audio.DeclaredSamples", samples, payload + 13, 5);
                if (samples > 0) probe.Fact("Audio.DeclaredDurationSeconds", samples / (double)rate, payload + 10, 8, derived: true);
                else probe.Issue("media:duration-unavailable");
            }
            else if (type == 4) ReadVorbisComments(probe, payload, size);
            first = false; offset = payload + size;
        }
    }

    private static void ReadVorbisComments(Probe probe, long offset, int size)
    {
        var data = probe.Read(offset, size); int position = 0;
        uint ReadLength() { if (position > data.Length - 4) throw new InvalidDataException(); var value = U32(data, position, true); position += 4; return value; }
        var vendor = ReadLength(); if (vendor > data.Length - position) throw new InvalidDataException(); position += (int)vendor;
        uint entries = ReadLength(); if (entries > 4096) throw new MetadataLimitException();
        for (uint i = 0; i < entries; i++)
        {
            probe.Record(); uint length = ReadLength(); if (length > data.Length - position) throw new InvalidDataException();
            var value = new UTF8Encoding(false, true).GetString(data, position, (int)length); int separator = value.IndexOf('=');
            if (separator > 0) probe.Fact("Vorbis." + value.Substring(0, separator).ToUpperInvariant(), value.Substring(separator + 1), offset + position, (int)length);
            position += (int)length;
        }
        if (position != data.Length) probe.Issue("media:vorbis-comment-tail");
    }
}
