namespace FileInspectorX;

/// <summary>
/// Structurally validated detectors for common binary formats whose short magic values are not
/// sufficient evidence by themselves.
/// </summary>
internal static partial class Signatures
{
    internal static bool TryMatchCommonBinary(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        if (TryMatchPe(src, out result)) return true;
        if (TryMatchPng(src, out result)) return true;
        if (TryMatchGif(src, out result)) return true;
        if (TryMatchPdf(src, out result)) return true;
        if (TryMatchJpeg(src, out result)) return true;
        if (TryMatchBmp(src, out result)) return true;
        if (TryMatchGzip(src, out result)) return true;
        if (TryMatchBzip2(src, out result)) return true;
        if (TryMatchOgg(src, out result)) return true;
        if (TryMatchMp3(src, out result)) return true;
        if (TryMatchWasm(src, out result)) return true;
        if (TryMatchPcapNg(src, out result)) return true;
        if (TryMatchPcap(src, out result)) return true;
        if (TryMatchFlac(src, out result)) return true;
        if (TryMatchCrx(src, out result)) return true;
        if (TryMatchIcon(src, out result)) return true;
        result = null;
        return false;
    }

    internal static bool TryMatchPng(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 33 || !src.Slice(0, 8).SequenceEqual(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A })) return false;
        if (ReadUInt32BigEndian(src, 8) != 13 || !src.Slice(12, 4).SequenceEqual("IHDR"u8)) return false;
        uint width = ReadUInt32BigEndian(src, 16);
        uint height = ReadUInt32BigEndian(src, 20);
        byte bitDepth = src[24];
        byte colorType = src[25];
        bool validDepth = colorType switch
        {
            0 => bitDepth is 1 or 2 or 4 or 8 or 16,
            2 => bitDepth is 8 or 16,
            3 => bitDepth is 1 or 2 or 4 or 8,
            4 or 6 => bitDepth is 8 or 16,
            _ => false
        };
        if (width == 0 || height == 0 || !validDepth || src[26] != 0 || src[27] != 0 || src[28] > 1) return false;
        result = BinaryResult("png", "image/png", "png:signature+ihdr");
        return true;
    }

    internal static bool TryMatchGif(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 13 ||
            (!src.Slice(0, 6).SequenceEqual("GIF87a"u8) && !src.Slice(0, 6).SequenceEqual("GIF89a"u8))) return false;
        ushort width = ReadUInt16LittleEndian(src, 6);
        ushort height = ReadUInt16LittleEndian(src, 8);
        if (width == 0 || height == 0) return false;
        result = BinaryResult("gif", "image/gif", "gif:logical-screen");
        return true;
    }

    internal static bool TryMatchZip(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        int localOffset = src.Length >= 4 && ReadUInt32LittleEndian(src, 0) == 0x08074B50 ? 4 : 0;
        if (src.Length >= localOffset + 30 &&
            TryValidateZipLocalHeader(src.Slice(localOffset, 30), src.Length - localOffset))
        {
            result = BinaryResult("zip", "application/zip",
                localOffset == 0 ? "zip:local-file-header" : "zip:spanning-marker+local-file-header");
            return true;
        }

        if (localOffset != 0) return false;

        if (src.Length < 22 || ReadUInt32LittleEndian(src, 0) != 0x06054B50) return false;
        ushort disk = ReadUInt16LittleEndian(src, 4);
        ushort centralDisk = ReadUInt16LittleEndian(src, 6);
        ushort entriesOnDisk = ReadUInt16LittleEndian(src, 8);
        ushort entriesTotal = ReadUInt16LittleEndian(src, 10);
        uint centralSize = ReadUInt32LittleEndian(src, 12);
        uint centralOffset = ReadUInt32LittleEndian(src, 16);
        ushort commentLength = ReadUInt16LittleEndian(src, 20);
        if (disk != 0 || centralDisk != 0 || entriesOnDisk != entriesTotal ||
            (entriesTotal == 0) != (centralSize == 0 && centralOffset == 0) ||
            22L + commentLength != src.Length) return false;
        result = BinaryResult("zip", "application/zip", "zip:end-of-central-directory");
        return true;
    }

    internal static bool TryMatchZip(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try
        {
            if (stream.Length < 22) return false;
            stream.Seek(0, SeekOrigin.Begin);
            var header = new byte[34];
            int read = ReadHeaderBytes(stream, header);
            var src = new ReadOnlySpan<byte>(header, 0, read);
            int localOffset = read >= 4 && ReadUInt32LittleEndian(src, 0) == 0x08074B50 ? 4 : 0;
            if (read >= localOffset + 30 &&
                TryValidateZipLocalHeader(src.Slice(localOffset, 30), stream.Length - localOffset))
            {
                result = BinaryResult("zip", "application/zip",
                    localOffset == 0 ? "zip:local-file-header" : "zip:spanning-marker+local-file-header");
                return true;
            }
            if (localOffset != 0) return false;
            if (read < 22 || ReadUInt32LittleEndian(src, 0) != 0x06054B50) return false;
            ushort disk = ReadUInt16LittleEndian(src, 4);
            ushort centralDisk = ReadUInt16LittleEndian(src, 6);
            ushort entriesOnDisk = ReadUInt16LittleEndian(src, 8);
            ushort entriesTotal = ReadUInt16LittleEndian(src, 10);
            uint centralSize = ReadUInt32LittleEndian(src, 12);
            uint centralOffset = ReadUInt32LittleEndian(src, 16);
            ushort commentLength = ReadUInt16LittleEndian(src, 20);
            if (disk != 0 || centralDisk != 0 || entriesOnDisk != entriesTotal ||
                (entriesTotal == 0) != (centralSize == 0 && centralOffset == 0) ||
                22L + commentLength != stream.Length) return false;
            result = BinaryResult("zip", "application/zip", "zip:end-of-central-directory");
            return true;
        }
        catch
        {
            result = null;
            return false;
        }
        finally
        {
            try { stream.Seek(originalPosition, SeekOrigin.Begin); } catch { }
        }
    }

    internal static bool TryMatchOle2(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 512 || !src.Slice(0, 8).SequenceEqual(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 })) return false;
        for (int i = 8; i < 24; i++) if (src[i] != 0) return false;
        ushort major = ReadUInt16LittleEndian(src, 26);
        ushort byteOrder = ReadUInt16LittleEndian(src, 28);
        ushort sectorShift = ReadUInt16LittleEndian(src, 30);
        ushort miniSectorShift = ReadUInt16LittleEndian(src, 32);
        for (int i = 34; i < 40; i++) if (src[i] != 0) return false;
        uint directorySectorCount = ReadUInt32LittleEndian(src, 40);
        uint fatSectorCount = ReadUInt32LittleEndian(src, 44);
        uint firstDirectorySector = ReadUInt32LittleEndian(src, 48);
        if (major is not (3 or 4) || byteOrder != 0xFFFE ||
            (major == 3 ? sectorShift != 9 : sectorShift != 12) || miniSectorShift != 6 ||
            (major == 3 && directorySectorCount != 0) || fatSectorCount == 0 || firstDirectorySector >= 0xFFFFFFFA) return false;
        result = BinaryResult("ole2", "application/vnd.ms-office", "ole2:compound-file-header");
        return true;
    }

    private static bool IsKnownZipMethod(ushort method)
        => method is 0 or 1 or 2 or 3 or 4 or 5 or 6 or 8 or 9 or 10 or 12 or 14 or 16 or 18 or 19 or 20 or
                     93 or 94 or 95 or 96 or 97 or 98 or 99;

    private static bool TryValidateZipLocalHeader(ReadOnlySpan<byte> header, long availableLength)
    {
        if (header.Length < 30 || ReadUInt32LittleEndian(header, 0) != 0x04034B50) return false;
        ushort versionNeeded = ReadUInt16LittleEndian(header, 4);
        ushort flags = ReadUInt16LittleEndian(header, 6);
        ushort method = ReadUInt16LittleEndian(header, 8);
        ushort nameLength = ReadUInt16LittleEndian(header, 26);
        ushort extraLength = ReadUInt16LittleEndian(header, 28);
        return versionNeeded is >= 10 and <= 100 && (flags & 0xC000) == 0 && IsKnownZipMethod(method) &&
               nameLength > 0 && 30L + nameLength + extraLength <= availableLength;
    }

    private static int ReadHeaderBytes(Stream stream, byte[] buffer)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = stream.Read(buffer, total, buffer.Length - total);
            if (read <= 0) break;
            total += read;
        }
        return total;
    }

    internal static bool TryMatchPe(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 0x40 || src[0] != (byte)'M' || src[1] != (byte)'Z') return false;
        uint peOffset = ReadUInt32LittleEndian(src, 0x3C);
        if (peOffset < 0x40 || peOffset > int.MaxValue || peOffset + 26L > src.Length) return false;
        return TryValidatePeHeader(src.Slice((int)peOffset), peOffset, src.Length, out result);
    }

    internal static bool TryMatchPe(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try
        {
            if (stream.Length < 0x40 || !TryReadAt(stream, 0, 0x40, out var dosHeader)) return false;
            var dos = new ReadOnlySpan<byte>(dosHeader);
            if (dos[0] != (byte)'M' || dos[1] != (byte)'Z') return false;
            uint peOffset = ReadUInt32LittleEndian(dos, 0x3C);
            if (peOffset < 0x40 || peOffset + 26L > stream.Length ||
                !TryReadAt(stream, peOffset, 26, out var peHeader)) return false;
            return TryValidatePeHeader(new ReadOnlySpan<byte>(peHeader), peOffset, stream.Length, out result);
        }
        catch
        {
            result = null;
            return false;
        }
        finally
        {
            try { stream.Seek(originalPosition, SeekOrigin.Begin); } catch { }
        }
    }

    private static bool TryValidatePeHeader(ReadOnlySpan<byte> peHeader, long peOffset, long totalLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (peHeader.Length < 26 || peHeader[0] != (byte)'P' || peHeader[1] != (byte)'E' || peHeader[2] != 0 || peHeader[3] != 0) return false;

        ushort machine = ReadUInt16LittleEndian(peHeader, 4);
        ushort sections = ReadUInt16LittleEndian(peHeader, 6);
        ushort optionalHeaderSize = ReadUInt16LittleEndian(peHeader, 20);
        ushort characteristics = ReadUInt16LittleEndian(peHeader, 22);
        if (machine == 0 || sections is < 1 or > 96 || optionalHeaderSize < 2 || peOffset + 24L + optionalHeaderSize > totalLength) return false;

        ushort optionalMagic = ReadUInt16LittleEndian(peHeader, 24);
        if (optionalMagic != 0x10B && optionalMagic != 0x20B) return false;
        string extension = (characteristics & 0x2000) != 0 ? "dll" : "exe";
        result = new ContentTypeDetectionResult
        {
            Extension = extension,
            MimeType = "application/x-msdownload",
            Confidence = "High",
            Reason = optionalMagic == 0x20B ? "pe:pe32+" : "pe:pe32"
        };
        return true;
    }

    internal static bool TryMatchPdf(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 8 || !src.Slice(0, 5).SequenceEqual("%PDF-"u8)) return false;
        if (src[5] is < (byte)'1' or > (byte)'2' || src[6] != (byte)'.' || src[7] is < (byte)'0' or > (byte)'9') return false;
        result = BinaryResult("pdf", "application/pdf", "pdf:header");
        return true;
    }

    internal static bool TryMatchJpeg(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 6 || src[0] != 0xFF || src[1] != 0xD8 || src[2] != 0xFF) return false;
        int markerOffset = 2;
        while (markerOffset < src.Length && src[markerOffset] == 0xFF) markerOffset++;
        if (markerOffset >= src.Length) return false;
        byte marker = src[markerOffset];
        if (marker == 0 || marker == 0xD8 || marker == 0xD9) return false;
        if (marker != 0x01 && marker is not (>= 0xD0 and <= 0xD7))
        {
            if (markerOffset + 3 > src.Length) return false;
            ushort segmentLength = ReadUInt16BigEndian(src, markerOffset + 1);
            if (segmentLength < 2) return false;
        }
        result = BinaryResult("jpg", "image/jpeg", "jpeg:soi+marker");
        return true;
    }

    internal static bool TryMatchBmp(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 26 || src[0] != (byte)'B' || src[1] != (byte)'M') return false;
        uint fileSize = ReadUInt32LittleEndian(src, 2);
        uint pixelOffset = ReadUInt32LittleEndian(src, 10);
        uint dibSize = ReadUInt32LittleEndian(src, 14);
        if (fileSize < 26 || pixelOffset < 14 + dibSize || pixelOffset > fileSize) return false;
        if (dibSize is not (12u or 16u or 40u or 52u or 56u or 64u or 108u or 124u)) return false;
        result = BinaryResult("bmp", "image/bmp", "bmp:file+dib-header");
        return true;
    }

    internal static bool TryMatchGzip(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 10 || src[0] != 0x1F || src[1] != 0x8B || src[2] != 8 || (src[3] & 0xE0) != 0) return false;
        result = BinaryResult("gz", "application/gzip", "gzip:member-header");
        return true;
    }

    internal static bool TryMatchBzip2(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 10 || src[0] != (byte)'B' || src[1] != (byte)'Z' || src[2] != (byte)'h' || src[3] is < (byte)'1' or > (byte)'9') return false;
        bool block = src.Slice(4, 6).SequenceEqual(new byte[] { 0x31, 0x41, 0x59, 0x26, 0x53, 0x59 });
        bool end = src.Slice(4, 6).SequenceEqual(new byte[] { 0x17, 0x72, 0x45, 0x38, 0x50, 0x90 });
        if (!block && !end) return false;
        result = BinaryResult("bz2", "application/x-bzip2", "bzip2:stream-header");
        return true;
    }

    internal static bool TryMatchOgg(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 27 || !src.Slice(0, 4).SequenceEqual("OggS"u8) || src[4] != 0 || (src[5] & 0xF8) != 0) return false;
        int segmentCount = src[26];
        if (27 + segmentCount > src.Length) return false;
        result = BinaryResult("ogg", "application/ogg", "ogg:page-header");
        return true;
    }

    internal static bool TryMatchMp3(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 10 || !src.Slice(0, 3).SequenceEqual("ID3"u8)) return false;
        if (src[3] is < 2 or > 4 || src[4] == 0xFF || (src[6] & 0x80) != 0 || (src[7] & 0x80) != 0 || (src[8] & 0x80) != 0 || (src[9] & 0x80) != 0) return false;
        byte allowedFlags = src[3] switch { 2 => 0xC0, 3 => 0xE0, _ => 0xF0 };
        if ((src[5] & ~allowedFlags) != 0) return false;
        result = BinaryResult("mp3", "audio/mpeg", $"mp3:id3v2.{src[3]}");
        return true;
    }

    internal static bool TryMatchWasm(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 8 || !src.Slice(0, 4).SequenceEqual(new byte[] { 0, 0x61, 0x73, 0x6D }) || ReadUInt32LittleEndian(src, 4) != 1) return false;
        result = BinaryResult("wasm", "application/wasm", "wasm:version=1");
        return true;
    }

    internal static bool TryMatchPcap(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 24) return false;
        uint magic = ReadUInt32BigEndian(src, 0);
        bool littleEndian;
        bool nanoseconds;
        if (magic == 0xD4C3B2A1) { littleEndian = true; nanoseconds = false; }
        else if (magic == 0xA1B2C3D4) { littleEndian = false; nanoseconds = false; }
        else if (magic == 0x4D3CB2A1) { littleEndian = true; nanoseconds = true; }
        else if (magic == 0xA1B23C4D) { littleEndian = false; nanoseconds = true; }
        else return false;
        ushort major = ReadUInt16(src, 4, littleEndian);
        ushort minor = ReadUInt16(src, 6, littleEndian);
        uint snapLength = ReadUInt32(src, 16, littleEndian);
        if (major != 2 || minor != 4 || snapLength == 0 || snapLength > 0x10000000) return false;
        result = BinaryResult("pcap", "application/vnd.tcpdump.pcap", nanoseconds ? "pcap:nanosecond" : "pcap:microsecond");
        return true;
    }

    internal static bool TryMatchPcapNg(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 28 || ReadUInt32BigEndian(src, 0) != 0x0A0D0D0A) return false;
        uint byteOrder = ReadUInt32BigEndian(src, 8);
        bool littleEndian;
        if (byteOrder == 0x4D3C2B1A) littleEndian = true;
        else if (byteOrder == 0x1A2B3C4D) littleEndian = false;
        else return false;
        uint blockLength = ReadUInt32(src, 4, littleEndian);
        ushort major = ReadUInt16(src, 12, littleEndian);
        ushort minor = ReadUInt16(src, 14, littleEndian);
        if (blockLength < 28 || (blockLength & 3) != 0 || blockLength > src.Length || major != 1 || minor != 0) return false;
        if (ReadUInt32(src, checked((int)blockLength - 4), littleEndian) != blockLength) return false;
        result = BinaryResult("pcapng", "application/x-pcapng", "pcapng:section-header");
        return true;
    }

    internal static bool TryMatchPcapNg(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try
        {
            if (stream.Length < 28 || !TryReadAt(stream, 0, 16, out var headerBytes)) return false;
            var header = new ReadOnlySpan<byte>(headerBytes);
            if (ReadUInt32BigEndian(header, 0) != 0x0A0D0D0A) return false;
            uint byteOrder = ReadUInt32BigEndian(header, 8);
            bool littleEndian;
            if (byteOrder == 0x4D3C2B1A) littleEndian = true;
            else if (byteOrder == 0x1A2B3C4D) littleEndian = false;
            else return false;
            uint blockLength = ReadUInt32(header, 4, littleEndian);
            ushort major = ReadUInt16(header, 12, littleEndian);
            ushort minor = ReadUInt16(header, 14, littleEndian);
            if (blockLength < 28 || (blockLength & 3) != 0 || blockLength > stream.Length ||
                major != 1 || minor != 0 ||
                !TryReadAt(stream, blockLength - 4L, 4, out var trailerBytes) ||
                ReadUInt32(new ReadOnlySpan<byte>(trailerBytes), 0, littleEndian) != blockLength) return false;
            result = BinaryResult("pcapng", "application/x-pcapng", "pcapng:section-header");
            return true;
        }
        catch
        {
            result = null;
            return false;
        }
        finally
        {
            try { stream.Seek(originalPosition, SeekOrigin.Begin); } catch { }
        }
    }

    internal static bool TryMatchFlac(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 42 || !src.Slice(0, 4).SequenceEqual("fLaC"u8)) return false;
        if ((src[4] & 0x7F) != 0 || ReadUInt24BigEndian(src, 5) != 34) return false;
        uint sampleRate = (uint)((src[18] << 12) | (src[19] << 4) | (src[20] >> 4));
        if (sampleRate == 0) return false;
        result = BinaryResult("flac", "audio/flac", "flac:streaminfo");
        return true;
    }

    internal static bool TryMatchCrx(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 12 || !src.Slice(0, 4).SequenceEqual("Cr24"u8)) return false;
        uint version = ReadUInt32LittleEndian(src, 4);
        long headerEnd;
        if (version == 2)
        {
            if (src.Length < 16) return false;
            headerEnd = 16L + ReadUInt32LittleEndian(src, 8) + ReadUInt32LittleEndian(src, 12);
        }
        else if (version == 3)
        {
            headerEnd = 12L + ReadUInt32LittleEndian(src, 8);
        }
        else return false;
        if (headerEnd > int.MaxValue || headerEnd > src.Length ||
            !TryMatchZip(src.Slice((int)headerEnd), out _)) return false;
        result = BinaryResult("crx", "application/x-chrome-extension", $"crx:version={version}");
        return true;
    }

    internal static bool TryMatchCrx(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try
        {
            if (stream.Length < 12 || !TryReadAt(stream, 0, (int)Math.Min(16, stream.Length), out var headerBytes)) return false;
            var header = new ReadOnlySpan<byte>(headerBytes);
            if (!header.Slice(0, 4).SequenceEqual("Cr24"u8)) return false;
            uint version = ReadUInt32LittleEndian(header, 4);
            long headerEnd;
            if (version == 2)
            {
                if (header.Length < 16) return false;
                headerEnd = 16L + ReadUInt32LittleEndian(header, 8) + ReadUInt32LittleEndian(header, 12);
            }
            else if (version == 3) headerEnd = 12L + ReadUInt32LittleEndian(header, 8);
            else return false;

            if (headerEnd < 12 || headerEnd + 30L > stream.Length ||
                !TryReadAt(stream, headerEnd, 30, out var zipHeader) ||
                !TryValidateZipLocalHeader(new ReadOnlySpan<byte>(zipHeader), stream.Length - headerEnd)) return false;
            result = BinaryResult("crx", "application/x-chrome-extension", $"crx:version={version}");
            return true;
        }
        catch
        {
            result = null;
            return false;
        }
        finally
        {
            try { stream.Seek(originalPosition, SeekOrigin.Begin); } catch { }
        }
    }

    internal static bool TryMatchIcon(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 22 || ReadUInt16LittleEndian(src, 0) != 0) return false;
        ushort type = ReadUInt16LittleEndian(src, 2);
        ushort count = ReadUInt16LittleEndian(src, 4);
        if (type is not (1 or 2) || count is < 1 or > 1024 || 6L + count * 16L > src.Length) return false;
        uint firstSize = ReadUInt32LittleEndian(src, 14);
        uint firstOffset = ReadUInt32LittleEndian(src, 18);
        if (firstSize == 0 || firstOffset < 6 + count * 16u) return false;
        string extension = type == 1 ? "ico" : "cur";
        result = BinaryResult(extension, type == 1 ? "image/x-icon" : "image/x-win-bitmap", $"icon-directory:{extension}");
        return true;
    }

    private static ContentTypeDetectionResult BinaryResult(string extension, string mimeType, string reason)
        => new() { Extension = extension, MimeType = mimeType, Confidence = "High", Reason = reason };

    private static ushort ReadUInt16LittleEndian(ReadOnlySpan<byte> src, int offset)
        => (ushort)(src[offset] | src[offset + 1] << 8);

    private static ushort ReadUInt16(ReadOnlySpan<byte> src, int offset, bool littleEndian)
        => littleEndian ? ReadUInt16LittleEndian(src, offset) : ReadUInt16BigEndian(src, offset);

    private static uint ReadUInt32LittleEndian(ReadOnlySpan<byte> src, int offset)
        => (uint)(src[offset] | src[offset + 1] << 8 | src[offset + 2] << 16 | src[offset + 3] << 24);

    private static uint ReadUInt24BigEndian(ReadOnlySpan<byte> src, int offset)
        => (uint)(src[offset] << 16 | src[offset + 1] << 8 | src[offset + 2]);

    private static ulong ReadUInt64(ReadOnlySpan<byte> src, int offset, bool littleEndian)
    {
        ulong value = 0;
        if (littleEndian)
        {
            for (int i = 7; i >= 0; i--) value = (value << 8) | src[offset + i];
        }
        else
        {
            for (int i = 0; i < 8; i++) value = (value << 8) | src[offset + i];
        }
        return value;
    }
}
