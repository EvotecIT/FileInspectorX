namespace FileInspectorX;

/// <summary>
/// Structurally validated detectors for common binary formats whose short magic values are not
/// sufficient evidence by themselves.
/// </summary>
internal static partial class Signatures
{
    internal static bool TryMatchCommonBinary(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchCommonBinary(src, src.Length, out result);

    internal static bool TryMatchCommonBinary(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        if (TryMatchPe(src, out result)) return true;
        if (TryMatchPng(src, completeLength, out result)) return true;
        if (TryMatchGif(src, out result)) return true;
        if (TryMatchPdf(src, out result)) return true;
        if (TryMatchJpeg(src, completeLength, out result)) return true;
        if (TryMatchBmp(src, completeLength, out result)) return true;
        if (TryMatchGzip(src, completeLength, out result)) return true;
        if (TryMatchBzip2(src, completeLength, out result)) return true;
        if (TryMatchOgg(src, completeLength, out result)) return true;
        if (TryMatchMp3(src, completeLength, out result)) return true;
        if (TryMatchWasm(src, out result)) return true;
        if (TryMatchPcapNg(src, out result)) return true;
        if (TryMatchPcap(src, completeLength, out result)) return true;
        if (TryMatchFlac(src, out result)) return true;
        if (TryMatchCrx(src, out result)) return true;
        if (TryMatchIcon(src, out result)) return true;
        result = null;
        return false;
    }

    internal static bool TryMatchPng(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchPng(src, src.Length, out result);

    internal static bool TryMatchPng(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
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
        if (ReadUInt32BigEndian(src, 29) != ComputePngCrc(src.Slice(12, 17))) return false;
        bool complete = false;
        bool sawIdat = false;
        bool idatSequenceEnded = false;
        bool sawPlte = false;
        int idatBudget = Math.Max(256, Settings.DetectionReadBudgetBytes);
        using var idat = new MemoryStream();
        bool idatBudgetExceeded = false;
        int cursor = 8;
        while (cursor + 12 <= src.Length)
        {
            uint length = ReadUInt32BigEndian(src, cursor);
            if (length > int.MaxValue || (ulong)cursor + 12 + length > (ulong)src.Length) break;
            int chunkLength = (int)length;
            var typeAndData = src.Slice(cursor + 4, 4 + chunkLength);
            if (ReadUInt32BigEndian(src, cursor + 8 + chunkLength) != ComputePngCrc(typeAndData)) return false;
            uint type = ReadUInt32BigEndian(src, cursor + 4);
            if (cursor == 8 && type != 0x49484452) return false;
            if (cursor != 8 && type == 0x49484452) return false;
            if (type == 0x504C5445)
            {
                if (sawPlte || sawIdat || colorType is 0 or 4 || chunkLength == 0 || chunkLength > 768 || chunkLength % 3 != 0) return false;
                int paletteEntries = chunkLength / 3;
                if (colorType == 3 && paletteEntries > 1 << bitDepth) return false;
                sawPlte = true;
            }
            if (type == 0x49444154)
            {
                if (idatSequenceEnded || colorType == 3 && !sawPlte) return false;
                sawIdat = true;
                if (!idatBudgetExceeded)
                {
                    if (idat.Length + chunkLength > idatBudget)
                    {
                        idatBudgetExceeded = true;
                    }
                    else if (chunkLength > 0)
                    {
                        byte[] chunk = src.Slice(cursor + 8, chunkLength).ToArray();
                        idat.Write(chunk, 0, chunk.Length);
                    }
                }
            }
            else if (sawIdat && type != 0x49454E44)
            {
                idatSequenceEnded = true;
            }
            cursor += 12 + chunkLength;
            if (type == 0x49454E44)
            {
                if (chunkLength != 0 || !sawIdat || (completeLength.HasValue && cursor != completeLength.Value)) return false;
                complete = true;
                break;
            }
        }
        if (completeLength.HasValue && completeLength.Value <= src.Length && !complete) return false;
        bool fullyBounded = complete && completeLength.HasValue && cursor == completeLength.Value;
        PngIdatValidation idatValidation = fullyBounded
            ? ValidatePngIdat(idat.ToArray(), idatBudgetExceeded, width, height, bitDepth, colorType, src[28], idatBudget)
            : PngIdatValidation.BudgetOrUnsupported;
        if (fullyBounded && idatValidation == PngIdatValidation.Invalid) return false;
        bool fullyValidated = fullyBounded && idatValidation == PngIdatValidation.Valid;
        result = BinaryResult("png", "image/png", fullyValidated ? "png:chunks+idat+iend" :
            fullyBounded ? "png:chunks+iend;idat-budget-or-interlace" : "png:signature+ihdr;sampled-chunks");
        if (!fullyValidated) result.Confidence = "Medium";
        return true;
    }

    private enum PngIdatValidation
    {
        Invalid,
        BudgetOrUnsupported,
        Valid
    }

    private static PngIdatValidation ValidatePngIdat(byte[] idat, bool budgetExceeded, uint width, uint height,
        byte bitDepth, byte colorType, byte interlace, int budget)
    {
        if (budgetExceeded || interlace != 0) return PngIdatValidation.BudgetOrUnsupported;
        if (idat.Length < 7) return PngIdatValidation.Invalid;
        int header = idat[0] << 8 | idat[1];
        if ((idat[0] & 0x0F) != 8 || (idat[0] >> 4) > 7 || header % 31 != 0 || (idat[1] & 0x20) != 0)
            return PngIdatValidation.Invalid;

        int channels = colorType switch { 0 => 1, 2 => 3, 3 => 1, 4 => 2, 6 => 4, _ => 0 };
        ulong rowBytes = ((ulong)width * (uint)channels * bitDepth + 7) / 8;
        ulong expectedLength = (rowBytes + 1) * height;
        if (channels == 0 || expectedLength == 0 || expectedLength > (ulong)budget || expectedLength > int.MaxValue)
            return PngIdatValidation.BudgetOrUnsupported;

        var decoded = new byte[(int)expectedLength];
        try
        {
            using var compressed = new MemoryStream(idat, 2, idat.Length - 6, writable: false);
            using var inflater = new System.IO.Compression.DeflateStream(
                compressed, System.IO.Compression.CompressionMode.Decompress, leaveOpen: false);
            int read = 0;
            while (read < decoded.Length)
            {
                int count = inflater.Read(decoded, read, decoded.Length - read);
                if (count == 0) return PngIdatValidation.Invalid;
                read += count;
            }
            if (inflater.ReadByte() != -1) return PngIdatValidation.Invalid;
        }
        catch (IOException)
        {
            return PngIdatValidation.Invalid;
        }

        int rowStride = checked((int)rowBytes + 1);
        for (int row = 0; row < (int)height; row++)
            if (decoded[row * rowStride] > 4) return PngIdatValidation.Invalid;

        uint storedAdler = (uint)idat[idat.Length - 4] << 24 | (uint)idat[idat.Length - 3] << 16 |
                           (uint)idat[idat.Length - 2] << 8 | idat[idat.Length - 1];
        return storedAdler == ComputePngAdler32(decoded) ? PngIdatValidation.Valid : PngIdatValidation.Invalid;
    }

    private static uint ComputePngAdler32(ReadOnlySpan<byte> data)
    {
        const uint modulus = 65521;
        uint a = 1, b = 0;
        for (int index = 0; index < data.Length; index++)
        {
            a = (a + data[index]) % modulus;
            b = (b + a) % modulus;
        }
        return b << 16 | a;
    }

    private static uint ComputePngCrc(ReadOnlySpan<byte> data)
    {
        uint crc = uint.MaxValue;
        for (int index = 0; index < data.Length; index++)
        {
            crc ^= data[index];
            for (int bit = 0; bit < 8; bit++) crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        }
        return ~crc;
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
        => TryMatchZip(src, src.Length, out result);

    internal static bool TryMatchZip(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        int localOffset = src.Length >= 4 && ReadUInt32LittleEndian(src, 0) == 0x08074B50 ? 4 : 0;
        if (src.Length >= localOffset + 30 &&
            TryValidateZipLocalHeader(src.Slice(localOffset), completeLength.HasValue ? completeLength.Value - localOffset : null,
                src.Length - localOffset, out bool sampledHeader))
        {
            string reason = localOffset == 0 ? "zip:local-file-header" : "zip:spanning-marker+local-file-header";
            result = new ContentTypeDetectionResult {
                Extension = "zip",
                MimeType = "application/zip",
                Confidence = sampledHeader ? "Medium" : "High",
                Reason = sampledHeader ? reason + ";sampled-variable-header" : reason
            };
            return true;
        }

        if (localOffset != 0) return false;

        if (!completeLength.HasValue || src.Length < 22 || ReadUInt32LittleEndian(src, 0) != 0x06054B50) return false;
        ushort disk = ReadUInt16LittleEndian(src, 4);
        ushort centralDisk = ReadUInt16LittleEndian(src, 6);
        ushort entriesOnDisk = ReadUInt16LittleEndian(src, 8);
        ushort entriesTotal = ReadUInt16LittleEndian(src, 10);
        uint centralSize = ReadUInt32LittleEndian(src, 12);
        uint centralOffset = ReadUInt32LittleEndian(src, 16);
        ushort commentLength = ReadUInt16LittleEndian(src, 20);
        if (disk != 0 || centralDisk != 0 || entriesOnDisk != entriesTotal ||
            entriesTotal != 0 || centralSize != 0 || centralOffset != 0 ||
            22L + commentLength != completeLength.Value) return false;
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
            var header = new byte[34];
            stream.Seek(0, SeekOrigin.Begin);
            int read = ReadHeaderBytes(stream, header);
            var src = new ReadOnlySpan<byte>(header, 0, read);
            int localOffset = read >= 4 && ReadUInt32LittleEndian(src, 0) == 0x08074B50 ? 4 : 0;
            if (read >= localOffset + 30)
            {
                int variableEnd = localOffset + 30 + ReadUInt16LittleEndian(src, localOffset + 26) + ReadUInt16LittleEndian(src, localOffset + 28);
                int budget = Math.Max(34, Settings.DetectionReadBudgetBytes);
                if (variableEnd > read && variableEnd <= budget && variableEnd <= stream.Length && TryReadAt(stream, 0, variableEnd, out var completeHeader))
                {
                    header = completeHeader;
                    read = header.Length;
                    src = new ReadOnlySpan<byte>(header);
                }
            }
            if (read >= localOffset + 30 &&
                TryValidateZipLocalHeader(src.Slice(localOffset), stream.Length - localOffset, read - localOffset, out _))
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
                entriesTotal != 0 || centralSize != 0 || centralOffset != 0 ||
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
        => TryValidateZipLocalHeader(header, availableLength, header.Length, out _);

    private static bool TryValidateZipLocalHeader(ReadOnlySpan<byte> header, long? availableLength, long sampledLength, out bool sampledHeader)
    {
        sampledHeader = false;
        if (header.Length < 30 || ReadUInt32LittleEndian(header, 0) != 0x04034B50) return false;
        ushort versionNeeded = ReadUInt16LittleEndian(header, 4);
        ushort flags = ReadUInt16LittleEndian(header, 6);
        ushort method = ReadUInt16LittleEndian(header, 8);
        uint compressedSize32 = ReadUInt32LittleEndian(header, 18);
        uint uncompressedSize32 = ReadUInt32LittleEndian(header, 22);
        ushort nameLength = ReadUInt16LittleEndian(header, 26);
        ushort extraLength = ReadUInt16LittleEndian(header, 28);
        if (versionNeeded is < 10 or > 100 || (flags & 0xC000) != 0 || !IsKnownZipMethod(method) || nameLength == 0) return false;
        long requiredLength = 30L + nameLength + extraLength;
        if ((flags & 0x0008) == 0)
        {
            ulong compressedSize = compressedSize32;
            if (compressedSize32 == uint.MaxValue)
            {
                if (versionNeeded < 45 || requiredLength > header.Length ||
                    !TryReadZip64CompressedSize(header.Slice(30 + nameLength, extraLength),
                        uncompressedSize32 == uint.MaxValue, out compressedSize)) return false;
            }
            if (compressedSize > long.MaxValue || requiredLength > long.MaxValue - (long)compressedSize) return false;
            requiredLength += (long)compressedSize;
        }
        else
        {
            const int minimumDataDescriptorLength = 12;
            if (availableLength.HasValue)
            {
                if (requiredLength > availableLength.Value - minimumDataDescriptorLength) return false;
            }
            else
            {
                sampledHeader = true;
            }
        }
        if (availableLength.HasValue) return requiredLength <= availableLength.Value;
        sampledHeader |= requiredLength > sampledLength;
        return true;
    }

    private static bool TryReadZip64CompressedSize(ReadOnlySpan<byte> extra, bool hasZip64UncompressedSize, out ulong compressedSize)
    {
        compressedSize = 0;
        int cursor = 0;
        while (cursor + 4 <= extra.Length)
        {
            ushort id = ReadUInt16LittleEndian(extra, cursor);
            ushort length = ReadUInt16LittleEndian(extra, cursor + 2);
            cursor += 4;
            if (length > extra.Length - cursor) return false;
            if (id == 0x0001)
            {
                int valueOffset = hasZip64UncompressedSize ? 8 : 0;
                if (length < valueOffset + 8) return false;
                compressedSize = ReadUInt64(extra, cursor + valueOffset, littleEndian: true);
                return true;
            }
            cursor += length;
        }
        return false;
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
        => TryMatchPe(src, src.Length, out result);

    internal static bool TryMatchPe(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 0x40 || src[0] != (byte)'M' || src[1] != (byte)'Z') return false;
        uint peOffset = ReadUInt32LittleEndian(src, 0x3C);
        if (peOffset < 0x40 || peOffset > int.MaxValue ||
            (completeLength.HasValue && peOffset + 26L > completeLength.Value)) return false;
        if (peOffset + 26L <= src.Length)
        {
            if (!TryValidatePeHeader(src.Slice((int)peOffset), peOffset, completeLength ?? long.MaxValue, out result)) return false;
            if (!completeLength.HasValue && peOffset + 24L + ReadUInt16LittleEndian(src, (int)peOffset + 20) > src.Length)
            {
                result!.Confidence = "Medium";
                result.Reason += ";sampled-optional-header";
            }
            return true;
        }
        if (completeLength.HasValue) return false;
        result = new ContentTypeDetectionResult
        {
            Extension = "exe",
            MimeType = "application/x-msdownload",
            Confidence = "Medium",
            Reason = "pe:dos-header;sampled-pe-offset"
        };
        return true;
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
                !TryReadAt(stream, peOffset, 26, out var pePrefix)) return false;
            ushort optionalHeaderSize = ReadUInt16LittleEndian(new ReadOnlySpan<byte>(pePrefix), 20);
            int peHeaderLength = checked(24 + optionalHeaderSize);
            if (peHeaderLength < 26 || peOffset + peHeaderLength > stream.Length ||
                !TryReadAt(stream, peOffset, peHeaderLength, out var peHeader)) return false;
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

        ushort sections = ReadUInt16LittleEndian(peHeader, 6);
        ushort machine = ReadUInt16LittleEndian(peHeader, 4);
        ushort optionalHeaderSize = ReadUInt16LittleEndian(peHeader, 20);
        ushort characteristics = ReadUInt16LittleEndian(peHeader, 22);
        long sectionTableEnd = peOffset + 24L + optionalHeaderSize + sections * 40L;
        if (sections is < 1 or > 96 || optionalHeaderSize < 2 || sectionTableEnd > totalLength) return false;

        ushort optionalMagic = ReadUInt16LittleEndian(peHeader, 24);
        if (optionalMagic != 0x10B && optionalMagic != 0x20B) return false;
        if (!IsCompatiblePeMachine(machine, optionalMagic)) return false;
        int minimumOptionalHeaderSize = optionalMagic == 0x10B ? 96 : 112;
        if (optionalHeaderSize < minimumOptionalHeaderSize || peHeader.Length < 24 + minimumOptionalHeaderSize) return false;
        uint sectionAlignment = ReadUInt32LittleEndian(peHeader, 56);
        uint fileAlignment = ReadUInt32LittleEndian(peHeader, 60);
        uint sizeOfImage = ReadUInt32LittleEndian(peHeader, 80);
        uint sizeOfHeaders = ReadUInt32LittleEndian(peHeader, 84);
        if (sectionAlignment == 0 || fileAlignment == 0 || (fileAlignment & (fileAlignment - 1)) != 0) return false;
        ulong alignedSectionTableEnd = ((ulong)sectionTableEnd + fileAlignment - 1) & ~((ulong)fileAlignment - 1);
        if (
            sectionAlignment < fileAlignment ||
            (sectionAlignment < 0x1000 ? fileAlignment != sectionAlignment : fileAlignment < 512) ||
            sizeOfImage == 0 || sizeOfImage % sectionAlignment != 0 ||
            sizeOfHeaders == 0 || sizeOfHeaders % fileAlignment != 0 ||
            sizeOfImage < sizeOfHeaders || sizeOfHeaders > totalLength || sizeOfHeaders < alignedSectionTableEnd) return false;
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

    private static bool IsCompatiblePeMachine(ushort machine, ushort optionalMagic)
    {
        bool is64BitMachine = machine is 0x0200 or 0x6264 or 0x5064 or 0x5128 or 0x8664 or 0xA641 or 0xA64E or 0xAA64;
        bool known = is64BitMachine || machine is 0x014C or 0x0166 or 0x0169 or 0x0184 or 0x01A2 or 0x01A3 or
            0x01A6 or 0x01A8 or 0x01C0 or 0x01C2 or 0x01C4 or 0x01D3 or 0x01F0 or 0x01F1 or 0x01F2 or
            0x0266 or 0x0284 or 0x0366 or 0x0466 or 0x0EBC or 0x5032 or 0x6232 or 0x9041;
        return known && (machine == 0x0EBC || optionalMagic == (is64BitMachine ? 0x20B : 0x10B));
    }

    internal static bool TryMatchPdf(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 8 || !src.Slice(0, 5).SequenceEqual("%PDF-"u8)) return false;
        if (src[5] is < (byte)'1' or > (byte)'2' || src[6] != (byte)'.' || src[7] is < (byte)'0' or > (byte)'9') return false;
        result = BinaryResult("pdf", "application/pdf", "pdf:header");
        return true;
    }

    internal static bool TryMatchBmp(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchBmp(src, src.Length, out result);

    internal static bool TryMatchBmp(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 26 || src[0] != (byte)'B' || src[1] != (byte)'M') return false;
        uint fileSize = ReadUInt32LittleEndian(src, 2);
        uint pixelOffset = ReadUInt32LittleEndian(src, 10);
        uint dibSize = ReadUInt32LittleEndian(src, 14);
        if (fileSize < 26 || pixelOffset < 14 + dibSize || pixelOffset > fileSize ||
            (completeLength.HasValue && (fileSize > completeLength.Value || pixelOffset > completeLength.Value))) return false;
        if (dibSize is not (12u or 16u or 40u or 52u or 56u or 64u or 108u or 124u)) return false;
        if (!TryValidateBmpDib(src, dibSize, pixelOffset, fileSize)) return false;
        result = BinaryResult("bmp", "image/bmp", "bmp:file+dib-header");
        if (!completeLength.HasValue && fileSize > src.Length)
        {
            result.Confidence = "Medium";
            result.Reason += ";sampled-file-size";
        }
        return true;
    }

    private static bool TryValidateBmpDib(ReadOnlySpan<byte> src, uint dibSize, uint pixelOffset, uint fileSize)
    {
        long width;
        long height;
        ushort planes;
        ushort bitsPerPixel;
        uint compression = 0;
        uint imageSize = 0;
        if (dibSize == 12)
        {
            width = ReadUInt16LittleEndian(src, 18);
            height = ReadUInt16LittleEndian(src, 20);
            planes = ReadUInt16LittleEndian(src, 22);
            bitsPerPixel = ReadUInt16LittleEndian(src, 24);
            if (bitsPerPixel is not (1 or 4 or 8 or 24)) return false;
        }
        else
        {
            if (src.Length < 30) return false;
            width = unchecked((int)ReadUInt32LittleEndian(src, 18));
            height = unchecked((int)ReadUInt32LittleEndian(src, 22));
            planes = ReadUInt16LittleEndian(src, 26);
            bitsPerPixel = ReadUInt16LittleEndian(src, 28);
            if (dibSize >= 40)
            {
                if (src.Length < 38) return false;
                compression = ReadUInt32LittleEndian(src, 30);
                imageSize = ReadUInt32LittleEndian(src, 34);
            }
            else if (bitsPerPixel is not (1 or 4 or 8 or 24)) return false;
        }
        if (width <= 0 || height == 0 || planes != 1 || height == int.MinValue) return false;
        bool validEncoding = compression switch
        {
            0 => bitsPerPixel is 1 or 4 or 8 or 16 or 24 or 32,
            1 => bitsPerPixel == 8 && height > 0,
            2 => bitsPerPixel == 4 && height > 0,
            3 or 6 => bitsPerPixel is 16 or 32,
            4 or 5 => height > 0,
            _ => false
        };
        if (!validEncoding) return false;
        ulong available = fileSize - pixelOffset;
        ulong required;
        if (compression is 0 or 3 or 6)
        {
            ulong rowBits = checked((ulong)width * bitsPerPixel);
            ulong stride = ((rowBits + 31) / 32) * 4;
            ulong rows = (ulong)Math.Abs(height);
            if (stride != 0 && rows > ulong.MaxValue / stride) return false;
            required = stride * rows;
            if (imageSize != 0 && imageSize < required) return false;
        }
        else
        {
            required = imageSize == 0 ? available : imageSize;
            if (required == 0) return false;
        }
        return required <= available;
    }

    internal static bool TryMatchWasm(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 8 || !src.Slice(0, 4).SequenceEqual(new byte[] { 0, 0x61, 0x73, 0x6D }) || ReadUInt32LittleEndian(src, 4) != 1) return false;
        result = BinaryResult("wasm", "application/wasm", "wasm:version=1");
        return true;
    }

    internal static bool TryMatchPcap(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchPcap(src, src.Length, out result);

    internal static bool TryMatchPcap(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
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
        if (major != 2 || minor != 4 || snapLength == 0 || snapLength > 0x10000000 || completeLength < 0) return false;
        int cursor = 24;
        while (cursor < src.Length)
        {
            if (src.Length - cursor < 16)
            {
                if (completeLength.HasValue) return false;
                result = BinaryResult("pcap", "application/vnd.tcpdump.pcap", nanoseconds ? "pcap:nanosecond" : "pcap:microsecond");
                result.Confidence = "Medium";
                result.Reason += ";sampled-record";
                return true;
            }
            uint fraction = ReadUInt32(src, cursor + 4, littleEndian);
            uint includedLength = ReadUInt32(src, cursor + 8, littleEndian);
            uint originalLength = ReadUInt32(src, cursor + 12, littleEndian);
            if (fraction >= (nanoseconds ? 1000000000u : 1000000u) || includedLength > snapLength || includedLength > originalLength) return false;
            long recordEnd = (long)cursor + 16L + includedLength;
            if (completeLength.HasValue && recordEnd > completeLength.Value) return false;
            if (recordEnd > src.Length)
            {
                if (completeLength.HasValue) return false;
                result = BinaryResult("pcap", "application/vnd.tcpdump.pcap", nanoseconds ? "pcap:nanosecond" : "pcap:microsecond");
                result.Confidence = "Medium";
                result.Reason += ";sampled-payload";
                return true;
            }
            cursor = (int)recordEnd;
        }
        if (completeLength.HasValue && cursor != completeLength.Value) return false;
        result = BinaryResult("pcap", "application/vnd.tcpdump.pcap", nanoseconds ? "pcap:nanosecond" : "pcap:microsecond");
        return true;
    }

    internal static bool TryMatchPcap(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try
        {
            if (stream.Length < 24 || !TryReadAt(stream, 0, 24, out var globalBytes)) return false;
            var global = new ReadOnlySpan<byte>(globalBytes);
            uint magic = ReadUInt32BigEndian(global, 0);
            bool littleEndian, nanoseconds;
            if (magic == 0xD4C3B2A1) { littleEndian = true; nanoseconds = false; }
            else if (magic == 0xA1B2C3D4) { littleEndian = false; nanoseconds = false; }
            else if (magic == 0x4D3CB2A1) { littleEndian = true; nanoseconds = true; }
            else if (magic == 0xA1B23C4D) { littleEndian = false; nanoseconds = true; }
            else return false;
            if (ReadUInt16(global, 4, littleEndian) != 2 || ReadUInt16(global, 6, littleEndian) != 4) return false;
            uint snapLength = ReadUInt32(global, 16, littleEndian);
            if (snapLength == 0 || snapLength > 0x10000000) return false;
            long cursor = 24;
            int remainingRecords = Math.Max(1, Settings.DetectionReadBudgetBytes / 16);
            while (cursor < stream.Length)
            {
                if (remainingRecords-- == 0)
                {
                    result = BinaryResult("pcap", "application/vnd.tcpdump.pcap", nanoseconds ? "pcap:nanosecond" : "pcap:microsecond");
                    result.Confidence = "Medium";
                    result.Reason += ";record-scan-budget";
                    return true;
                }
                if (stream.Length - cursor < 16 || !TryReadAt(stream, cursor, 16, out var recordBytes)) return false;
                var record = new ReadOnlySpan<byte>(recordBytes);
                uint fraction = ReadUInt32(record, 4, littleEndian);
                uint includedLength = ReadUInt32(record, 8, littleEndian);
                uint originalLength = ReadUInt32(record, 12, littleEndian);
                if (fraction >= (nanoseconds ? 1000000000u : 1000000u) || includedLength > snapLength || includedLength > originalLength ||
                    includedLength > stream.Length - cursor - 16) return false;
                cursor += 16L + includedLength;
            }
            if (cursor != stream.Length) return false;
            result = BinaryResult("pcap", "application/vnd.tcpdump.pcap", nanoseconds ? "pcap:nanosecond" : "pcap:microsecond");
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

    internal static bool TryMatchPcapNg(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchPcapNg(src, src.Length, out result);

    internal static bool TryMatchPcapNg(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
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
        long sectionLength = unchecked((long)ReadUInt64(src, 16, littleEndian));
        if (blockLength < 28 || (blockLength & 3) != 0 || major != 1 || minor != 0 ||
            sectionLength < -1 || (completeLength.HasValue && (blockLength > completeLength.Value ||
                (sectionLength >= 0 && (ulong)sectionLength > (ulong)(completeLength.Value - blockLength))))) return false;
        if (blockLength > src.Length)
        {
            if (completeLength.HasValue) return false;
            result = new ContentTypeDetectionResult {
                Extension = "pcapng",
                MimeType = "application/x-pcapng",
                Confidence = "Medium",
                Reason = "pcapng:section-header;sampled-block"
            };
            return true;
        }
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
            if (stream.Length < 28 || !TryReadAt(stream, 0, 24, out var headerBytes)) return false;
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
            long sectionLength = unchecked((long)ReadUInt64(header, 16, littleEndian));
            if (blockLength < 28 || (blockLength & 3) != 0 || blockLength > stream.Length ||
                major != 1 || minor != 0 || sectionLength < -1 ||
                (sectionLength >= 0 && (ulong)sectionLength > (ulong)(stream.Length - blockLength)) ||
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

    internal static bool TryMatchIcon(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchIcon(src, src.Length, out result);

    internal static bool TryMatchIcon(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 22 || ReadUInt16LittleEndian(src, 0) != 0) return false;
        ushort type = ReadUInt16LittleEndian(src, 2);
        ushort count = ReadUInt16LittleEndian(src, 4);
        long directoryEnd = 6L + count * 16L;
        if (type is not (1 or 2) || count is < 1 or > 1024 ||
            (completeLength.HasValue && (directoryEnd > completeLength.Value || directoryEnd > src.Length))) return false;
        int availableEntries = Math.Min(count, Math.Max(0, src.Length - 6) / 16);
        if (availableEntries == 0 || (completeLength.HasValue && availableEntries != count)) return false;
        var ranges = new System.Collections.Generic.List<(ulong Start, ulong End)>();
        bool sampledPayload = false;
        for (int index = 0; index < availableEntries; index++)
        {
            int entryOffset = 6 + index * 16;
            int width = src[entryOffset] == 0 ? 256 : src[entryOffset];
            int height = src[entryOffset + 1] == 0 ? 256 : src[entryOffset + 1];
            ushort firstField = ReadUInt16LittleEndian(src, entryOffset + 4);
            ushort secondField = ReadUInt16LittleEndian(src, entryOffset + 6);
            if (type == 1 && (firstField != 1 || secondField is not (1 or 4 or 8 or 16 or 24 or 32)) ||
                type == 2 && (firstField >= width || secondField >= height)) return false;
            uint imageSize = ReadUInt32LittleEndian(src, entryOffset + 8);
            uint imageOffset = ReadUInt32LittleEndian(src, entryOffset + 12);
            if (imageSize == 0 || imageOffset < directoryEnd ||
                (completeLength.HasValue && ((ulong)imageOffset + imageSize > (ulong)completeLength.Value))) return false;
            ulong imageEnd = (ulong)imageOffset + imageSize;
            for (int range = 0; range < ranges.Count; range++)
                if (imageOffset < ranges[range].End && imageEnd > ranges[range].Start) return false;
            ranges.Add((imageOffset, imageEnd));
            if (imageEnd <= (ulong)src.Length)
            {
                if (!TryValidateIconPayload(src.Slice((int)imageOffset, (int)imageSize), width, height, secondField, type)) return false;
            }
            else if (completeLength.HasValue) return false;
            else sampledPayload = true;
        }
        string extension = type == 1 ? "ico" : "cur";
        result = new ContentTypeDetectionResult {
            Extension = extension,
            MimeType = type == 1 ? "image/x-icon" : "image/x-win-bitmap",
            Confidence = completeLength.HasValue && !sampledPayload ? "High" : "Medium",
            Reason = completeLength.HasValue && !sampledPayload ? $"icon-directory:{extension}" : $"icon-directory:{extension};sampled-length-unknown;sampled-payload"
        };
        return true;
    }

    private static bool TryValidateIconPayload(ReadOnlySpan<byte> payload, int width, int height, ushort directoryBitCount, ushort type)
    {
        if (TryMatchPng(payload, payload.Length, out _))
            return payload.Length >= 24 && ReadUInt32BigEndian(payload, 16) == (uint)width &&
                   ReadUInt32BigEndian(payload, 20) == (uint)height;
        if (payload.Length < 40) return false;
        uint dibSize = ReadUInt32LittleEndian(payload, 0);
        if (dibSize is not (40 or 52 or 56 or 108 or 124) || dibSize > payload.Length) return false;
        int dibWidth = unchecked((int)ReadUInt32LittleEndian(payload, 4));
        int dibHeight = unchecked((int)ReadUInt32LittleEndian(payload, 8));
        ushort planes = ReadUInt16LittleEndian(payload, 12);
        ushort bitCount = ReadUInt16LittleEndian(payload, 14);
        uint compression = ReadUInt32LittleEndian(payload, 16);
        if (dibWidth != width || dibHeight != height * 2 || planes != 1 || bitCount is not (1 or 4 or 8 or 16 or 24 or 32) ||
            type == 1 && directoryBitCount != bitCount || compression > 6 || compression == 4 || compression == 5) return false;
        return true;
    }

    internal static bool TryMatchIcon(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try
        {
            if (stream.Length < 22 || !TryReadAt(stream, 0, 6, out var headerBytes)) return false;
            var header = new ReadOnlySpan<byte>(headerBytes);
            if (ReadUInt16LittleEndian(header, 0) != 0) return false;
            ushort count = ReadUInt16LittleEndian(header, 4);
            if (count is < 1 or > 1024) return false;
            int directoryLength = checked(6 + count * 16);
            if (stream.Length <= Settings.DetectionReadBudgetBytes)
                return TryReadAt(stream, 0, (int)stream.Length, out var completeBytes) &&
                       TryMatchIcon(new ReadOnlySpan<byte>(completeBytes), stream.Length, out result);
            if (!TryReadAt(stream, 0, directoryLength, out var directoryBytes) ||
                !TryMatchIcon(new ReadOnlySpan<byte>(directoryBytes), completeLength: null, out result)) return false;
            var directory = new ReadOnlySpan<byte>(directoryBytes);
            ushort type = ReadUInt16LittleEndian(directory, 2);
            for (int index = 0; index < count; index++)
            {
                int entry = 6 + index * 16;
                int width = directory[entry] == 0 ? 256 : directory[entry];
                int height = directory[entry + 1] == 0 ? 256 : directory[entry + 1];
                ushort bitCount = ReadUInt16LittleEndian(directory, entry + 6);
                uint imageSize = ReadUInt32LittleEndian(directory, entry + 8);
                uint imageOffset = ReadUInt32LittleEndian(directory, entry + 12);
                int prefixLength = (int)Math.Min(imageSize, 124u);
                if (!TryReadAt(stream, imageOffset, prefixLength, out var payloadPrefix)) return false;
                var payload = new ReadOnlySpan<byte>(payloadPrefix);
                if (payload.Length >= 8 && payload.Slice(0, 8).SequenceEqual(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }))
                {
                    if (payload.Length < 24 || ReadUInt32BigEndian(payload, 16) != (uint)width ||
                        ReadUInt32BigEndian(payload, 20) != (uint)height) return false;
                }
                else if (!TryValidateIconPayload(payload, width, height, bitCount, type)) return false;
            }
            result!.Confidence = "Medium";
            result.Reason = "icon-directory:" + result.Extension + ";payload-scan-budget";
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
