namespace FileInspectorX;

/// <summary>
/// Structurally validated package, media, medical, graphics, and data-container formats.
/// </summary>
internal static partial class Signatures
{
    internal static bool TryMatchExtendedHeaderFormats(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchExtendedHeaderFormats(src, src.Length, out result);

    internal static bool TryMatchExtendedHeaderFormats(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        if (TryMatchRpm(src, completeLength, out result)) return true;
        if (TryMatchQcow2(src, completeLength, out result)) return true;
        if (TryMatchMidi(src, completeLength, out result)) return true;
        if (TryMatchDds(src, completeLength, out result)) return true;
        if (TryMatchQoi(src, completeLength, out result)) return true;
        if (TryMatchDicom(src, completeLength, out result)) return true;
        if (TryMatchOutlookNdb(src, completeLength, out result)) return true;
        if (TryMatchMatroska(src, completeLength, out result)) return true;
        result = null;
        return false;
    }

    internal static bool TryMatchRpm(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchRpm(src, src.Length, out result);

    internal static bool TryMatchRpm(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try
        {
            if (stream.Length < 144 || !TryReadAt(stream, 0, 112, out var prefix)) return false;
            var src = new ReadOnlySpan<byte>(prefix);
            if (!TryGetRpmMainHeaderOffset(src, stream.Length, out long mainHeaderOffset, out int signatureLength) ||
                signatureLength > Settings.DetectionReadBudgetBytes ||
                !TryReadAt(stream, 96, signatureLength, out var signatureHeader) ||
                !TryValidateRpmHeader(new ReadOnlySpan<byte>(signatureHeader), out _) ||
                !TryReadAt(stream, mainHeaderOffset, 16, out var mainHeader) ||
                !TryGetRpmHeaderLength(new ReadOnlySpan<byte>(mainHeader), out int mainLength) ||
                mainLength > Settings.DetectionReadBudgetBytes || mainHeaderOffset + mainLength > stream.Length ||
                !TryReadAt(stream, mainHeaderOffset, mainLength, out var completeMainHeader) ||
                !TryValidateRpmHeader(new ReadOnlySpan<byte>(completeMainHeader), out _) ||
                !TryReadAt(stream, mainHeaderOffset + mainLength, (int)Math.Min(6, stream.Length - mainHeaderOffset - mainLength), out var payloadPrefix) ||
                !IsRpmPayloadPrefix(new ReadOnlySpan<byte>(payloadPrefix))) return false;
            result = BinaryResult("rpm", "application/x-rpm", "rpm:lead+signature-header");
            result.Confidence = "Medium";
            result.Reason += ";payload-not-validated";
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

    internal static bool TryMatchRpm(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!TryGetRpmMainHeaderOffset(src, completeLength, out long mainHeaderOffset, out int signatureLength)) return false;
        if (signatureLength > src.Length - 96)
        {
            if (completeLength.HasValue) return false;
            result = BinaryResult("rpm", "application/x-rpm", "rpm:lead+signature-header;sampled-signature-header");
            result.Confidence = "Medium";
            return true;
        }
        if (!TryValidateRpmHeader(src.Slice(96, signatureLength), out _)) return false;
        if (mainHeaderOffset + 16L > src.Length)
        {
            if (completeLength.HasValue) return false;
            result = BinaryResult("rpm", "application/x-rpm", "rpm:lead+signature-header;sampled-main-header");
            result.Confidence = "Medium";
            return true;
        }
        if (!TryGetRpmHeaderLength(src.Slice((int)mainHeaderOffset, 16), out int mainLength)) return false;
        long payloadOffset = mainHeaderOffset + mainLength;
        if (completeLength.HasValue && payloadOffset >= completeLength.Value) return false;
        if (payloadOffset > src.Length)
        {
            if (completeLength.HasValue) return false;
            result = BinaryResult("rpm", "application/x-rpm", "rpm:lead+signature-header;sampled-main-header");
            result.Confidence = "Medium";
            return true;
        }
        if (!TryValidateRpmHeader(src.Slice((int)mainHeaderOffset, mainLength), out _) ||
            !IsRpmPayloadPrefix(src.Slice((int)payloadOffset))) return false;
        result = BinaryResult("rpm", "application/x-rpm", "rpm:lead+signature-header");
        result.Confidence = "Medium";
        result.Reason += ";payload-not-validated";
        return true;
    }

    private static bool TryGetRpmMainHeaderOffset(ReadOnlySpan<byte> src, long? completeLength, out long mainHeaderOffset, out int signatureLength)
    {
        mainHeaderOffset = 0;
        signatureLength = 0;
        if (src.Length < 112 || !src.Slice(0, 4).SequenceEqual(new byte[] { 0xED, 0xAB, 0xEE, 0xDB })) return false;
        if (src[4] != 3 || src[5] != 0 || ReadUInt16BigEndian(src, 6) > 1 || ReadUInt16BigEndian(src, 78) != 5) return false;
        for (int i = 80; i < 96; i++) if (src[i] != 0) return false;
        if (!src.Slice(96, 4).SequenceEqual(new byte[] { 0x8E, 0xAD, 0xE8, 0x01 })) return false;
        for (int i = 100; i < 104; i++) if (src[i] != 0) return false;
        uint indexCount = ReadUInt32BigEndian(src, 104);
        uint dataLength = ReadUInt32BigEndian(src, 108);
        if (indexCount is < 1 or > 65535 || dataLength > 0x40000000) return false;
        long signatureEnd = 112L + indexCount * 16L + dataLength;
        long computedLength = signatureEnd - 96L;
        if (computedLength > int.MaxValue) return false;
        signatureLength = (int)computedLength;
        mainHeaderOffset = (signatureEnd + 7L) & ~7L;
        return signatureEnd >= 112 && mainHeaderOffset >= signatureEnd &&
               (!completeLength.HasValue || mainHeaderOffset + 16L <= completeLength.Value);
    }

    private static bool TryGetRpmHeaderLength(ReadOnlySpan<byte> header, out int length)
    {
        length = 0;
        if (header.Length < 16 || !header.Slice(0, 4).SequenceEqual(new byte[] { 0x8E, 0xAD, 0xE8, 0x01 })) return false;
        for (int i = 4; i < 8; i++) if (header[i] != 0) return false;
        uint indexCount = ReadUInt32BigEndian(header, 8);
        uint dataLength = ReadUInt32BigEndian(header, 12);
        long computed = 16L + indexCount * 16L + dataLength;
        if (indexCount is < 1 or > 65535 || dataLength > 0x40000000 || computed > int.MaxValue) return false;
        length = (int)computed;
        return true;
    }

    private static bool TryValidateRpmHeader(ReadOnlySpan<byte> header, out int length)
    {
        if (!TryGetRpmHeaderLength(header, out length) || header.Length < length) return false;
        uint indexCount = ReadUInt32BigEndian(header, 8);
        uint dataLength = ReadUInt32BigEndian(header, 12);
        int storeOffset = checked(16 + (int)indexCount * 16);
        for (uint index = 0; index < indexCount; index++)
        {
            int record = checked(16 + (int)index * 16);
            uint tag = ReadUInt32BigEndian(header, record);
            uint type = ReadUInt32BigEndian(header, record + 4);
            uint offset = ReadUInt32BigEndian(header, record + 8);
            uint count = ReadUInt32BigEndian(header, record + 12);
            if (tag == 0 || type is < 1 or > 9 || count == 0 || offset > dataLength) return false;
            ulong valueLength;
            if (type is 1 or 2) valueLength = count;
            else if (type == 3) valueLength = (ulong)count * 2;
            else if (type == 4) valueLength = (ulong)count * 4;
            else if (type == 5) valueLength = (ulong)count * 8;
            else if (type == 7) valueLength = count;
            else
            {
                int strings = 0;
                int cursor = storeOffset + (int)offset;
                int storeEnd = storeOffset + (int)dataLength;
                while (cursor < storeEnd && strings < count)
                {
                    if (header[cursor++] == 0) strings++;
                }
                if (strings != count) return false;
                valueLength = (ulong)(cursor - storeOffset) - offset;
            }
            if (valueLength > dataLength - offset) return false;
        }
        return true;
    }

    private static bool IsRpmPayloadPrefix(ReadOnlySpan<byte> payload)
    {
        if (payload.Length >= 6 && (payload.Slice(0, 6).SequenceEqual("070701"u8) ||
                                    payload.Slice(0, 6).SequenceEqual("070702"u8))) return true;
        if (payload.Length >= 2 && payload[0] == 0x1F && payload[1] == 0x8B) return true;
        if (payload.Length >= 3 && payload.Slice(0, 3).SequenceEqual("BZh"u8)) return true;
        if (payload.Length >= 6 && payload.Slice(0, 6).SequenceEqual(new byte[] { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 })) return true;
        if (payload.Length >= 4 && ReadUInt32LittleEndian(payload, 0) == 0xFD2FB528) return true;
        if (payload.Length < 5 || payload[0] > 224 || payload[0] % 9 > 4) return false;
        uint dictionarySize = ReadUInt32LittleEndian(payload, 1);
        return dictionarySize is >= 4096 and <= 0x60000000;
    }

    internal static bool TryMatchQcow2(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchQcow2(src, src.Length, out result);

    internal static bool TryMatchQcow2(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try
        {
            if (stream.Length < 72 || !TryReadAt(stream, 0, (int)Math.Min(104, stream.Length), out var header)) return false;
            var headerSpan = new ReadOnlySpan<byte>(header);
            if (headerSpan.Length < 36 || ReadUInt32BigEndian(headerSpan, 32) != 2)
                return TryMatchQcow2(headerSpan, stream.Length, out result);
            if (headerSpan.Length < 104) return false;
            uint clusterBits = ReadUInt32BigEndian(headerSpan, 20);
            if (clusterBits is < 9 or > 21) return false;
            int extensionAreaLength = (int)Math.Min(1L << (int)clusterBits, stream.Length);
            if (!TryReadAt(stream, 0, extensionAreaLength, out var extensionArea)) return false;
            return TryMatchQcow2(new ReadOnlySpan<byte>(extensionArea), stream.Length, out result);
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

    internal static bool TryMatchQcow2(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 72 || !src.Slice(0, 4).SequenceEqual(new byte[] { (byte)'Q', (byte)'F', (byte)'I', 0xFB })) return false;
        uint version = ReadUInt32BigEndian(src, 4);
        ulong backingOffset = ReadUInt64(src, 8, littleEndian: false);
        uint backingSize = ReadUInt32BigEndian(src, 16);
        uint clusterBits = ReadUInt32BigEndian(src, 20);
        ulong virtualSize = ReadUInt64(src, 24, littleEndian: false);
        uint cryptMethod = ReadUInt32BigEndian(src, 32);
        uint l1Size = ReadUInt32BigEndian(src, 36);
        ulong l1Offset = ReadUInt64(src, 40, littleEndian: false);
        ulong refcountOffset = ReadUInt64(src, 48, littleEndian: false);
        uint refcountClusters = ReadUInt32BigEndian(src, 56);
        if (version is not (2u or 3u) || clusterBits is < 9 or > 21 || virtualSize == 0 || cryptMethod > 2 ||
            completeLength < 0 ||
            l1Size == 0 || l1Offset == 0 || refcountOffset == 0 || refcountClusters == 0) return false;
        ulong clusterSize = 1UL << (int)clusterBits;
        uint headerLength = 72;
        if (version == 3)
        {
            if (src.Length < 104) return false;
            ulong incompatibleFeatures = ReadUInt64(src, 72, littleEndian: false);
            uint refcountOrder = ReadUInt32BigEndian(src, 96);
            headerLength = ReadUInt32BigEndian(src, 100);
            if ((incompatibleFeatures & ~0x1FUL) != 0 || refcountOrder > 6 || headerLength < 104 ||
                (headerLength & 7) != 0 || headerLength > clusterSize ||
                (completeLength.HasValue && headerLength > completeLength.Value)) return false;
        }
        bool extendedL2 = version == 3 && src.Length >= 80 && (ReadUInt64(src, 72, littleEndian: false) & 0x10UL) != 0;
        ulong l2Entries = clusterSize / (extendedL2 ? 16UL : 8UL);
        ulong bytesCoveredPerL1Entry = clusterSize * l2Entries;
        ulong requiredL1Entries = (virtualSize - 1) / bytesCoveredPerL1Entry + 1;
        if (requiredL1Entries > l1Size) return false;
        if ((l1Offset & (clusterSize - 1)) != 0 || (refcountOffset & (clusterSize - 1)) != 0) return false;
        if ((backingOffset == 0) != (backingSize == 0)) return false;
        ulong encryptionOffset = 0;
        ulong encryptionLength = 0;
        if (version == 3 && cryptMethod == 2 &&
            !TryValidateQcow2LuksExtension(src, headerLength, clusterSize, completeLength, out encryptionOffset, out encryptionLength)) return false;
        if (version == 2 && cryptMethod == 2) return false;
        if (completeLength.HasValue)
        {
            ulong fileLength = (ulong)completeLength.Value;
            if (!IsQcow2RangeWithin(backingOffset, backingSize, fileLength) ||
                !IsQcow2RangeWithin(l1Offset, (ulong)l1Size * 8UL, fileLength) ||
                 !IsQcow2RangeWithin(refcountOffset, (ulong)refcountClusters * clusterSize, fileLength)) return false;
        }
        var ranges = new System.Collections.Generic.List<(ulong Offset, ulong Length)> {
            (0, headerLength), (l1Offset, (ulong)l1Size * 8UL),
            (refcountOffset, (ulong)refcountClusters * clusterSize)
        };
        if (backingSize != 0) ranges.Add((backingOffset, backingSize));
        if (encryptionLength != 0) ranges.Add((encryptionOffset, encryptionLength));
        for (int i = 0; i < ranges.Count; i++)
            for (int j = i + 1; j < ranges.Count; j++)
                if (Qcow2RangesOverlap(ranges[i], ranges[j])) return false;
        result = BinaryResult("qcow2", "application/x-qemu-disk", $"qcow2:version={version}");
        result.Confidence = "Medium";
        result.Reason += ";refcount-contents-not-validated";
        if (!completeLength.HasValue)
        {
            result.Reason += ";sampled-length-unknown";
        }
        return true;
    }

    private static bool IsQcow2RangeWithin(ulong offset, ulong length, ulong fileLength)
        => offset <= fileLength && length <= fileLength - offset;

    private static bool Qcow2RangesOverlap((ulong Offset, ulong Length) first, (ulong Offset, ulong Length) second)
    {
        if (first.Length == 0 || second.Length == 0) return false;
        return first.Offset <= second.Offset
            ? second.Offset - first.Offset < first.Length
            : first.Offset - second.Offset < second.Length;
    }

    private static bool TryValidateQcow2LuksExtension(ReadOnlySpan<byte> src, uint headerLength, ulong clusterSize,
        long? completeLength, out ulong encryptionOffset, out ulong encryptionLength)
    {
        encryptionOffset = 0;
        encryptionLength = 0;
        int cursor = (int)headerLength;
        bool found = false;
        while (cursor + 8 <= src.Length && (ulong)cursor < clusterSize)
        {
            uint type = ReadUInt32BigEndian(src, cursor);
            uint length = ReadUInt32BigEndian(src, cursor + 4);
            cursor += 8;
            if (type == 0) return length == 0 && found;
            ulong paddedLength = ((ulong)length + 7) & ~7UL;
            if (paddedLength > int.MaxValue || (ulong)cursor + paddedLength > (ulong)src.Length ||
                (ulong)cursor + paddedLength > clusterSize) return false;
            if (type == 0x0537BE77)
            {
                if (found || length != 16) return false;
                encryptionOffset = ReadUInt64(src, cursor, littleEndian: false);
                encryptionLength = ReadUInt64(src, cursor + 8, littleEndian: false);
                if (encryptionOffset == 0 || encryptionLength < 592 || (encryptionOffset & (clusterSize - 1)) != 0 ||
                    (completeLength.HasValue && (encryptionOffset > (ulong)completeLength.Value ||
                                                 encryptionLength > (ulong)completeLength.Value - encryptionOffset))) return false;
                found = true;
            }
            cursor += (int)paddedLength;
        }
        return false;
    }

    internal static bool TryMatchDds(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchDds(src, src.Length, out result);

    internal static bool TryMatchDds(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 128 || !src.Slice(0, 4).SequenceEqual("DDS "u8) || ReadUInt32LittleEndian(src, 4) != 124) return false;
        uint flags = ReadUInt32LittleEndian(src, 8);
        uint height = ReadUInt32LittleEndian(src, 12);
        uint width = ReadUInt32LittleEndian(src, 16);
        uint pixelFormatSize = ReadUInt32LittleEndian(src, 76);
        uint pixelFormatFlags = ReadUInt32LittleEndian(src, 80);
        uint fourCc = ReadUInt32LittleEndian(src, 84);
        uint rgbBitCount = ReadUInt32LittleEndian(src, 88);
        uint redMask = ReadUInt32LittleEndian(src, 92);
        uint greenMask = ReadUInt32LittleEndian(src, 96);
        uint blueMask = ReadUInt32LittleEndian(src, 100);
        uint alphaMask = ReadUInt32LittleEndian(src, 104);
        uint caps = ReadUInt32LittleEndian(src, 108);
        uint depth = ReadUInt32LittleEndian(src, 24);
        uint caps2 = ReadUInt32LittleEndian(src, 112);
        uint mipMapCount = ReadUInt32LittleEndian(src, 28);
        uint pitchOrLinearSize = ReadUInt32LittleEndian(src, 20);
        if ((flags & 0x1007) != 0x1007 || height == 0 || width == 0 || pixelFormatSize != 32 || (caps & 0x1000) == 0) return false;
        const uint fourCcFlag = 0x4;
        const uint rgbFlag = 0x40;
        const uint yuvFlag = 0x200;
        const uint luminanceFlag = 0x20000;
        const uint bumpLuminanceFlag = 0x40000;
        const uint bumpDuDvFlag = 0x80000;
        const uint supportedFlags = 0x1 | 0x2 | fourCcFlag | rgbFlag | yuvFlag | luminanceFlag | bumpLuminanceFlag | bumpDuDvFlag;
        if ((pixelFormatFlags & ~supportedFlags) != 0) return false;
        bool hasFourCc = (pixelFormatFlags & fourCcFlag) != 0;
        bool hasRgb = (pixelFormatFlags & rgbFlag) != 0;
        bool hasYuv = (pixelFormatFlags & yuvFlag) != 0;
        bool hasLuminance = (pixelFormatFlags & luminanceFlag) != 0;
        bool hasBumpLuminance = (pixelFormatFlags & bumpLuminanceFlag) != 0;
        bool hasBumpDuDv = (pixelFormatFlags & bumpDuDvFlag) != 0;
        bool alphaOnly = (pixelFormatFlags & 0x2) != 0 && !hasFourCc && !hasRgb && !hasYuv && !hasLuminance && !hasBumpLuminance && !hasBumpDuDv;
        if ((pixelFormatFlags & 0x2) != 0 && !alphaOnly || (pixelFormatFlags & 0x1) != 0 && hasFourCc) return false;
        int encodingKinds = (hasFourCc ? 1 : 0) + (hasRgb ? 1 : 0) + (hasYuv ? 1 : 0) + (hasLuminance ? 1 : 0) +
                            (hasBumpLuminance ? 1 : 0) + (hasBumpDuDv ? 1 : 0) + (alphaOnly ? 1 : 0);
        if (encodingKinds != 1) return false;
        if (hasFourCc)
        {
            if (!IsKnownNumericDdsFourCc(fourCc))
            {
                for (int shift = 0; shift < 32; shift += 8)
                {
                    byte character = (byte)(fourCc >> shift);
                    if (character < 0x20 || character > 0x7E) return false;
                }
            }
        }
        else if (!TryValidateDdsMasks(pixelFormatFlags, rgbBitCount, redMask, greenMask, blueMask, alphaMask,
                     hasRgb, hasYuv, hasLuminance, hasBumpLuminance, hasBumpDuDv, alphaOnly))
        {
            return false;
        }
        uint arraySize = 1;
        bool dx10Cube = false;
        uint dxgiFormat = 0;
        if (hasFourCc && fourCc == 0x30315844)
        {
            if (src.Length < 148) return false;
            dxgiFormat = ReadUInt32LittleEndian(src, 128);
            uint resourceDimension = ReadUInt32LittleEndian(src, 132);
            uint miscFlag = ReadUInt32LittleEndian(src, 136);
            arraySize = ReadUInt32LittleEndian(src, 140);
            uint alphaMode = ReadUInt32LittleEndian(src, 144);
            if (!IsKnownDdsDxgiFormat(dxgiFormat) || resourceDimension is < 2 or > 4 || arraySize == 0 ||
                alphaMode > 4 ||
                (resourceDimension == 2 && (height != 1 || depth != 0 || (flags & 0x800000) != 0 || (caps2 & 0x200000) != 0)) ||
                (resourceDimension == 3 && (depth != 0 || (flags & 0x800000) != 0 || (caps2 & 0x200000) != 0)) ||
                (resourceDimension == 4 && (arraySize != 1 || (miscFlag & 0x4) != 0 || depth == 0 ||
                    (flags & 0x800000) == 0 || (caps2 & 0x200000) == 0))) return false;
            dx10Cube = (miscFlag & 0x4) != 0;
            if (dx10Cube && (resourceDimension != 3 || width != height)) return false;
        }
        int headerLength = hasFourCc && fourCc == 0x30315844 ? 148 : 128;
        bool encodingSizeKnown = !hasFourCc || fourCc == 0x30315844 || IsKnownNumericDdsFourCc(fourCc) ||
                                 GetDdsBlockBytes(fourCc, 0) != 0;
        if (!TryGetDdsMinimumPayloadLength(width, height, depth, mipMapCount, flags, caps2,
                hasFourCc, fourCc, dxgiFormat, rgbBitCount, pitchOrLinearSize, arraySize, dx10Cube,
                out ulong minimumPayload) || completeLength < headerLength ||
            completeLength.HasValue && minimumPayload > (ulong)(completeLength.Value - headerLength)) return false;
        result = BinaryResult("dds", "image/vnd-ms.dds", "dds:header+pixel-format");
        if (!encodingSizeKnown)
        {
            result.Confidence = "Medium";
            result.Reason += ";encoding-size-not-validated";
        }
        if (!completeLength.HasValue) { result.Confidence = "Medium"; result.Reason += ";sampled-length-unknown"; }
        return true;
    }

    private static bool TryGetDdsMinimumPayloadLength(uint width, uint height, uint depth, uint declaredMipCount,
        uint flags, uint caps2, bool hasFourCc, uint fourCc, uint dxgiFormat, uint bitCount,
        uint pitchOrLinearSize, uint arraySize, bool dx10Cube, out ulong length)
    {
        length = 0;
        uint mipCount = (flags & 0x20000) != 0 ? declaredMipCount : 1;
        if (mipCount is < 1 or > 32) return false;
        uint surfaces = arraySize;
        if (dx10Cube)
        {
            if (surfaces > uint.MaxValue / 6) return false;
            surfaces *= 6;
        }
        else if ((caps2 & 0x200) != 0)
        {
            uint faceBits = caps2 & 0xFC00;
            int faces = 0;
            for (uint bit = 0x400; bit <= 0x8000; bit <<= 1) if ((faceBits & bit) != 0) faces++;
            if (faces == 0) return false;
            surfaces = (uint)faces;
        }
        if (surfaces == 0) return false;
        uint currentWidth = width, currentHeight = height, currentDepth = Math.Max(1u, depth);
        for (uint mip = 0; mip < mipCount; mip++)
        {
            ulong mipLength;
            int blockBytes = GetDdsBlockBytes(fourCc, dxgiFormat);
            if (blockBytes != 0)
                mipLength = ((currentWidth + 3UL) / 4UL) * ((currentHeight + 3UL) / 4UL) * currentDepth * (uint)blockBytes;
            else if (dxgiFormat is >= 130 and <= 132)
            {
                if (dxgiFormat == 130 && (currentWidth & 1) != 0 || dxgiFormat == 131 && (currentHeight & 1) != 0)
                    return false;
                ulong rowBytes = currentWidth;
                if (mip == 0 && pitchOrLinearSize != 0)
                {
                    if (pitchOrLinearSize < rowBytes) return false;
                    rowBytes = pitchOrLinearSize;
                }
                ulong planeRows = dxgiFormat switch
                {
                    130 => currentHeight * 2UL,                         // P208: Y + interleaved UV.
                    131 => currentHeight + 2UL * ((currentHeight + 1UL) / 2UL), // V208: Y + U + V half-height.
                    _ => currentHeight * 3UL                           // V408: full-height Y, U and V.
                };
                if (planeRows == 0 || rowBytes > ulong.MaxValue / planeRows ||
                    rowBytes * planeRows > ulong.MaxValue / currentDepth) return false;
                mipLength = rowBytes * planeRows * currentDepth;
            }
            else if (dxgiFormat != 0 && TryGetDdsBitsPerPixel(dxgiFormat, out uint dxgiBits))
            {
                ulong rowBytes = (currentWidth * (ulong)dxgiBits + 7UL) / 8UL;
                if (mip == 0 && pitchOrLinearSize != 0)
                {
                    if (pitchOrLinearSize < rowBytes) return false;
                    rowBytes = pitchOrLinearSize;
                }
                mipLength = rowBytes * currentHeight * currentDepth;
            }
            else if (hasFourCc && TryGetLegacyDdsBitsPerPixel(fourCc, out uint legacyBits))
            {
                ulong rowBytes = (currentWidth * (ulong)legacyBits + 7UL) / 8UL;
                if (mip == 0 && pitchOrLinearSize != 0)
                {
                    if (pitchOrLinearSize < rowBytes) return false;
                    rowBytes = pitchOrLinearSize;
                }
                mipLength = rowBytes * currentHeight * currentDepth;
            }
            else if (!hasFourCc && bitCount != 0)
            {
                ulong rowBytes = (currentWidth * (ulong)bitCount + 7UL) / 8UL;
                if (mip == 0 && (flags & 0x8) != 0)
                {
                    if (pitchOrLinearSize < rowBytes) return false;
                    rowBytes = pitchOrLinearSize;
                }
                mipLength = rowBytes * currentHeight * currentDepth;
            }
            else if (mip == 0 && pitchOrLinearSize != 0)
                mipLength = pitchOrLinearSize * (ulong)currentDepth;
            else
                mipLength = ((ulong)currentWidth * currentHeight * currentDepth + 7UL) / 8UL;
            if (mipLength == 0 || mipLength > ulong.MaxValue / surfaces || length > ulong.MaxValue - mipLength * surfaces) return false;
            length += mipLength * surfaces;
            currentWidth = Math.Max(1u, currentWidth >> 1);
            currentHeight = Math.Max(1u, currentHeight >> 1);
            currentDepth = Math.Max(1u, currentDepth >> 1);
        }
        return true;
    }

    private static int GetDdsBlockBytes(uint fourCc, uint dxgiFormat)
    {
        if (fourCc is 0x31545844 or 0x31495441 or 0x55344342 or 0x53344342) return 8; // DXT1, ATI1, BC4U/S
        if (fourCc is 0x32545844 or 0x33545844 or 0x34545844 or 0x35545844 or
            0x32495441 or 0x55354342 or 0x53354342) return 16; // DXT2-5, ATI2, BC5U/S
        if (dxgiFormat is >= 70 and <= 72 or >= 79 and <= 81) return 8;
        if (dxgiFormat is >= 73 and <= 78 or >= 82 and <= 84 or >= 94 and <= 99) return 16;
        return 0;
    }

    private static bool TryGetDdsBitsPerPixel(uint format, out uint bits)
    {
        bits = 0;
        if (format is >= 1 and <= 4) bits = 128;
        else if (format is >= 5 and <= 8) bits = 96;
        else if (format is >= 9 and <= 22 or >= 109 and <= 110) bits = 64;
        else if (format is >= 23 and <= 47 or >= 67 and <= 69 or >= 87 and <= 93 or >= 100 and <= 102 or >= 106 and <= 108 or >= 111 and <= 115) bits = 32;
        else if (format is >= 48 and <= 59 or >= 85 and <= 86 or 105) bits = 16;
        else if (format is >= 60 and <= 65) bits = 8;
        else if (format == 66) bits = 1;
        else if (format == 103) bits = 12;
        else if (format == 104) bits = 24;
        return bits != 0;
    }

    private static bool IsKnownDdsDxgiFormat(uint format)
        => format is >= 1 and <= 115 or >= 130 and <= 132 or 189 or 190;

    private static bool IsKnownNumericDdsFourCc(uint format)
        => format == 36 || format is >= 110 and <= 116;

    private static bool TryGetLegacyDdsBitsPerPixel(uint format, out uint bits)
    {
        bits = format switch
        {
            36 or 110 or 113 or 115 => 64,
            111 => 16,
            112 or 114 => 32,
            116 => 128,
            _ => 0
        };
        return bits != 0;
    }

    private static bool TryValidateDdsMasks(uint flags, uint bitCount, uint red, uint green, uint blue, uint alpha,
        bool rgb, bool yuv, bool luminance, bool bumpLuminance, bool bumpDuDv, bool alphaOnly)
    {
        if (bitCount is < 1 or > 32) return false;
        uint allowedBits = bitCount == 32 ? uint.MaxValue : (1u << (int)bitCount) - 1;
        if (((red | green | blue | alpha) & ~allowedBits) != 0) return false;
        bool alphaRequired = (flags & 0x1) != 0 || alphaOnly;
        if (alphaRequired && alpha == 0 || !alphaRequired && alpha != 0) return false;
        if (rgb || yuv)
        {
            if (red == 0 || green == 0 || blue == 0) return false;
            if ((red & green) != 0 || (red & blue) != 0 || (green & blue) != 0 || (alpha & (red | green | blue)) != 0) return false;
            return true;
        }
        if (luminance) return red != 0 && green == 0 && blue == 0 && (alpha & red) == 0;
        if (bumpDuDv)
            return red != 0 && green != 0 && blue == 0 && (red & green) == 0 && (alpha & (red | green)) == 0;
        if (bumpLuminance)
            return red != 0 && green != 0 && blue != 0 && (red & green) == 0 && (red & blue) == 0 &&
                   (green & blue) == 0 && (alpha & (red | green | blue)) == 0;
        return alphaOnly && red == 0 && green == 0 && blue == 0;
    }

    internal static bool TryMatchQoi(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchQoi(src, src.Length, out result);

    internal static bool TryMatchQoi(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 14 || !src.Slice(0, 4).SequenceEqual("qoif"u8)) return false;
        uint width = ReadUInt32BigEndian(src, 4);
        uint height = ReadUInt32BigEndian(src, 8);
        byte channels = src[12];
        byte colorSpace = src[13];
        if (width == 0 || height == 0 || channels is not (3 or 4) || colorSpace > 1 ||
            completeLength < 0 || completeLength.HasValue && completeLength.Value < src.Length) return false;
        string confidence = "Medium";
        string reason = "qoi:header";
        ulong pixelCount = (ulong)width * height;
        if (completeLength == src.Length && src.Length >= 23 &&
            src.Slice(src.Length - 8, 8).SequenceEqual(new byte[] { 0, 0, 0, 0, 0, 0, 0, 1 }) &&
            TryValidateQoiChunks(src.Slice(14, src.Length - 22), pixelCount))
        {
            confidence = "High";
            reason += "+pixel-stream+end-marker";
        }
        result = new ContentTypeDetectionResult { Extension = "qoi", MimeType = "image/qoi", Confidence = confidence, Reason = reason };
        return true;
    }

    private static bool TryValidateQoiChunks(ReadOnlySpan<byte> chunks, ulong expectedPixels)
    {
        ulong pixels = 0;
        int cursor = 0;
        while (cursor < chunks.Length && pixels < expectedPixels)
        {
            byte operation = chunks[cursor++];
            ulong produced = 1;
            if (operation == 0xFE)
            {
                if (cursor + 3 > chunks.Length) return false;
                cursor += 3;
            }
            else if (operation == 0xFF)
            {
                if (cursor + 4 > chunks.Length) return false;
                cursor += 4;
            }
            else if ((operation & 0xC0) == 0x80)
            {
                if (cursor >= chunks.Length) return false;
                cursor++;
            }
            else if ((operation & 0xC0) == 0xC0)
            {
                produced = (ulong)(operation & 0x3F) + 1;
            }
            if (produced > expectedPixels - pixels) return false;
            pixels += produced;
        }
        return pixels == expectedPixels && cursor == chunks.Length;
    }

    internal static bool TryMatchDicom(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchDicom(src, src.Length, out result);

    internal static bool TryMatchDicom(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 144 || !src.Slice(128, 4).SequenceEqual("DICM"u8)) return false;
        if (ReadUInt16LittleEndian(src, 132) != 0x0002 || ReadUInt16LittleEndian(src, 134) != 0x0000 ||
            src[136] != (byte)'U' || src[137] != (byte)'L' || ReadUInt16LittleEndian(src, 138) != 4)
            return false;
        uint metaLength = ReadUInt32LittleEndian(src, 140);
        long metaEnd = 144L + metaLength;
        if (metaLength < 48 || completeLength < 0 || (completeLength.HasValue && metaEnd > completeLength.Value)) return false;
        bool fileMetaVersion = false, sopClass = false, sopInstance = false, transferSyntax = false, implementationClass = false;
        ushort previousTag = 0;
        bool sawTag = false;
        bool sampled = metaEnd > src.Length;
        long cursor = 144;
        while (cursor < metaEnd)
        {
            if (cursor > int.MaxValue || cursor + 8 > src.Length)
                return !completeLength.HasValue && TryCreateSampledDicomResult(
                    fileMetaVersion, sopClass, sopInstance, transferSyntax, implementationClass, out result);
            int element = (int)cursor;
            ushort group = ReadUInt16LittleEndian(src, element);
            ushort tag = ReadUInt16LittleEndian(src, element + 2);
            byte vr1 = src[element + 4], vr2 = src[element + 5];
            if (group != 0x0002 || vr1 is < (byte)'A' or > (byte)'Z' || vr2 is < (byte)'A' or > (byte)'Z') return false;
            if (sawTag && tag <= previousTag) return false;
            previousTag = tag;
            sawTag = true;
            bool longValue = IsDicomLongValueRepresentation(vr1, vr2);
            int headerLength = longValue ? 12 : 8;
            if (cursor + headerLength > src.Length)
                return !completeLength.HasValue && TryCreateSampledDicomResult(
                    fileMetaVersion, sopClass, sopInstance, transferSyntax, implementationClass, out result);
            uint valueLength;
            if (longValue)
            {
                if (src[element + 6] != 0 || src[element + 7] != 0) return false;
                valueLength = ReadUInt32LittleEndian(src, element + 8);
            }
            else
            {
                valueLength = ReadUInt16LittleEndian(src, element + 6);
            }
            long valueOffset = cursor + headerLength;
            long valueEnd = valueOffset + valueLength;
            if (valueEnd < valueOffset || valueEnd > metaEnd || valueLength == uint.MaxValue) return false;
            bool requiredUid = tag is 0x0002 or 0x0003 or 0x0010 or 0x0012;
            if (valueEnd > src.Length && !completeLength.HasValue)
            {
                if (tag == 0x0001 || requiredUid) return false;
                return TryCreateSampledDicomResult(
                    fileMetaVersion, sopClass, sopInstance, transferSyntax, implementationClass, out result);
            }
            if (tag == 0x0001)
            {
                if (fileMetaVersion || vr1 != (byte)'O' || vr2 != (byte)'B' || valueLength != 2 || valueEnd > src.Length ||
                    src[(int)valueOffset] != 0 || src[(int)valueOffset + 1] != 1) return false;
                fileMetaVersion = true;
            }
            if (requiredUid)
            {
                if (vr1 != (byte)'U' || vr2 != (byte)'I' || valueEnd > src.Length ||
                    !IsValidDicomUid(src.Slice((int)valueOffset, (int)valueLength))) return false;
                if (tag == 0x0002) { if (sopClass) return false; sopClass = true; }
                else if (tag == 0x0003) { if (sopInstance) return false; sopInstance = true; }
                else if (tag == 0x0010) { if (transferSyntax) return false; transferSyntax = true; }
                else { if (implementationClass) return false; implementationClass = true; }
            }
            sampled |= valueEnd > src.Length;
            cursor = valueEnd;
        }
        if (cursor != metaEnd || !fileMetaVersion || !sopClass || !sopInstance || !transferSyntax || !implementationClass) return false;
        result = BinaryResult("dcm", "application/dicom", "dicom:preamble+meta-header");
        if (completeLength.HasValue && (metaEnd >= completeLength.Value || metaEnd + 8 > src.Length))
        {
            result.Confidence = "Medium";
            result.Reason += ";data-set-not-validated";
        }
        else if (completeLength.HasValue && !TryValidateDicomFirstDataSetElement(src, checked((int)metaEnd), completeLength.Value))
        {
            result.Confidence = "Medium";
            result.Reason += ";data-set-not-validated";
        }
        else if (completeLength.HasValue)
        {
            result.Confidence = "Medium";
            result.Reason += ";data-set-not-fully-validated";
        }
        if (!completeLength.HasValue && sampled)
        {
            result.Confidence = "Medium";
            result.Reason += ";sampled-meta-header";
        }
        return true;
    }

    private static bool TryValidateDicomFirstDataSetElement(ReadOnlySpan<byte> src, int offset, long completeLength)
    {
        if (offset < 0 || offset + 8 > src.Length || offset + 8 > completeLength) return false;
        ushort group = ReadUInt16LittleEndian(src, offset);
        ushort tag = ReadUInt16LittleEndian(src, offset + 2);
        byte vr1 = src[offset + 4], vr2 = src[offset + 5];
        if (group == 0x0002 || group == 0xFFFF || tag == 0xFFFF || vr1 is < (byte)'A' or > (byte)'Z' || vr2 is < (byte)'A' or > (byte)'Z') return false;
        bool longValue = IsDicomLongValueRepresentation(vr1, vr2);
        int headerLength = longValue ? 12 : 8;
        if (offset + headerLength > src.Length || offset + headerLength > completeLength) return false;
        uint valueLength = longValue ? ReadUInt32LittleEndian(src, offset + 8) : ReadUInt16LittleEndian(src, offset + 6);
        if (longValue && (src[offset + 6] != 0 || src[offset + 7] != 0) || valueLength == uint.MaxValue) return false;
        return (ulong)offset + (uint)headerLength + valueLength <= (ulong)completeLength;
    }

    private static bool TryCreateSampledDicomResult(bool fileMetaVersion, bool sopClass, bool sopInstance,
        bool transferSyntax, bool implementationClass, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!fileMetaVersion || !sopClass || !sopInstance || !transferSyntax || !implementationClass) return false;
        result = BinaryResult("dcm", "application/dicom", "dicom:preamble+meta-header;sampled-meta-header");
        result.Confidence = "Medium";
        return true;
    }

    private static bool IsDicomLongValueRepresentation(byte first, byte second)
        => first == (byte)'O' && second is (byte)'B' or (byte)'D' or (byte)'F' or (byte)'L' or (byte)'W' ||
           first == (byte)'S' && second == (byte)'Q' || first == (byte)'U' && second is (byte)'C' or (byte)'R' or (byte)'T' or (byte)'N';

    private static bool IsValidDicomUid(ReadOnlySpan<byte> value)
    {
        if (value.Length is < 2 or > 64 || (value.Length & 1) != 0) return false;
        int length = value.Length;
        if (value[length - 1] == 0) length--;
        if (length == 0 || value[0] == (byte)'.' || value[length - 1] == (byte)'.') return false;
        int componentStart = 0;
        for (int index = 0; index < length; index++)
        {
            byte current = value[index];
            if (current == (byte)'.')
            {
                if (index == componentStart || index - componentStart > 1 && value[componentStart] == (byte)'0') return false;
                componentStart = index + 1;
            }
            else
            {
                if (current is < (byte)'0' or > (byte)'9') return false;
            }
        }
        return length > componentStart && (length - componentStart == 1 || value[componentStart] != (byte)'0');
    }

    internal static bool TryMatchOutlookNdb(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchOutlookNdb(src, src.Length, out result);

    internal static bool TryMatchOutlookNdb(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 24 || !src.Slice(0, 4).SequenceEqual("!BDN"u8) || !src.Slice(8, 2).SequenceEqual("SM"u8)) return false;
        ushort version = ReadUInt16LittleEndian(src, 10);
        ushort clientVersion = ReadUInt16LittleEndian(src, 12);
        if (version is not (14 or 15 or 21) && version is not (>= 23 and <= 50)) return false;
        if (clientVersion == 0 || src[14] != 1 || src[15] != 1 || ReadUInt32LittleEndian(src, 16) != 0 || ReadUInt32LittleEndian(src, 20) != 0) return false;
        bool unicode = version >= 21;
        int requiredHeader = unicode ? 564 : 512;
        if (src.Length < requiredHeader)
        {
            if (completeLength.HasValue) return false;
            result = BinaryResult("ndb", "application/vnd.ms-outlook", unicode ? "outlook-ndb:unicode;sampled-header" : "outlook-ndb:ansi;sampled-header");
            result.Confidence = "Medium";
            return true;
        }
        if (ReadUInt32LittleEndian(src, 4) != ComputeNdbCrc32(src.Slice(8, 464))) return false;
        if (unicode && ReadUInt32LittleEndian(src, 524) != ComputeNdbCrc32(src.Slice(8, 516))) return false;
        result = BinaryResult("ndb", "application/vnd.ms-outlook", unicode ? "outlook-ndb:unicode" : "outlook-ndb:ansi");
        result.Confidence = "Medium";
        result.Reason += ";root-pages-not-validated";
        return true;
    }

    private static uint ComputeNdbCrc32(ReadOnlySpan<byte> data)
    {
        uint crc = uint.MaxValue;
        for (int i = 0; i < data.Length; i++)
        {
            crc ^= data[i];
            for (int bit = 0; bit < 8; bit++) crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        }
        return ~crc;
    }

    internal static bool TryMatchMatroska(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchMatroska(src, src.Length, out result);

    internal static bool TryMatchMatroska(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!TryReadMatroskaDocumentType(src, out string? docType, out int headerEnd) ||
            !TryFindMatroskaSegment(src, headerEnd, completeLength, out bool sampledRootVoid,
                out bool rootScanBudgetExceeded, out bool sampledSegment)) return false;
        result = MatroskaResult(docType!, sampledRootVoid, rootScanBudgetExceeded, sampledSegment);
        return true;
    }

    private static bool TryReadMatroskaDocumentType(ReadOnlySpan<byte> src, out string? docType, out int headerEnd)
    {
        docType = null;
        headerEnd = 0;
        if (src.Length < 12 || !src.Slice(0, 4).SequenceEqual(new byte[] { 0x1A, 0x45, 0xDF, 0xA3 })) return false;
        int cursor = 4;
        if (!TryReadEbmlVInt(src, ref cursor, stripMarker: true, out ulong headerLength) || headerLength > 4096 || headerLength > (ulong)(src.Length - cursor)) return false;
        headerEnd = cursor + (int)headerLength;
        ulong ebmlVersion = 1, ebmlReadVersion = 1, maxIdLength = 4, maxSizeLength = 8;
        ulong docTypeVersion = 1, docTypeReadVersion = 1;
        var seen = new System.Collections.Generic.HashSet<ulong>();
        while (cursor < headerEnd)
        {
            if (!TryReadEbmlVInt(src.Slice(0, headerEnd), ref cursor, stripMarker: false, out ulong id)) return false;
            if (!TryReadEbmlVInt(src.Slice(0, headerEnd), ref cursor, stripMarker: true, out ulong length) || length > (ulong)(headerEnd - cursor)) return false;
            bool standardField = id is 0x4282 or 0x4286 or 0x42F7 or 0x42F2 or 0x42F3 or 0x4287 or 0x4285;
            if (standardField && !seen.Add(id)) return false;
            if (id == 0x4282)
            {
                if (length is < 4 or > 8) return false;
                docType = System.Text.Encoding.ASCII.GetString(src.Slice(cursor, (int)length).ToArray());
            }
            else if (id is 0x4286 or 0x42F7 or 0x42F2 or 0x42F3 or 0x4287 or 0x4285)
            {
                if (!TryReadEbmlUnsigned(src.Slice(cursor, (int)length), out ulong value)) return false;
                if (id == 0x4286) ebmlVersion = value;
                else if (id == 0x42F7) ebmlReadVersion = value;
                else if (id == 0x42F2) maxIdLength = value;
                else if (id == 0x42F3) maxSizeLength = value;
                else if (id == 0x4287) docTypeVersion = value;
                else docTypeReadVersion = value;
            }
            cursor += (int)length;
        }
        return docType is "matroska" or "webm" && ebmlVersion == 1 && ebmlReadVersion == 1 &&
               maxIdLength == 4 && maxSizeLength is >= 1 and <= 8 && docTypeVersion >= 1 &&
               docTypeReadVersion >= 1 && docTypeReadVersion <= docTypeVersion &&
               (docType != "webm" || docTypeReadVersion <= 2);
    }

    private static bool TryReadEbmlUnsigned(ReadOnlySpan<byte> valueBytes, out ulong value)
    {
        value = 0;
        if (valueBytes.Length is < 1 or > 8) return false;
        for (int i = 0; i < valueBytes.Length; i++) value = (value << 8) | valueBytes[i];
        return true;
    }

    private static bool TryFindMatroskaSegment(ReadOnlySpan<byte> src, int cursor, long? completeLength,
        out bool sampledRootVoid, out bool rootScanBudgetExceeded, out bool sampledSegment)
    {
        sampledRootVoid = false;
        rootScanBudgetExceeded = false;
        sampledSegment = false;
        int remainingElements = Math.Max(1, Settings.DetectionReadBudgetBytes / 64);
        bool foundSegment = false;
        while (cursor < src.Length)
        {
            if (remainingElements-- == 0)
            {
                rootScanBudgetExceeded = true;
                return foundSegment;
            }
            if (src.Length - cursor >= 4 && src.Slice(cursor, 4).SequenceEqual(new byte[] { 0x18, 0x53, 0x80, 0x67 }))
            {
                if (foundSegment) return false;
                foundSegment = true;
                cursor += 4;
                if (!TryReadEbmlSize(src, ref cursor, out ulong segmentLength, out bool unknownLength)) return false;
                if (completeLength.HasValue && cursor > completeLength.Value) return false;
                ulong availableLength = (ulong)Math.Max(0, src.Length - cursor);
                ulong? completeSegmentLength = unknownLength
                    ? completeLength.HasValue ? (ulong)(completeLength.Value - cursor) : null
                    : segmentLength;
                if (completeLength.HasValue && (cursor > completeLength.Value || !unknownLength && segmentLength > (ulong)(completeLength.Value - cursor))) return false;
                MatroskaSegmentStatus status = InspectMatroskaSegmentChildren(src.Slice(cursor), completeSegmentLength);
                if (status == MatroskaSegmentStatus.Invalid) return false;
                sampledSegment = status == MatroskaSegmentStatus.Sampled;
                if (!completeLength.HasValue && (!completeSegmentLength.HasValue || completeSegmentLength.Value > availableLength)) sampledSegment = true;
                if (!completeLength.HasValue || unknownLength || segmentLength > availableLength) return true;
                cursor += checked((int)segmentLength);
                continue;
            }
            if (!TryReadEbmlVInt(src, ref cursor, stripMarker: false, out ulong id) || id != 0xEC ||
                !TryReadEbmlVInt(src, ref cursor, stripMarker: true, out ulong length)) return false;
            if (length > (ulong)(src.Length - cursor))
            {
                if (completeLength.HasValue) return false;
                sampledRootVoid = true;
                return true;
            }
            cursor += (int)length;
            if (cursor == src.Length && !completeLength.HasValue)
            {
                sampledRootVoid = true;
                return true;
            }
        }
        return foundSegment && (!completeLength.HasValue || cursor == completeLength.Value);
    }

    private static ContentTypeDetectionResult MatroskaResult(string docType, bool sampledRootVoid = false,
        bool rootScanBudgetExceeded = false, bool sampledSegment = false)
    {
        var result = docType == "webm"
            ? BinaryResult("webm", "application/webm", "ebml:doctype=webm")
            : BinaryResult("matroska", "application/x-matroska", "ebml:doctype=matroska");
        result.Confidence = "Medium";
        result.Reason += ";segment-child-semantics-not-validated";
        if (sampledRootVoid)
        {
            result.Confidence = "Medium";
            result.Reason += ";sampled-root-void";
        }
        if (rootScanBudgetExceeded)
        {
            result.Confidence = "Medium";
            result.Reason += ";root-scan-budget";
        }
        if (sampledSegment)
        {
            result.Confidence = "Medium";
            result.Reason += ";sampled-segment";
        }
        return result;
    }

    private enum MatroskaSegmentStatus { Invalid, Sampled, Complete }

    private static MatroskaSegmentStatus InspectMatroskaSegmentChildren(ReadOnlySpan<byte> payload, ulong? completeLength)
    {
        int cursor = 0;
        bool info = false, tracks = false;
        int remainingElements = Math.Max(1, Settings.DetectionReadBudgetBytes / 16);
        ulong scanLength = completeLength ?? (ulong)payload.Length;
        while ((ulong)cursor < scanLength)
        {
            if (remainingElements-- == 0) return MatroskaSegmentStatus.Sampled;
            if (cursor >= payload.Length) return MatroskaSegmentStatus.Sampled;
            if (!TryReadEbmlVInt(payload, ref cursor, stripMarker: false, out ulong id) ||
                !TryReadEbmlSize(payload, ref cursor, out ulong length, out bool unknownLength))
                return completeLength.HasValue && completeLength.Value <= (ulong)payload.Length
                    ? MatroskaSegmentStatus.Invalid : MatroskaSegmentStatus.Sampled;
            if (unknownLength)
                return id == 0x1F43B675 && info && tracks ? MatroskaSegmentStatus.Complete : MatroskaSegmentStatus.Invalid;
            if (length > scanLength - (ulong)cursor) return MatroskaSegmentStatus.Invalid;
            if (id == 0x1549A966) { if (length == 0 || info) return MatroskaSegmentStatus.Invalid; info = true; }
            if (id == 0x1654AE6B) { if (length == 0 || tracks) return MatroskaSegmentStatus.Invalid; tracks = true; }
            if (length > (ulong)(payload.Length - cursor)) return MatroskaSegmentStatus.Sampled;
            cursor += (int)length;
        }
        return (ulong)cursor == scanLength && info && tracks ? MatroskaSegmentStatus.Complete : MatroskaSegmentStatus.Invalid;
    }

    internal static bool TryMatchMatroska(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try
        {
            if (stream.Length < 16) return false;
            int readLength = (int)Math.Min(stream.Length, 4L + 8L + 4096L);
            stream.Seek(0, SeekOrigin.Begin);
            var bytes = new byte[readLength];
            int read = ReadHeaderBytes(stream, bytes);
            if (!TryReadMatroskaDocumentType(new ReadOnlySpan<byte>(bytes, 0, read), out string? docType, out int headerEnd)) return false;
            long cursor = headerEnd;
            int remainingElements = Math.Max(1, Settings.DetectionReadBudgetBytes / 64);
            bool foundSegment = false;
            bool sampledSegment = false;
            while (cursor < stream.Length)
            {
                if (remainingElements-- == 0)
                {
                    if (!foundSegment) return false;
                    result = MatroskaResult(docType!, rootScanBudgetExceeded: true);
                    return true;
                }
                if (stream.Length - cursor >= 4 && TryReadAt(stream, cursor, 4, out var idBytes) &&
                    new ReadOnlySpan<byte>(idBytes).SequenceEqual(new byte[] { 0x18, 0x53, 0x80, 0x67 }))
                {
                    if (foundSegment) return false;
                    foundSegment = true;
                    stream.Seek(cursor + 4, SeekOrigin.Begin);
                    if (!TryReadEbmlSize(stream, out ulong segmentLength, out bool unknownLength) ||
                        (!unknownLength && segmentLength > (ulong)(stream.Length - stream.Position))) return false;
                    long segmentPayloadOffset = stream.Position;
                    ulong completeSegmentLength = unknownLength ? (ulong)(stream.Length - segmentPayloadOffset) : segmentLength;
                    int segmentReadLength = (int)Math.Min(completeSegmentLength, (ulong)Math.Max(16, Settings.DetectionReadBudgetBytes));
                    if (!TryReadAt(stream, segmentPayloadOffset, segmentReadLength, out var segmentBytes)) return false;
                    MatroskaSegmentStatus status = InspectMatroskaSegmentChildren(new ReadOnlySpan<byte>(segmentBytes), completeSegmentLength);
                    if (status == MatroskaSegmentStatus.Invalid) return false;
                    sampledSegment = status == MatroskaSegmentStatus.Sampled;
                    if (unknownLength)
                    {
                        result = MatroskaResult(docType!, sampledSegment: sampledSegment);
                        return true;
                    }
                    cursor = segmentPayloadOffset + checked((long)segmentLength);
                    continue;
                }
                if (!TryReadAt(stream, cursor, 1, out var voidId) || voidId[0] != 0xEC) return false;
                stream.Seek(cursor + 1, SeekOrigin.Begin);
                if (!TryReadEbmlVInt(stream, out ulong voidLength)) return false;
                long payloadOffset = stream.Position;
                if (voidLength > (ulong)(stream.Length - payloadOffset)) return false;
                cursor = payloadOffset + (long)voidLength;
            }
            if (!foundSegment) return false;
            result = MatroskaResult(docType!, sampledSegment: sampledSegment);
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

    private static bool TryReadEbmlVInt(ReadOnlySpan<byte> src, ref int cursor, bool stripMarker, out ulong value)
    {
        value = 0;
        if (cursor >= src.Length) return false;
        byte first = src[cursor];
        int length = 1;
        byte marker = 0x80;
        while (length <= 8 && (first & marker) == 0) { marker >>= 1; length++; }
        if (length > 8 || cursor + length > src.Length) return false;
        value = stripMarker ? (ulong)(first & (marker - 1)) : first;
        for (int i = 1; i < length; i++) value = (value << 8) | src[cursor + i];
        cursor += length;
        if (stripMarker)
        {
            ulong unknown = length == 8 ? 0x00FFFFFFFFFFFFFFUL : (1UL << (7 * length)) - 1;
            if (value == unknown) return false;
        }
        return true;
    }

    private static bool TryReadEbmlSize(ReadOnlySpan<byte> src, ref int cursor, out ulong value, out bool unknown)
    {
        value = 0;
        unknown = false;
        if (cursor >= src.Length) return false;
        byte first = src[cursor];
        int length = 1;
        byte marker = 0x80;
        while (length <= 8 && (first & marker) == 0) { marker >>= 1; length++; }
        if (length > 8 || cursor + length > src.Length) return false;
        value = (ulong)(first & (marker - 1));
        for (int index = 1; index < length; index++) value = (value << 8) | src[cursor + index];
        cursor += length;
        ulong unknownValue = length == 8 ? 0x00FFFFFFFFFFFFFFUL : (1UL << (7 * length)) - 1;
        unknown = value == unknownValue;
        return true;
    }

    private static bool TryReadEbmlSize(Stream stream, out ulong value, out bool unknown)
    {
        value = 0;
        unknown = false;
        int firstValue = stream.ReadByte();
        if (firstValue < 0) return false;
        byte first = (byte)firstValue;
        int length = 1;
        byte marker = 0x80;
        while (length <= 8 && (first & marker) == 0) { marker >>= 1; length++; }
        if (length > 8) return false;
        value = (ulong)(first & (marker - 1));
        for (int index = 1; index < length; index++)
        {
            int current = stream.ReadByte();
            if (current < 0) return false;
            value = (value << 8) | (byte)current;
        }
        ulong unknownValue = length == 8 ? 0x00FFFFFFFFFFFFFFUL : (1UL << (7 * length)) - 1;
        unknown = value == unknownValue;
        return true;
    }

    private static bool TryReadEbmlVInt(Stream stream, out ulong value)
    {
        value = 0;
        int firstValue = stream.ReadByte();
        if (firstValue < 0) return false;
        byte first = (byte)firstValue;
        int length = 1;
        byte marker = 0x80;
        while (length <= 8 && (first & marker) == 0) { marker >>= 1; length++; }
        if (length > 8) return false;
        value = (ulong)(first & (marker - 1));
        for (int index = 1; index < length; index++)
        {
            int current = stream.ReadByte();
            if (current < 0) return false;
            value = (value << 8) | (byte)current;
        }
        ulong unknown = length == 8 ? 0x00FFFFFFFFFFFFFFUL : (1UL << (7 * length)) - 1;
        return value != unknown;
    }
}
