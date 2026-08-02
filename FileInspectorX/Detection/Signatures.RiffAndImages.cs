namespace FileInspectorX;

/// <summary>
/// RIFF container and common image formats (TIFF/GLB) detection.
/// </summary>
internal static partial class Signatures {
    internal static bool TryMatchRiff(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 12) return false;
        if (!src.Slice(0, 4).SequenceEqual("RIFF"u8)) return false;
        var fcc = src.Slice(8, 4);
        if (fcc.SequenceEqual("WAVE"u8)) { result = new ContentTypeDetectionResult { Extension = "wav", MimeType = "audio/wav", Confidence = "High", Reason = "riff:wav" }; return true; }
        if (fcc.SequenceEqual("AVI "u8)) { result = new ContentTypeDetectionResult { Extension = "avi", MimeType = "video/x-msvideo", Confidence = "High", Reason = "riff:avi" }; return true; }
        if (fcc.SequenceEqual("WEBP"u8)) { result = new ContentTypeDetectionResult { Extension = "webp", MimeType = "image/webp", Confidence = "High", Reason = "riff:webp" }; return true; }
        return false;
    }

    internal static bool TryMatchGlb(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchGlb(src, src.Length, out result);

    internal static bool TryMatchGlb(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 20 || !src.Slice(0, 4).SequenceEqual("glTF"u8) || completeLength > uint.MaxValue) return false;
        uint version = ReadUInt32LittleEndian(src, 4);
        uint totalLength = ReadUInt32LittleEndian(src, 8);
        if (completeLength.HasValue && totalLength != completeLength.Value) return false;
        if (!completeLength.HasValue && totalLength < src.Length) return false;

        uint contentLength = ReadUInt32LittleEndian(src, 12);
        uint contentType = ReadUInt32LittleEndian(src, 16);
        if (version == 1) {
            if (totalLength < 21 || contentLength == 0 || contentLength > totalLength - 20 || contentType != 0 ||
                !HasGlbJsonObjectStart(src, 20, contentLength)) return false;
            result = GlbResult(version, completeLength.HasValue);
            return true;
        }

        if (version != 2 || totalLength < 21 || (totalLength & 3) != 0 || contentType != 0x4E4F534A ||
            contentLength == 0 || (contentLength & 3) != 0 || contentLength > totalLength - 20 ||
            !HasGlbJsonObjectStart(src, 20, contentLength)) return false;
        if (completeLength.HasValue && totalLength <= src.Length && !TryValidateGlbV2Chunks(src.Slice(0, (int)totalLength))) return false;
        result = GlbResult(version, completeLength.HasValue);
        return true;
    }

    internal static bool TryMatchGlb(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try
        {
            if (stream.Length < 20 || stream.Length > uint.MaxValue) return false;
            int prefixLength = (int)Math.Min(stream.Length, Math.Max(20, Settings.DetectionReadBudgetBytes));
            if (!TryReadAt(stream, 0, prefixLength, out var prefix)) return false;
            var src = new ReadOnlySpan<byte>(prefix);
            if (!TryMatchGlb(src, completeLength: null, out var sampled)) return false;
            uint version = ReadUInt32LittleEndian(src, 4);
            uint totalLength = ReadUInt32LittleEndian(src, 8);
            if (totalLength != stream.Length) return false;
            if (version == 1)
            {
                result = GlbResult(version, complete: true);
                return true;
            }

            long cursor = 12;
            int remainingHeaders = Math.Max(1, Settings.DetectionReadBudgetBytes / 64);
            bool sawJson = false;
            bool sawBin = false;
            while (cursor < stream.Length)
            {
                if (remainingHeaders-- == 0)
                {
                    result = sampled;
                    result!.Reason += ";chunk-scan-budget";
                    return true;
                }
                if (stream.Length - cursor < 8 || !TryReadAt(stream, cursor, 8, out var chunkHeader)) return false;
                var header = new ReadOnlySpan<byte>(chunkHeader);
                uint chunkLength = ReadUInt32LittleEndian(header, 0);
                uint chunkType = ReadUInt32LittleEndian(header, 4);
                if ((chunkLength & 3) != 0 || chunkLength > stream.Length - cursor - 8) return false;
                if (chunkType == 0x4E4F534A)
                {
                    if (sawJson || cursor != 12) return false;
                    sawJson = true;
                }
                else if (chunkType == 0x004E4942)
                {
                    if (!sawJson || sawBin) return false;
                    sawBin = true;
                }
                cursor += 8 + chunkLength;
            }
            if (cursor != stream.Length || !sawJson) return false;
            result = GlbResult(version, complete: true);
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

    private static bool TryValidateGlbV2Chunks(ReadOnlySpan<byte> src)
    {
        int cursor = 12;
        bool sawJson = false;
        bool sawBin = false;
        while (cursor < src.Length)
        {
            if (src.Length - cursor < 8) return false;
            uint chunkLength = ReadUInt32LittleEndian(src, cursor);
            uint chunkType = ReadUInt32LittleEndian(src, cursor + 4);
            if ((chunkLength & 3) != 0 || chunkLength > (uint)(src.Length - cursor - 8)) return false;
            if (chunkType == 0x4E4F534A)
            {
                if (sawJson || cursor != 12) return false;
                sawJson = true;
            }
            else if (chunkType == 0x004E4942)
            {
                if (!sawJson || sawBin) return false;
                sawBin = true;
            }
            cursor += 8 + (int)chunkLength;
        }
        return cursor == src.Length && sawJson;
    }

    private static ContentTypeDetectionResult GlbResult(uint version, bool complete) => new() {
        Extension = "glb",
        MimeType = "model/gltf-binary",
        Confidence = complete ? "High" : "Medium",
        Reason = $"glb:v{version}+json-" + (version == 1 ? "content" : "chunk") +
                 (complete ? string.Empty : ";sampled-length-unknown")
    };

    private static bool HasGlbJsonObjectStart(ReadOnlySpan<byte> src, int offset, uint declaredLength) {
        int available = (int)Math.Min(declaredLength, (uint)Math.Max(0, src.Length - offset));
        for (int i = 0; i < available; i++) {
            byte current = src[offset + i];
            if (current is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n') continue;
            return current == (byte)'{';
        }
        return false;
    }

    internal static bool TryMatchTiff(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchTiff(src, src.Length, out result);

    internal static bool TryMatchTiff(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result) {
        result = null;
        if (!TryReadTiffHeader(src, out bool littleEndian, out bool isBigTiff, out ulong firstIfd)) return false;
        TiffDirectoryStatus status = InspectTiffDirectories(src, completeLength, littleEndian, isBigTiff, firstIfd);
        if (status == TiffDirectoryStatus.Invalid) return false;
        result = TiffResult(littleEndian, isBigTiff);
        if (status == TiffDirectoryStatus.Sampled) { result.Confidence = "Medium"; result.Reason += ";sampled-ifd-offset;sampled-ifd-chain"; }
        return true;
    }

    internal static bool TryMatchTiff(Stream stream, out ContentTypeDetectionResult? result) {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try {
            if (stream.Length < 8 || !TryReadAt(stream, 0, (int)Math.Min(16, stream.Length), out var header) ||
                !TryReadTiffHeader(new ReadOnlySpan<byte>(header), out bool littleEndian, out bool isBigTiff, out ulong firstIfd)) return false;
            TiffDirectoryStatus status = InspectTiffDirectories(stream, littleEndian, isBigTiff, firstIfd);
            if (status == TiffDirectoryStatus.Invalid) return false;
            result = TiffResult(littleEndian, isBigTiff);
            if (status == TiffDirectoryStatus.Sampled) { result.Confidence = "Medium"; result.Reason += ";ifd-budget"; }
            return true;
        } catch {
            result = null;
            return false;
        } finally {
            try { stream.Seek(originalPosition, SeekOrigin.Begin); } catch { }
        }
    }

    private static bool TryReadTiffHeader(ReadOnlySpan<byte> src, out bool littleEndian, out bool isBigTiff, out ulong firstIfd) {
        littleEndian = false;
        isBigTiff = false;
        firstIfd = 0;
        if (src.Length < 8) return false;
        if (src[0] == 0x49 && src[1] == 0x49) littleEndian = true;
        else if (src[0] == 0x4D && src[1] == 0x4D) littleEndian = false;
        else return false;
        ushort magic = ReadUInt16(src, 2, littleEndian);
        if (magic == 42) {
            firstIfd = ReadUInt32(src, 4, littleEndian);
            if (firstIfd < 8 || (firstIfd & 1) != 0) return false;
            return true;
        }
        if (magic != 43 || src.Length < 16) return false;
        if (ReadUInt16(src, 4, littleEndian) != 8 || ReadUInt16(src, 6, littleEndian) != 0) return false;
        isBigTiff = true;
        firstIfd = ReadUInt64(src, 8, littleEndian);
        if (firstIfd < 16 || (firstIfd & 7) != 0) return false;
        return true;
    }

    private static bool IsTiffDirectoryRangeValid(ulong firstIfd, ulong entries, bool isBigTiff, ulong completeLength) {
        ulong countSize = isBigTiff ? 8UL : 2UL;
        ulong entrySize = isBigTiff ? 20UL : 12UL;
        ulong nextOffsetSize = isBigTiff ? 8UL : 4UL;
        if (firstIfd > completeLength || firstIfd > ulong.MaxValue - countSize - nextOffsetSize) return false;
        ulong fixedLength = firstIfd + countSize + nextOffsetSize;
        if (entries > (ulong.MaxValue - fixedLength) / entrySize) return false;
        return fixedLength + entries * entrySize <= completeLength;
    }

    private enum TiffDirectoryStatus { Invalid, Sampled, Complete }

    private static TiffDirectoryStatus InspectTiffDirectories(ReadOnlySpan<byte> src, long? completeLength,
        bool littleEndian, bool isBigTiff, ulong firstIfd) {
        if (completeLength < 0) return TiffDirectoryStatus.Invalid;
        ulong totalLength = completeLength.HasValue ? (ulong)completeLength.Value : (ulong)src.Length;
        var visited = new System.Collections.Generic.HashSet<ulong>();
        int remainingEntries = Math.Max(1, Settings.DetectionReadBudgetBytes / (isBigTiff ? 20 : 12));
        ulong current = firstIfd;
        while (current != 0) {
            if (!visited.Add(current) || current > int.MaxValue) return TiffDirectoryStatus.Invalid;
            int countSize = isBigTiff ? 8 : 2;
            if (current + (ulong)countSize > totalLength) return completeLength.HasValue ? TiffDirectoryStatus.Invalid : TiffDirectoryStatus.Sampled;
            if (current + (ulong)countSize > (ulong)src.Length) return completeLength.HasValue ? TiffDirectoryStatus.Invalid : TiffDirectoryStatus.Sampled;
            int offset = (int)current;
            ulong count = isBigTiff ? ReadUInt64(src, offset, littleEndian) : ReadUInt16(src, offset, littleEndian);
            if (!IsTiffDirectoryRangeValid(current, count, isBigTiff, totalLength)) return TiffDirectoryStatus.Invalid;
            if (count > (ulong)remainingEntries) return TiffDirectoryStatus.Sampled;
            int entrySize = isBigTiff ? 20 : 12;
            int inlineSize = isBigTiff ? 8 : 4;
            ulong directoryEnd = current + (ulong)countSize + count * (ulong)entrySize + (ulong)inlineSize;
            if (directoryEnd > (ulong)src.Length) return completeLength.HasValue ? TiffDirectoryStatus.Invalid : TiffDirectoryStatus.Sampled;
            for (ulong index = 0; index < count; index++) {
                int entry = checked(offset + countSize + (int)index * entrySize);
                ushort type = ReadUInt16(src, entry + 2, littleEndian);
                int typeSize = GetTiffTypeSize(type, isBigTiff);
                ulong valueCount = isBigTiff ? ReadUInt64(src, entry + 4, littleEndian) : ReadUInt32(src, entry + 4, littleEndian);
                if (typeSize == 0 || valueCount > ulong.MaxValue / (uint)typeSize) return TiffDirectoryStatus.Invalid;
                ulong valueLength = valueCount * (uint)typeSize;
                if (valueLength > (ulong)inlineSize) {
                    ulong valueOffset = isBigTiff ? ReadUInt64(src, entry + 12, littleEndian) : ReadUInt32(src, entry + 8, littleEndian);
                    ulong alignment = isBigTiff ? 8UL : 2UL;
                    if (valueOffset < (isBigTiff ? 16UL : 8UL) || (valueOffset & (alignment - 1)) != 0 ||
                        valueOffset > totalLength || valueLength > totalLength - valueOffset) return TiffDirectoryStatus.Invalid;
                }
            }
            remainingEntries -= (int)count;
            int nextOffset = checked(offset + countSize + (int)count * entrySize);
            current = isBigTiff ? ReadUInt64(src, nextOffset, littleEndian) : ReadUInt32(src, nextOffset, littleEndian);
            if (current != 0 && (current < (isBigTiff ? 16UL : 8UL) || (current & (isBigTiff ? 7UL : 1UL)) != 0))
                return TiffDirectoryStatus.Invalid;
        }
        return TiffDirectoryStatus.Complete;
    }

    private static TiffDirectoryStatus InspectTiffDirectories(Stream stream, bool littleEndian, bool isBigTiff, ulong firstIfd) {
        var visited = new System.Collections.Generic.HashSet<ulong>();
        int remainingEntries = Math.Max(1, Settings.DetectionReadBudgetBytes / (isBigTiff ? 20 : 12));
        ulong current = firstIfd;
        while (current != 0) {
            if (!visited.Add(current) || current > long.MaxValue) return TiffDirectoryStatus.Invalid;
            int countSize = isBigTiff ? 8 : 2;
            if (!TryReadAt(stream, (long)current, countSize, out var countBytes)) return TiffDirectoryStatus.Invalid;
            ulong count = isBigTiff ? ReadUInt64(new ReadOnlySpan<byte>(countBytes), 0, littleEndian) : ReadUInt16(new ReadOnlySpan<byte>(countBytes), 0, littleEndian);
            if (!IsTiffDirectoryRangeValid(current, count, isBigTiff, (ulong)stream.Length)) return TiffDirectoryStatus.Invalid;
            if (count > (ulong)remainingEntries) return TiffDirectoryStatus.Sampled;
            int entrySize = isBigTiff ? 20 : 12;
            int nextSize = isBigTiff ? 8 : 4;
            long payloadLength = checked((long)count * entrySize + nextSize);
            if (payloadLength > int.MaxValue || !TryReadAt(stream, (long)current + countSize, (int)payloadLength, out var payloadBytes)) return TiffDirectoryStatus.Invalid;
            var payload = new ReadOnlySpan<byte>(payloadBytes);
            for (ulong index = 0; index < count; index++) {
                int entry = checked((int)index * entrySize);
                int typeSize = GetTiffTypeSize(ReadUInt16(payload, entry + 2, littleEndian), isBigTiff);
                ulong valueCount = isBigTiff ? ReadUInt64(payload, entry + 4, littleEndian) : ReadUInt32(payload, entry + 4, littleEndian);
                if (typeSize == 0 || valueCount > ulong.MaxValue / (uint)typeSize) return TiffDirectoryStatus.Invalid;
                ulong valueLength = valueCount * (uint)typeSize;
                if (valueLength > (ulong)nextSize) {
                    ulong valueOffset = isBigTiff ? ReadUInt64(payload, entry + 12, littleEndian) : ReadUInt32(payload, entry + 8, littleEndian);
                    ulong alignment = isBigTiff ? 8UL : 2UL;
                    if (valueOffset < (isBigTiff ? 16UL : 8UL) || (valueOffset & (alignment - 1)) != 0 ||
                        valueOffset > (ulong)stream.Length || valueLength > (ulong)stream.Length - valueOffset) return TiffDirectoryStatus.Invalid;
                }
            }
            remainingEntries -= (int)count;
            int nextOffset = checked((int)count * entrySize);
            current = isBigTiff ? ReadUInt64(payload, nextOffset, littleEndian) : ReadUInt32(payload, nextOffset, littleEndian);
            if (current != 0 && (current < (isBigTiff ? 16UL : 8UL) || (current & (isBigTiff ? 7UL : 1UL)) != 0)) return TiffDirectoryStatus.Invalid;
        }
        return TiffDirectoryStatus.Complete;
    }

    private static int GetTiffTypeSize(ushort type, bool isBigTiff) => type switch {
        1 or 2 or 6 or 7 => 1,
        3 or 8 => 2,
        4 or 9 or 11 or 13 => 4,
        5 or 10 or 12 => 8,
        16 or 17 or 18 when isBigTiff => 8,
        _ => 0
    };

    private static ContentTypeDetectionResult TiffResult(bool littleEndian, bool isBigTiff) => new() {
        Extension = "tif",
        MimeType = "image/tiff",
        Confidence = "High",
        Reason = isBigTiff
            ? (littleEndian ? "bigtiff:le+ifd" : "bigtiff:be+ifd")
            : (littleEndian ? "tiff:le+ifd" : "tiff:be+ifd")
    };
}
