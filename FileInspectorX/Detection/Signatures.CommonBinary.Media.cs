namespace FileInspectorX;

/// <summary>
/// Structural validation for common compressed image, archive, and audio formats.
/// </summary>
internal static partial class Signatures
{
    internal static bool TryMatchJpeg(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        CommonBinaryValidation status = ValidateJpeg(src, completeLength);
        if (status == CommonBinaryValidation.Invalid) return false;
        result = BinaryResult("jpg", "image/jpeg", status == CommonBinaryValidation.Complete
            ? "jpeg:markers+scan+eoi" : "jpeg:soi+sampled-markers");
        if (status == CommonBinaryValidation.Sampled) result.Confidence = "Medium";
        return true;
    }

    private static CommonBinaryValidation ValidateJpeg(ReadOnlySpan<byte> src, long? completeLength)
    {
        if (src.Length < 4 || src[0] != 0xFF || src[1] != 0xD8) return CommonBinaryValidation.Invalid;
        bool complete = completeLength.HasValue && completeLength.Value <= src.Length;
        int limit = complete ? checked((int)completeLength!.Value) : src.Length;
        int cursor = 2;
        bool sawFrame = false, sawScan = false, entropy = false;
        while (cursor < limit)
        {
            byte marker;
            if (entropy)
            {
                while (cursor < limit && src[cursor] != 0xFF) cursor++;
                if (cursor >= limit) return complete ? CommonBinaryValidation.Invalid : CommonBinaryValidation.Sampled;
                while (cursor < limit && src[cursor] == 0xFF) cursor++;
                if (cursor >= limit) return complete ? CommonBinaryValidation.Invalid : CommonBinaryValidation.Sampled;
                marker = src[cursor++];
                if (marker == 0 || marker is >= 0xD0 and <= 0xD7) continue;
                entropy = false;
            }
            else
            {
                if (src[cursor++] != 0xFF) return CommonBinaryValidation.Invalid;
                while (cursor < limit && src[cursor] == 0xFF) cursor++;
                if (cursor >= limit) return complete ? CommonBinaryValidation.Invalid : CommonBinaryValidation.Sampled;
                marker = src[cursor++];
            }
            if (marker == 0 || marker == 0xD8) return CommonBinaryValidation.Invalid;
            if (marker == 0xD9) return sawFrame && sawScan ? CommonBinaryValidation.Complete : CommonBinaryValidation.Invalid;
            if (marker == 0x01 || marker is >= 0xD0 and <= 0xD7) continue;
            if (cursor + 2 > limit) return complete ? CommonBinaryValidation.Invalid : CommonBinaryValidation.Sampled;
            ushort segmentLength = ReadUInt16BigEndian(src, cursor);
            if (segmentLength < 2) return CommonBinaryValidation.Invalid;
            long segmentEnd = (long)cursor + segmentLength;
            if (completeLength.HasValue && segmentEnd > completeLength.Value) return CommonBinaryValidation.Invalid;
            if (segmentEnd > limit) return complete ? CommonBinaryValidation.Invalid : CommonBinaryValidation.Sampled;
            if (IsJpegStartOfFrame(marker))
            {
                if (segmentLength < 8 || src[cursor + 2] is not (8 or 12 or 16) ||
                    ReadUInt16BigEndian(src, cursor + 3) == 0 || ReadUInt16BigEndian(src, cursor + 5) == 0) return CommonBinaryValidation.Invalid;
                sawFrame = true;
            }
            if (marker == 0xDA)
            {
                if (!sawFrame || segmentLength < 6) return CommonBinaryValidation.Invalid;
                sawScan = true;
                entropy = true;
            }
            cursor = (int)segmentEnd;
        }
        return complete ? CommonBinaryValidation.Invalid : CommonBinaryValidation.Sampled;
    }

    private static bool IsJpegStartOfFrame(byte marker)
        => marker is >= 0xC0 and <= 0xCF && marker is not (0xC4 or 0xC8 or 0xCC);

    internal static bool TryMatchGzip(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchGzip(src, src.Length, out result);

    internal static bool TryMatchGzip(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 10 || src[0] != 0x1F || src[1] != 0x8B || src[2] != 8 || (src[3] & 0xE0) != 0) return false;
        bool complete = completeLength.HasValue && completeLength.Value <= src.Length;
        if (complete && !TryValidateGzipMember(src.Slice(0, checked((int)completeLength!.Value)))) return false;
        result = BinaryResult("gz", "application/gzip", complete ? "gzip:member-framing" : "gzip:sampled-member-header");
        result.Confidence = "Medium";
        return true;
    }

    private static bool TryValidateGzipMember(ReadOnlySpan<byte> src)
    {
        if (src.Length < 19) return false;
        byte flags = src[3];
        int cursor = 10;
        if ((flags & 4) != 0)
        {
            if (cursor + 2 > src.Length - 8) return false;
            ushort extraLength = ReadUInt16LittleEndian(src, cursor);
            cursor += 2;
            if (extraLength > src.Length - 8 - cursor) return false;
            cursor += extraLength;
        }
        if ((flags & 8) != 0 && !TrySkipZeroTerminatedField(src, ref cursor)) return false;
        if ((flags & 16) != 0 && !TrySkipZeroTerminatedField(src, ref cursor)) return false;
        if ((flags & 2) != 0)
        {
            if (cursor + 2 > src.Length - 8) return false;
            cursor += 2;
        }
        return cursor < src.Length - 8;
    }

    private static bool TrySkipZeroTerminatedField(ReadOnlySpan<byte> src, ref int cursor)
    {
        int limit = src.Length - 8;
        while (cursor < limit && src[cursor] != 0) cursor++;
        if (cursor >= limit) return false;
        cursor++;
        return true;
    }

    internal static bool TryMatchBzip2(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchBzip2(src, src.Length, out result);

    internal static bool TryMatchBzip2(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 10 || src[0] != (byte)'B' || src[1] != (byte)'Z' || src[2] != (byte)'h' || src[3] is < (byte)'1' or > (byte)'9') return false;
        bool block = src.Slice(4, 6).SequenceEqual(new byte[] { 0x31, 0x41, 0x59, 0x26, 0x53, 0x59 });
        bool end = src.Slice(4, 6).SequenceEqual(new byte[] { 0x17, 0x72, 0x45, 0x38, 0x50, 0x90 });
        if (!block && !end) return false;
        result = BinaryResult("bz2", "application/x-bzip2", "bzip2:stream-header;payload-not-validated");
        result.Confidence = "Medium";
        return true;
    }

    internal static bool TryMatchOgg(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 27 || !src.Slice(0, 4).SequenceEqual("OggS"u8) || src[4] != 0 || (src[5] & 0xF8) != 0) return false;
        bool complete = completeLength.HasValue && completeLength.Value <= src.Length;
        CommonBinaryValidation status = ValidateOggPages(src, complete ? checked((int)completeLength!.Value) : src.Length, complete);
        if (status == CommonBinaryValidation.Invalid) return false;
        result = BinaryResult("ogg", "application/ogg", status == CommonBinaryValidation.Complete
            ? "ogg:pages+checksums" : "ogg:sampled-page-header");
        result.Confidence = "Medium";
        result.Reason += ";logical-stream-sequencing-not-validated";
        return true;
    }

    private static CommonBinaryValidation ValidateOggPages(ReadOnlySpan<byte> src, int limit, bool complete)
    {
        int cursor = 0;
        bool sawPage = false;
        while (cursor < limit)
        {
            if (limit - cursor < 27) return complete ? CommonBinaryValidation.Invalid : CommonBinaryValidation.Sampled;
            if (!src.Slice(cursor, 4).SequenceEqual("OggS"u8) || src[cursor + 4] != 0 || (src[cursor + 5] & 0xF8) != 0)
                return CommonBinaryValidation.Invalid;
            int segments = src[cursor + 26];
            if (limit - cursor < 27 + segments) return complete ? CommonBinaryValidation.Invalid : CommonBinaryValidation.Sampled;
            int payloadLength = 0;
            for (int index = 0; index < segments; index++) payloadLength += src[cursor + 27 + index];
            int pageLength = 27 + segments + payloadLength;
            if (pageLength > limit - cursor) return complete ? CommonBinaryValidation.Invalid : CommonBinaryValidation.Sampled;
            if (ReadUInt32LittleEndian(src, cursor + 22) != ComputeOggCrc(src.Slice(cursor, pageLength)))
                return CommonBinaryValidation.Invalid;
            sawPage = true;
            cursor += pageLength;
        }
        return complete && sawPage && cursor == limit ? CommonBinaryValidation.Complete : CommonBinaryValidation.Sampled;
    }

    private static uint ComputeOggCrc(ReadOnlySpan<byte> page)
    {
        uint crc = 0;
        for (int index = 0; index < page.Length; index++)
        {
            byte value = index is >= 22 and < 26 ? (byte)0 : page[index];
            crc ^= (uint)value << 24;
            for (int bit = 0; bit < 8; bit++) crc = (crc & 0x80000000) != 0 ? crc << 1 ^ 0x04C11DB7u : crc << 1;
        }
        return crc;
    }

    internal static bool TryMatchMp3(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 10 || !src.Slice(0, 3).SequenceEqual("ID3"u8)) return false;
        if (src[3] is < 2 or > 4 || src[4] == 0xFF || (src[6] & 0x80) != 0 || (src[7] & 0x80) != 0 || (src[8] & 0x80) != 0 || (src[9] & 0x80) != 0) return false;
        byte allowedFlags = src[3] switch { 2 => 0xC0, 3 => 0xE0, _ => 0xF0 };
        if ((src[5] & ~allowedFlags) != 0) return false;
        int tagSize = src[6] << 21 | src[7] << 14 | src[8] << 7 | src[9];
        long tagEnd = 10L + tagSize + (src[3] == 4 && (src[5] & 0x10) != 0 ? 10 : 0);
        if (completeLength.HasValue && tagEnd > completeLength.Value) return false;
        if (tagEnd > src.Length - 4)
        {
            if (completeLength.HasValue && completeLength.Value <= src.Length) return false;
            result = BinaryResult("mp3", "audio/mpeg", $"mp3:id3v2.{src[3]};sampled-tag");
            result.Confidence = "Medium";
            return true;
        }
        if (!TryGetMp3FrameLength(src.Slice((int)tagEnd, 4), out int frameLength) ||
            completeLength.HasValue && tagEnd + frameLength > completeLength.Value) return false;
        if (!completeLength.HasValue && tagEnd + frameLength > src.Length)
        {
            result = BinaryResult("mp3", "audio/mpeg", $"mp3:id3v2.{src[3]}+sampled-audio-frame");
            result.Confidence = "Medium";
            return true;
        }
        result = BinaryResult("mp3", "audio/mpeg", $"mp3:id3v2.{src[3]}+audio-frame");
        result.Confidence = "Medium";
        result.Reason += ";frame-chain-not-validated";
        return true;
    }

    private static bool TryGetMp3FrameLength(ReadOnlySpan<byte> header, out int length)
    {
        length = 0;
        uint value = ReadUInt32BigEndian(header, 0);
        if ((value & 0xFFE00000) != 0xFFE00000) return false;
        int version = (int)(value >> 19) & 3;
        int layer = (int)(value >> 17) & 3;
        int bitrateIndex = (int)(value >> 12) & 15;
        int rateIndex = (int)(value >> 10) & 3;
        int padding = (int)(value >> 9) & 1;
        if (version == 1 || layer == 0 || bitrateIndex is 0 or 15 || rateIndex == 3) return false;
        int[] rates = { 44100, 48000, 32000 };
        int sampleRate = rates[rateIndex] / (version == 3 ? 1 : version == 2 ? 2 : 4);
        int[][] mpeg1 = {
            new[] { 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448 },
            new[] { 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384 },
            new[] { 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320 }
        };
        int[] lowLayer1 = { 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256 };
        int[] lowOther = { 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160 };
        int layerIndex = 3 - layer;
        int bitrate = version == 3 ? mpeg1[layerIndex][bitrateIndex - 1] :
            layer == 3 ? lowLayer1[bitrateIndex - 1] : lowOther[bitrateIndex - 1];
        length = layer == 3 ? (12 * bitrate * 1000 / sampleRate + padding) * 4 :
            (version != 3 && layer == 1 ? 72 : 144) * bitrate * 1000 / sampleRate + padding;
        return length >= 4;
    }

    private enum CommonBinaryValidation { Invalid, Sampled, Complete }
}
