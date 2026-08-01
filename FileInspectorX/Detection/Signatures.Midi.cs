namespace FileInspectorX;

/// <summary>
/// Structural validation for Standard MIDI Files.
/// </summary>
internal static partial class Signatures
{
    internal static bool TryMatchMidi(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchMidi(src, src.Length, out result);

    internal static bool TryMatchMidi(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!TryReadMidiHeader(src, out ushort format, out ushort tracks)) return false;
        int cursor = 14;
        int foundTracks = 0;
        while (cursor < src.Length)
        {
            if (cursor + 8 > src.Length) {
                if (!completeLength.HasValue && (foundTracks == tracks || MatchesMidiTrackHeaderPrefix(src.Slice(cursor)))) {
                    result = MidiResult(format, tracks, complete: false);
                    return true;
                }
                return false;
            }
            bool isTrack = src.Slice(cursor, 4).SequenceEqual("MTrk"u8);
            uint chunkLength = ReadUInt32BigEndian(src, cursor + 4);
            cursor += 8;
            if (chunkLength > int.MaxValue) return false;
            if (chunkLength > src.Length - cursor) {
                if (!completeLength.HasValue && (foundTracks == tracks || isTrack && foundTracks < tracks && IsValidMidiTrackPrefix(src.Slice(cursor)))) {
                    result = MidiResult(format, tracks, complete: false);
                    return true;
                }
                return false;
            }
            if (isTrack)
            {
                if (foundTracks >= tracks || !TryValidateMidiTrack(src.Slice(cursor, (int)chunkLength))) return false;
                foundTracks++;
            }
            cursor += (int)chunkLength;
        }
        if (foundTracks != tracks || completeLength.HasValue && cursor != completeLength.Value) return false;
        result = MidiResult(format, tracks, completeLength.HasValue);
        return true;
    }

    /// <summary>
    /// Validates complete track chunks directly from a seekable stream so large MIDI files are not prefix-limited.
    /// </summary>
    internal static bool TryMatchMidi(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try
        {
            if (stream.Length < 26 || !TryReadAt(stream, 0, 14, out var header) ||
                !TryReadMidiHeader(new ReadOnlySpan<byte>(header), out ushort format, out ushort tracks)) return false;
            stream.Seek(14, SeekOrigin.Begin);
            long remainingValidationBudget = Math.Max(256, Settings.DetectionReadBudgetBytes);
            int remainingChunkHeaders = Math.Max(32, Math.Min(4096, (int)Math.Min(int.MaxValue, remainingValidationBudget / 8)));
            bool budgetExceeded = false;
            int foundTracks = 0;
            while (stream.Position < stream.Length)
            {
                if (remainingChunkHeaders-- == 0)
                {
                    if (foundTracks != tracks) return false;
                    budgetExceeded = true;
                    stream.Seek(0, SeekOrigin.End);
                    break;
                }
                if (!TryReadMidiChunkMarker(stream, out bool isTrack) || !TryReadMidiU4(stream, out uint chunkLength) ||
                    chunkLength > (ulong)(stream.Length - stream.Position)) return false;
                long chunkEnd = stream.Position + chunkLength;
                if (!isTrack)
                {
                    stream.Seek(chunkEnd, SeekOrigin.Begin);
                    continue;
                }
                if (foundTracks >= tracks) return false;
                foundTracks++;
                if (!budgetExceeded && chunkLength <= (ulong)remainingValidationBudget)
                {
                    if (!TryValidateMidiTrack(stream, chunkEnd)) return false;
                    remainingValidationBudget -= chunkLength;
                }
                else
                {
                    budgetExceeded = true;
                    stream.Seek(chunkEnd, SeekOrigin.Begin);
                }
            }
            if (stream.Position != stream.Length || foundTracks != tracks) return false;
            result = MidiResult(format, tracks, complete: true, budgetExceeded);
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

    private static bool TryReadMidiHeader(ReadOnlySpan<byte> src, out ushort format, out ushort tracks)
    {
        format = 0;
        tracks = 0;
        if (src.Length < 14 || !src.Slice(0, 4).SequenceEqual("MThd"u8) || ReadUInt32BigEndian(src, 4) != 6) return false;
        format = ReadUInt16BigEndian(src, 8);
        tracks = ReadUInt16BigEndian(src, 10);
        ushort division = ReadUInt16BigEndian(src, 12);
        if (format > 2 || tracks == 0 || (format == 0 && tracks != 1)) return false;
        if ((division & 0x8000) == 0) return division != 0;
        int framesPerSecond = unchecked((sbyte)(division >> 8));
        return framesPerSecond is -24 or -25 or -29 or -30 && (division & 0xFF) != 0;
    }

    private static bool TryValidateMidiTrack(ReadOnlySpan<byte> track)
    {
        int cursor = 0;
        byte runningStatus = 0;
        while (cursor < track.Length)
        {
            if (!TryReadMidiVariableLength(track, ref cursor, out _ ) || cursor >= track.Length) return false;
            byte current = track[cursor];
            byte status;
            bool consumedFirstData = false;
            if (current < 0x80)
            {
                if (runningStatus == 0) return false;
                status = runningStatus;
                consumedFirstData = true;
                cursor++;
            }
            else
            {
                status = current;
                cursor++;
                if (status < 0xF0) runningStatus = status;
                else if (status != 0xFF) runningStatus = 0;
            }

            if (status < 0xF0)
            {
                int dataLength = (status & 0xF0) is 0xC0 or 0xD0 ? 1 : 2;
                int remaining = dataLength - (consumedFirstData ? 1 : 0);
                if (remaining > track.Length - cursor) return false;
                for (int index = 0; index < remaining; index++) if (track[cursor + index] >= 0x80) return false;
                cursor += remaining;
                continue;
            }

            if (status == 0xFF)
            {
                if (cursor >= track.Length) return false;
                byte type = track[cursor++];
                if (!TryReadMidiVariableLength(track, ref cursor, out uint length) || length > track.Length - cursor) return false;
                cursor += (int)length;
                if (type == 0x2F) return length == 0 && cursor == track.Length;
                continue;
            }
            if (status is not (0xF0 or 0xF7) ||
                !TryReadMidiVariableLength(track, ref cursor, out uint sysexLength) ||
                sysexLength > track.Length - cursor) return false;
            cursor += (int)sysexLength;
        }
        return false;
    }

    private static bool MatchesMidiTrackHeaderPrefix(ReadOnlySpan<byte> remaining) {
        ReadOnlySpan<byte> expected = "MTrk"u8;
        if (remaining.Length > expected.Length) return false;
        return expected.Slice(0, remaining.Length).SequenceEqual(remaining);
    }

    private static bool IsValidMidiTrackPrefix(ReadOnlySpan<byte> track) {
        int cursor = 0;
        byte runningStatus = 0;
        while (cursor < track.Length) {
            int deltaStart = cursor;
            if (!TryReadMidiVariableLength(track, ref cursor, out _))
                return cursor == track.Length && cursor - deltaStart <= 4;
            if (cursor >= track.Length) return true;
            byte current = track[cursor];
            byte status;
            bool consumedFirstData = false;
            if (current < 0x80) {
                if (runningStatus == 0) return false;
                status = runningStatus;
                consumedFirstData = true;
                cursor++;
            } else {
                status = current;
                cursor++;
                if (status < 0xF0) runningStatus = status;
                else if (status != 0xFF) runningStatus = 0;
            }
            if (status < 0xF0) {
                int remaining = ((status & 0xF0) is 0xC0 or 0xD0 ? 1 : 2) - (consumedFirstData ? 1 : 0);
                int available = Math.Min(remaining, track.Length - cursor);
                for (int index = 0; index < available; index++) if (track[cursor + index] >= 0x80) return false;
                if (available < remaining) return true;
                cursor += remaining;
                continue;
            }
            if (status == 0xFF) {
                if (cursor >= track.Length) return true;
                byte type = track[cursor++];
                int lengthStart = cursor;
                if (!TryReadMidiVariableLength(track, ref cursor, out uint length))
                    return cursor == track.Length && cursor - lengthStart <= 4;
                if (length > track.Length - cursor) return true;
                cursor += (int)length;
                if (type == 0x2F) return false;
                continue;
            }
            if (status is not (0xF0 or 0xF7)) return false;
            int sysexStart = cursor;
            if (!TryReadMidiVariableLength(track, ref cursor, out uint sysexLength))
                return cursor == track.Length && cursor - sysexStart <= 4;
            if (sysexLength > track.Length - cursor) return true;
            cursor += (int)sysexLength;
        }
        return true;
    }

    private static bool TryValidateMidiTrack(Stream stream, long trackEnd)
    {
        byte runningStatus = 0;
        while (stream.Position < trackEnd)
        {
            if (!TryReadMidiVariableLength(stream, trackEnd, out _) || !TryReadMidiByte(stream, trackEnd, out byte current)) return false;
            byte status;
            bool consumedFirstData = false;
            if (current < 0x80)
            {
                if (runningStatus == 0) return false;
                status = runningStatus;
                consumedFirstData = true;
            }
            else
            {
                status = current;
                if (status < 0xF0) runningStatus = status;
                else if (status != 0xFF) runningStatus = 0;
            }

            if (status < 0xF0)
            {
                int remaining = ((status & 0xF0) is 0xC0 or 0xD0 ? 1 : 2) - (consumedFirstData ? 1 : 0);
                for (int index = 0; index < remaining; index++)
                    if (!TryReadMidiByte(stream, trackEnd, out byte data) || data >= 0x80) return false;
                continue;
            }

            if (status == 0xFF)
            {
                if (!TryReadMidiByte(stream, trackEnd, out byte type) ||
                    !TryReadMidiVariableLength(stream, trackEnd, out uint length) ||
                    length > (ulong)(trackEnd - stream.Position)) return false;
                stream.Seek(length, SeekOrigin.Current);
                if (type == 0x2F) return length == 0 && stream.Position == trackEnd;
                continue;
            }
            if (status is not (0xF0 or 0xF7) ||
                !TryReadMidiVariableLength(stream, trackEnd, out uint sysexLength) ||
                sysexLength > (ulong)(trackEnd - stream.Position)) return false;
            stream.Seek(sysexLength, SeekOrigin.Current);
        }
        return false;
    }

    private static bool TryReadMidiVariableLength(ReadOnlySpan<byte> src, ref int cursor, out uint value)
    {
        value = 0;
        for (int index = 0; index < 4; index++)
        {
            if (cursor >= src.Length) return false;
            byte current = src[cursor++];
            value = (value << 7) | (uint)(current & 0x7F);
            if ((current & 0x80) == 0) return true;
        }
        return false;
    }

    private static bool TryReadMidiVariableLength(Stream stream, long end, out uint value)
    {
        value = 0;
        for (int index = 0; index < 4; index++)
        {
            if (!TryReadMidiByte(stream, end, out byte current)) return false;
            value = (value << 7) | (uint)(current & 0x7F);
            if ((current & 0x80) == 0) return true;
        }
        return false;
    }

    private static bool TryReadMidiChunkMarker(Stream stream, out bool isTrack)
    {
        isTrack = true;
        ReadOnlySpan<byte> expected = "MTrk"u8;
        for (int index = 0; index < expected.Length; index++)
        {
            int current = stream.ReadByte();
            if (current < 0) return false;
            isTrack &= current == expected[index];
        }
        return true;
    }

    private static bool TryReadMidiU4(Stream stream, out uint value)
    {
        value = 0;
        int b0 = stream.ReadByte();
        int b1 = stream.ReadByte();
        int b2 = stream.ReadByte();
        int b3 = stream.ReadByte();
        if (b0 < 0 || b1 < 0 || b2 < 0 || b3 < 0) return false;
        value = ((uint)b0 << 24) | ((uint)b1 << 16) | ((uint)b2 << 8) | (uint)b3;
        return true;
    }

    private static bool TryReadMidiByte(Stream stream, long end, out byte value)
    {
        value = 0;
        if (stream.Position >= end) return false;
        int read = stream.ReadByte();
        if (read < 0) return false;
        value = (byte)read;
        return true;
    }

    private static ContentTypeDetectionResult MidiResult(ushort format, ushort tracks, bool complete, bool budgetExceeded = false)
        => new()
        {
            Extension = "mid",
            MimeType = "audio/midi",
            Confidence = complete && !budgetExceeded ? "High" : "Medium",
            Reason = $"midi:format={format};tracks={tracks}" +
                     (!complete ? ";sampled-length-unknown" : budgetExceeded ? ";validation-budget-exceeded" : string.Empty)
        };
}
