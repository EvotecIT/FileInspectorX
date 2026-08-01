namespace FileInspectorX;

/// <summary>
/// Chrome extension package detection and CRX3 signed-header validation.
/// </summary>
internal static partial class Signatures
{
    internal static bool TryMatchCrx(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchCrx(src, src.Length, out result);

    internal static bool TryMatchCrx(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 12 || !src.Slice(0, 4).SequenceEqual("Cr24"u8)) return false;
        uint version = ReadUInt32LittleEndian(src, 4);
        long headerEnd;
        if (version == 2)
        {
            if (src.Length < 16) return false;
            uint publicKeyLength = ReadUInt32LittleEndian(src, 8);
            uint signatureLength = ReadUInt32LittleEndian(src, 12);
            if (publicKeyLength == 0 || signatureLength == 0) return false;
            headerEnd = 16L + publicKeyLength + signatureLength;
        }
        else if (version == 3)
        {
            uint signedHeaderLength = ReadUInt32LittleEndian(src, 8);
            if (signedHeaderLength == 0) return false;
            headerEnd = 12L + signedHeaderLength;
        }
        else return false;
        if (headerEnd > int.MaxValue || completeLength < 0 ||
            (completeLength.HasValue && headerEnd > completeLength.Value)) return false;
        if (headerEnd > src.Length)
        {
            if (completeLength.HasValue && completeLength.Value <= src.Length) return false;
            result = CrxResult(version, complete: false);
            return true;
        }

        if (version == 3 && !TryValidateCrx3Header(src.Slice(12, (int)headerEnd - 12))) return false;
        long? zipLength = completeLength.HasValue ? completeLength.Value - headerEnd : null;
        if (!TryMatchZip(src.Slice((int)headerEnd), zipLength, out var zip)) return false;
        result = CrxResult(version, completeLength.HasValue && zip?.Confidence == "High");
        return true;
    }

    private static ContentTypeDetectionResult CrxResult(uint version, bool complete)
    {
        var result = BinaryResult("crx", "application/x-chrome-extension", $"crx:version={version}");
        if (!complete)
        {
            result.Confidence = "Medium";
            result.Reason += ";sampled-signed-header";
        }
        return result;
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
                uint publicKeyLength = ReadUInt32LittleEndian(header, 8);
                uint signatureLength = ReadUInt32LittleEndian(header, 12);
                if (publicKeyLength == 0 || signatureLength == 0) return false;
                headerEnd = 16L + publicKeyLength + signatureLength;
            }
            else if (version == 3)
            {
                uint signedHeaderLength = ReadUInt32LittleEndian(header, 8);
                if (signedHeaderLength == 0) return false;
                headerEnd = 12L + signedHeaderLength;
            }
            else return false;

            if (headerEnd < 12 || headerEnd + 30L > stream.Length) return false;
            bool signedHeaderValidated = version != 3;
            if (version == 3 && headerEnd - 12 <= Math.Max(256, Settings.DetectionReadBudgetBytes))
            {
                if (!TryReadAt(stream, 12, (int)(headerEnd - 12), out var signedHeader) ||
                    !TryValidateCrx3Header(new ReadOnlySpan<byte>(signedHeader))) return false;
                signedHeaderValidated = true;
            }
            if (!TryReadAt(stream, headerEnd, 30, out var zipHeader) ||
                !TryValidateZipLocalHeader(new ReadOnlySpan<byte>(zipHeader), stream.Length - headerEnd)) return false;
            result = BinaryResult("crx", "application/x-chrome-extension", $"crx:version={version}");
            if (!signedHeaderValidated)
            {
                result.Confidence = "Medium";
                result.Reason += ";signed-header-budget";
            }
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

    private static bool TryValidateCrx3Header(ReadOnlySpan<byte> header)
    {
        int cursor = 0;
        bool proof = false;
        bool signedData = false;
        while (cursor < header.Length)
        {
            if (!TryReadProtobufVarint(header, ref cursor, out ulong key)) return false;
            int field = (int)(key >> 3);
            int wire = (int)(key & 7);
            if (wire != 2 || !TryReadProtobufVarint(header, ref cursor, out ulong length) ||
                length > (ulong)(header.Length - cursor)) return false;
            var value = header.Slice(cursor, (int)length);
            cursor += (int)length;
            if (field is 1 or 2) proof |= TryValidateCrx3Proof(value);
            else if (field == 10000) signedData |= TryValidateCrx3SignedData(value);
        }
        return proof && signedData;
    }

    private static bool TryValidateCrx3Proof(ReadOnlySpan<byte> proof)
    {
        int cursor = 0;
        bool key = false;
        bool signature = false;
        while (cursor < proof.Length)
        {
            if (!TryReadProtobufVarint(proof, ref cursor, out ulong tag) || (tag & 7) != 2 ||
                !TryReadProtobufVarint(proof, ref cursor, out ulong length) || length == 0 || length > (ulong)(proof.Length - cursor)) return false;
            int field = (int)(tag >> 3);
            key |= field == 1;
            signature |= field == 2;
            cursor += (int)length;
        }
        return key && signature;
    }

    private static bool TryValidateCrx3SignedData(ReadOnlySpan<byte> data)
    {
        int cursor = 0;
        if (!TryReadProtobufVarint(data, ref cursor, out ulong tag) || tag != 0x0A ||
            !TryReadProtobufVarint(data, ref cursor, out ulong length) || length != 16) return false;
        return cursor + 16 == data.Length;
    }

    private static bool TryReadProtobufVarint(ReadOnlySpan<byte> data, ref int cursor, out ulong value)
    {
        value = 0;
        for (int shift = 0; shift < 64 && cursor < data.Length; shift += 7)
        {
            byte current = data[cursor++];
            value |= (ulong)(current & 0x7F) << shift;
            if ((current & 0x80) == 0) return true;
        }
        return false;
    }
}
