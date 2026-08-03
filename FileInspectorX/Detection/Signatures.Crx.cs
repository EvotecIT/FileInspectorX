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
        result.Confidence = "Medium";
        result.Reason += ";signature-not-verified";
        if (!complete)
        {
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
            result.Confidence = "Medium";
            result.Reason += ";signature-not-verified";
            StructuredValidationStatus zipStatus = TryValidateZipCentralDirectory(stream, headerEnd, stream.Length - headerEnd);
            if (!signedHeaderValidated || zipStatus != StructuredValidationStatus.Complete)
            {
                result.Confidence = "Medium";
                result.Reason += !signedHeaderValidated ? ";signed-header-budget" : ";zip-local-header-only";
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
            ulong fieldNumber = key >> 3;
            if (fieldNumber is 0 or > 0x1FFFFFFF) return false;
            int field = (int)fieldNumber;
            int wire = (int)(key & 7);
            if (field is 2 or 3)
            {
                if (!TryReadProtobufBytes(header, ref cursor, wire, out var value)) return false;
                if (!TryValidateCrx3Proof(value)) return false;
                proof = true;
            }
            else if (field == 10000)
            {
                if (!TryReadProtobufBytes(header, ref cursor, wire, out var value)) return false;
                if (!TryValidateCrx3SignedData(value)) return false;
                signedData = true;
            }
            else if (!TrySkipProtobufValue(header, ref cursor, field, wire)) return false;
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
            if (!TryReadProtobufVarint(proof, ref cursor, out ulong tag)) return false;
            ulong fieldNumber = tag >> 3;
            if (fieldNumber is 0 or > 0x1FFFFFFF) return false;
            int field = (int)fieldNumber;
            int wire = (int)(tag & 7);
            if (field is 1 or 2)
            {
                if (!TryReadProtobufBytes(proof, ref cursor, wire, out var value) || value.Length == 0) return false;
                key |= field == 1;
                signature |= field == 2;
            }
            else if (!TrySkipProtobufValue(proof, ref cursor, field, wire)) return false;
        }
        return key && signature;
    }

    private static bool TryValidateCrx3SignedData(ReadOnlySpan<byte> data)
    {
        int cursor = 0;
        bool crxId = false;
        while (cursor < data.Length)
        {
            if (!TryReadProtobufVarint(data, ref cursor, out ulong tag)) return false;
            ulong fieldNumber = tag >> 3;
            if (fieldNumber is 0 or > 0x1FFFFFFF) return false;
            int field = (int)fieldNumber;
            int wire = (int)(tag & 7);
            if (field == 1)
            {
                if (!TryReadProtobufBytes(data, ref cursor, wire, out var value) || value.Length != 16) return false;
                crxId = true;
            }
            else if (!TrySkipProtobufValue(data, ref cursor, field, wire)) return false;
        }
        return crxId;
    }

    private static bool TryReadProtobufBytes(ReadOnlySpan<byte> data, ref int cursor, int wire,
        out ReadOnlySpan<byte> value)
    {
        value = default;
        if (wire != 2 || !TryReadProtobufVarint(data, ref cursor, out ulong length) ||
            length > (ulong)(data.Length - cursor)) return false;
        value = data.Slice(cursor, (int)length);
        cursor += (int)length;
        return true;
    }

    private static bool TrySkipProtobufValue(ReadOnlySpan<byte> data, ref int cursor, int field, int wire, int depth = 0)
    {
        switch (wire)
        {
            case 0:
                return TryReadProtobufVarint(data, ref cursor, out _);
            case 1:
                if (cursor > data.Length - 8) return false;
                cursor += 8;
                return true;
            case 2:
                return TryReadProtobufBytes(data, ref cursor, wire, out _);
            case 3:
                if (depth >= 32) return false;
                while (cursor < data.Length)
                {
                    if (!TryReadProtobufVarint(data, ref cursor, out ulong nestedKey)) return false;
                    ulong nestedFieldNumber = nestedKey >> 3;
                    if (nestedFieldNumber is 0 or > 0x1FFFFFFF) return false;
                    int nestedField = (int)nestedFieldNumber;
                    int nestedWire = (int)(nestedKey & 7);
                    if (nestedWire == 4) return nestedField == field;
                    if (!TrySkipProtobufValue(data, ref cursor, nestedField, nestedWire, depth + 1)) return false;
                }
                return false;
            case 5:
                if (cursor > data.Length - 4) return false;
                cursor += 4;
                return true;
            default:
                return false;
        }
    }

    private static bool TryReadProtobufVarint(ReadOnlySpan<byte> data, ref int cursor, out ulong value)
    {
        value = 0;
        for (int shift = 0; shift < 64 && cursor < data.Length; shift += 7)
        {
            byte current = data[cursor++];
            if (shift == 63 && (current & 0x7F) > 1) return false;
            value |= (ulong)(current & 0x7F) << shift;
            if ((current & 0x80) == 0) return true;
        }
        return false;
    }
}
