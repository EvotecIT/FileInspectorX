namespace FileInspectorX;

/// <summary>
/// Seekable DICOM validation that can continue beyond the configured detection prefix.
/// </summary>
internal static partial class Signatures
{
    internal static bool TryMatchDicom(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try
        {
            if (stream.Length < 144 || !TryReadAt(stream, 0, 144, out var prefix)) return false;
            var header = new ReadOnlySpan<byte>(prefix);
            if (!header.Slice(128, 4).SequenceEqual("DICM"u8) ||
                ReadUInt16LittleEndian(header, 132) != 0x0002 || ReadUInt16LittleEndian(header, 134) != 0x0000 ||
                header[136] != (byte)'U' || header[137] != (byte)'L' || ReadUInt16LittleEndian(header, 138) != 4)
                return false;

            uint metaLength = ReadUInt32LittleEndian(header, 140);
            long metaEnd = 144L + metaLength;
            if (metaLength < 48 || metaEnd < 144 || metaEnd > stream.Length) return false;

            int budget = Math.Max(144, Settings.DetectionReadBudgetBytes);
            if (metaEnd <= budget && metaEnd <= int.MaxValue)
            {
                if (!TryReadAt(stream, 0, (int)metaEnd, out var completeMeta)) return false;
                return TryMatchDicom(new ReadOnlySpan<byte>(completeMeta), stream.Length, out result);
            }

            result = BinaryResult("dcm", "application/dicom", "dicom:preamble+meta-header;validation-budget-exceeded");
            result.Confidence = "Medium";
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
}
