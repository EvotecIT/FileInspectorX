namespace FileInspectorX;

/// <summary>
/// Scientific and structured-data container detection.
/// </summary>
internal static partial class Signatures {
    private static readonly byte[] Hdf5Signature = { 0x89, (byte)'H', (byte)'D', (byte)'F', 0x0D, 0x0A, 0x1A, 0x0A };

    internal static bool TryMatchHdf5(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        for (long offset = 0; offset <= src.Length - Hdf5Signature.Length; offset = NextHdf5Offset(offset)) {
            if (MatchesHdf5Signature(src, (int)offset)) {
                result = Hdf5Result(offset);
                return true;
            }
            if (offset > int.MaxValue / 2) break;
        }
        return false;
    }

    internal static bool TryMatchHdf5(Stream stream, long minimumOffset, out ContentTypeDetectionResult? result) {
        result = null;
        if (!stream.CanSeek || !stream.CanRead) return false;
        long originalPosition;
        long length;
        try {
            originalPosition = stream.Position;
            length = stream.Length;
        } catch {
            return false;
        }

        var signature = new byte[Hdf5Signature.Length];
        try {
            for (long offset = 0; offset <= length - signature.Length; offset = NextHdf5Offset(offset)) {
                if (offset < minimumOffset) {
                    if (offset > long.MaxValue / 2) break;
                    continue;
                }
                stream.Seek(offset, SeekOrigin.Begin);
                int read = 0;
                while (read < signature.Length) {
                    int current = stream.Read(signature, read, signature.Length - read);
                    if (current <= 0) break;
                    read += current;
                }
                if (read == signature.Length && MatchesHdf5Signature(signature, 0)) {
                    result = Hdf5Result(offset);
                    return true;
                }
                if (offset > long.MaxValue / 2) break;
            }
            return false;
        } catch {
            result = null;
            return false;
        } finally {
            try { stream.Seek(originalPosition, SeekOrigin.Begin); } catch { }
        }
    }

    internal static bool TryMatchNetCdf(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 16 || src[0] != (byte)'C' || src[1] != (byte)'D' || src[2] != (byte)'F' ||
            (src[3] != 1 && src[3] != 2 && src[3] != 5))
            return false;

        bool isCdf5 = src[3] == 5;
        if (isCdf5 && src.Length < 24) return false;
        int dimensionTagOffset = isCdf5 ? 12 : 8;
        int dimensionCountOffset = dimensionTagOffset + 4;
        uint dimensionTag = ReadUInt32BigEndian(src, dimensionTagOffset);
        if (dimensionTag == 0) {
            int countBytes = isCdf5 ? 8 : 4;
            for (int i = 0; i < countBytes; i++)
                if (src[dimensionCountOffset + i] != 0) return false;
        } else if (dimensionTag != 10) {
            return false;
        }

        result = new ContentTypeDetectionResult {
            Extension = "nc",
            MimeType = "application/x-netcdf",
            Confidence = "High",
            Reason = src[3] == 1 ? "netcdf:classic" : src[3] == 2 ? "netcdf:64-bit-offset" : "netcdf:64-bit-data"
        };
        return true;
    }

    private static long NextHdf5Offset(long offset) => offset == 0 ? 512 : offset * 2;

    private static bool MatchesHdf5Signature(ReadOnlySpan<byte> src, int offset) {
        for (int i = 0; i < Hdf5Signature.Length; i++)
            if (src[offset + i] != Hdf5Signature[i]) return false;
        return true;
    }

    private static ContentTypeDetectionResult Hdf5Result(long offset) => new() {
        Extension = "h5",
        MimeType = "application/x-hdf5",
        Confidence = "High",
        Reason = "hdf5:signature@" + offset
    };
}
