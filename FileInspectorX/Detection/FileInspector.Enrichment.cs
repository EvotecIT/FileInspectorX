using System.Security.Cryptography;

namespace FileInspectorX;

public static partial class FileInspector
{
    private static ContentTypeDetectionResult? Enrich(ContentTypeDetectionResult? result, ReadOnlySpan<byte> header, Stream? stream, DetectionOptions options) {
        int inspected = header.Length;
        if (options.MagicHeaderBytes > 0) {
            result ??= new ContentTypeDetectionResult { Extension = string.Empty, MimeType = string.Empty, Confidence = "Low", Reason = "unknown" };
            result.MagicHeaderHex = MagicHeaderHex(header, Math.Min(options.MagicHeaderBytes, header.Length));
        }
        if (options.ComputeSha256)
        {
            string hex = HashCompleteInput(header, stream);
            result ??= new ContentTypeDetectionResult { Extension = string.Empty, MimeType = string.Empty, Confidence = "Low", Reason = "unknown" };
            result.Sha256Hex = hex;
        }
        if (result != null)
        {
            result.BytesInspected = inspected;
            result.IsDangerous = result.IsDangerous ||
                                 DangerousExtensions.IsDangerous(result.Extension) ||
                                 DangerousExtensions.IsDangerous(result.GuessedExtension);
        }
        return result;
    }


    private static string HashCompleteInput(ReadOnlySpan<byte> prefix, Stream? stream)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long? position = stream?.CanSeek == true ? stream.Position : null;
        try
        {
            if (position.HasValue) stream!.Position = 0;
            // Memory inputs are complete. For forward-only inputs the consumed prefix must
            // participate in the digest, followed by the unread remainder.
            if (stream == null || !stream.CanSeek) AppendHash(hash, prefix);
            if (stream != null)
            {
                var buffer = new byte[8192];
                int read;
                while ((read = stream.Read(buffer, 0, buffer.Length)) > 0) hash.AppendData(buffer, 0, read);
            }
            return ToLowerHex(hash.GetHashAndReset());
        }
        finally { if (position.HasValue) stream!.Position = position.Value; }
    }

    private static void AppendHash(IncrementalHash hash, ReadOnlySpan<byte> bytes)
    {
#if NET8_0_OR_GREATER
        hash.AppendData(bytes);
#else
        var buffer = new byte[Math.Min(bytes.Length, 8192)];
        while (!bytes.IsEmpty)
        {
            int count = Math.Min(bytes.Length, buffer.Length);
            bytes.Slice(0, count).CopyTo(buffer);
            hash.AppendData(buffer, 0, count);
            bytes = bytes.Slice(count);
        }
#endif
    }

    private static ContentTypeDetectionResult? TryRefineGltfJson(ReadOnlyMemory<byte> prefix)
    {
        using var stream = new MemoryReadStream(prefix);
        return TryRefineGltfJson(stream);
    }
}
