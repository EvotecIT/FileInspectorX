using System.Security.Cryptography;

namespace FileInspectorX;

public static partial class FileInspector
{
    private static ContentTypeDetectionResult? Enrich(ContentTypeDetectionResult? result, ReadOnlySpan<byte> header, Stream? stream, DetectionOptions options) {
        int inspected = header.Length;
        // Public Detect calls retain readable unknown input when metrics were requested.
        // Private analysis detection keeps its existing nullable flow and enrichment policy.
        if (options.CollectMetrics && InspectionOperation.Current?.RetainUnknownDetection == true)
            result ??= CreateUnknownDetection();
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
        using var timing = InspectionOperation.Current?.Measure(InspectionStage.Sha256);
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
                while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    InspectionOperation.CheckCancellation();
                    hash.AppendData(buffer, 0, read);
                    InspectionOperation.Current?.Metrics?.Hash(read);
                }
            }
            return ToLowerHex(hash.GetHashAndReset());
        }
        finally { if (position.HasValue) stream!.Position = position.Value; }
    }

    private static void AppendHash(IncrementalHash hash, ReadOnlySpan<byte> bytes)
    {
#if NET8_0_OR_GREATER
        while (!bytes.IsEmpty)
        {
            InspectionOperation.CheckCancellation();
            int count = Math.Min(bytes.Length, 64 * 1024);
            hash.AppendData(bytes.Slice(0, count));
            InspectionOperation.Current?.Metrics?.Hash(count);
            bytes = bytes.Slice(count);
        }
#else
        var buffer = new byte[Math.Min(bytes.Length, 8192)];
        while (!bytes.IsEmpty)
        {
            InspectionOperation.CheckCancellation();
            int count = Math.Min(bytes.Length, buffer.Length);
            bytes.Slice(0, count).CopyTo(buffer);
            hash.AppendData(buffer, 0, count);
            InspectionOperation.Current?.Metrics?.Hash(count);
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
