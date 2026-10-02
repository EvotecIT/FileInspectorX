namespace FileInspectorX;

internal static partial class Signatures
{
    private static unsafe bool TryMatchEmptyZip64(ReadOnlySpan<byte> data, long? completeLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (completeLength != data.Length || data.Length < 98) return false;
        // Synchronous borrowing retains support for stack/native-backed spans.
        // The preflight and its read-only stream cannot escape the fixed scope.
        fixed (byte* pointer = data)
        {
            using var stream = new UnmanagedMemoryStream(pointer, data.Length);
            return TryMatchEmptyZip64(stream, out result);
        }
    }

    private static bool TryMatchEmptyZip64(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        var budget = ArchiveInspectionBudget.FromSettings();
        if (!budget.CheckCentralDirectory(stream, out var count) || count != 0) return false;
        result = BinaryResult("zip", "application/zip", "zip:zip64-empty-directory");
        return true;
    }
}
