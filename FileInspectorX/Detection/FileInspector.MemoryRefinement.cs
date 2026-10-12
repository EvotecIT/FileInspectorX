namespace FileInspectorX;

public static partial class FileInspector
{
    // Complete memory inputs use the same directory and structured-text evidence
    // as seekable files. Borrowing the bytes keeps span callers within a fixed scope.
    private static unsafe ContentTypeDetectionResult? RefineMemoryDetection(
        ReadOnlySpan<byte> data,
        ReadOnlyMemory<byte>? memory,
        ContentTypeDetectionResult? result)
    {
        if (result is null || data.IsEmpty) return result;
        if (memory.HasValue)
        {
            using var stream = new MemoryReadStream(memory.Value);
            return Refine(stream, result);
        }
        fixed (byte* pointer = data)
        {
            using var stream = new UnmanagedMemoryStream(pointer, data.Length);
            return Refine(stream, result);
        }

        static ContentTypeDetectionResult Refine(Stream stream, ContentTypeDetectionResult detection)
        {
            if (detection.Extension == "ole2")
                return TryRefineOle2Subtype(stream) ?? detection;
            TryValidateStructuredTextWithBudget(stream, detection, skipAdmxAdml: false);
            return detection;
        }
    }
}
