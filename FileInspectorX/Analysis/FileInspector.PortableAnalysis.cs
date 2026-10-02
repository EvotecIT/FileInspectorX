namespace FileInspectorX;

public static partial class FileInspector
{
    /// <summary>
    /// Analyzes complete content from a readable, seekable stream without closing it. The original
    /// position is restored where possible. The optional file name supplies type/name hints and is
    /// never opened. Requested filesystem-only stages are explicitly unavailable.
    /// </summary>
    public static FileAnalysis Analyze(Stream stream, DetectionOptions? options = null, string? fileName = null)
        => AnalyzeCore(InspectionInput.FromStream(stream, fileName), options);

    /// <summary>Analyzes complete array content without copying it. The optional file name is a hint only.</summary>
    public static FileAnalysis Analyze(byte[] data, DetectionOptions? options = null, string? fileName = null)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        return Analyze(data.AsMemory(), options, fileName);
    }

    /// <summary>Analyzes complete memory content without copying it. No filesystem path is associated with the result.</summary>
    public static FileAnalysis Analyze(ReadOnlyMemory<byte> data, DetectionOptions? options = null, string? fileName = null)
    {
        using var stream = new MemoryReadStream(data);
        return Analyze(stream, options, fileName);
    }

    /// <summary>
    /// Analyzes complete span content synchronously. The input is borrowed only for this call;
    /// learned classification uses a memory bridge so provider input cannot outlive the fixed span.
    /// </summary>
    public static unsafe FileAnalysis Analyze(ReadOnlySpan<byte> data, DetectionOptions? options = null, string? fileName = null)
    {
        if (data.IsEmpty || options?.LearnedClassificationMode is { } mode && mode != LearnedClassificationMode.Off)
            return Analyze(new ReadOnlyMemory<byte>(data.ToArray()), options, fileName);
        fixed (byte* pointer = data)
        {
            using var stream = new UnmanagedMemoryStream(pointer, data.Length);
            return Analyze(stream, options, fileName);
        }
    }

    /// <summary>
    /// Inspects complete stream content while preserving caller ownership and seekable position.
    /// Detection-only mode also accepts forward-only streams; full analysis requires seeking.
    /// The optional file name is a hint and cannot enable filesystem enrichment.
    /// </summary>
    public static FileAnalysis Inspect(Stream stream, DetectionOptions? options = null, string? fileName = null)
    {
        using var operation = InspectionOperation.Begin(options);
        options = operation.Options;
        using var input = InspectionInput.FromStream(stream, fileName, requireSeek: !options.DetectOnly);
        if (!options.DetectOnly)
        {
            var result = AnalyzeCore(input, options);
            result.Metrics = operation.SnapshotMetrics();
            return result;
        }
        ValidateLearnedClassificationMode(options);
        ContentTypeDetectionResult? detection;
        try
        {
            using var timing = operation.Measure(InspectionStage.Detection);
            detection = DetectInput(input, options);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not ArgumentOutOfRangeException and not OperationCanceledException)
        { return InputFailureAnalysis(options, detectionOnly: true, hasFileSystemSource: false); }
        var only = new FileAnalysis { SettingsSnapshot = options.Settings, HasFileSystemSource = false,
            Detection = detection, Kind = ClassifyKindWithLearnedText(detection), Flags = ContentFlags.None };
        PopulateDetectionSummary(only);
        return CompleteAnalysis(only, options, detectionOnly: true);
    }

    /// <summary>Inspects array content without copying it, optionally performing detection only.</summary>
    public static FileAnalysis Inspect(byte[] data, DetectionOptions? options = null, string? fileName = null)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        return Inspect(data.AsMemory(), options, fileName);
    }

    /// <summary>Inspects complete memory content without a filesystem staging file.</summary>
    public static FileAnalysis Inspect(ReadOnlyMemory<byte> data, DetectionOptions? options = null, string? fileName = null)
    {
        using var stream = new MemoryReadStream(data);
        return Inspect(stream, options, fileName);
    }

    /// <summary>Inspects span content synchronously, with a memory bridge when learned classification is requested.</summary>
    public static unsafe FileAnalysis Inspect(ReadOnlySpan<byte> data, DetectionOptions? options = null, string? fileName = null)
    {
        if (data.IsEmpty || options?.LearnedClassificationMode is { } mode && mode != LearnedClassificationMode.Off)
            return Inspect(new ReadOnlyMemory<byte>(data.ToArray()), options, fileName);
        fixed (byte* pointer = data)
        {
            using var stream = new UnmanagedMemoryStream(pointer, data.Length);
            return Inspect(stream, options, fileName);
        }
    }

    private static ContentTypeDetectionResult? DetectInput(InspectionInput input, DetectionOptions options)
    {
        input.RetainPosition();
        if (input.HasPath) return DetectPathCore(input.Path!, options, propagateReadFailure: true, input);
        try
        {
            using var stream = input.OpenRead();
            return DetectStreamCore(stream, options, System.IO.Path.GetExtension(input.Name).TrimStart('.'), input);
        }
        catch (Exception ex) when (options.LearnedClassificationMode == LearnedClassificationMode.Required &&
            ex is IOException or UnauthorizedAccessException)
        { throw new LearnedClassificationException("The required learned content classifier could not read the input.", ex); }
    }
}
