using OfficeIMO;
using OfficeIMO.Pdf;
using OfficeIMO.Reader;

namespace FileInspectorX.OfficeIMO;

public sealed partial class OfficeImoContentReader
{
    private long Expanded(Projection output) => Math.Min(_options.MaxNativeExpandedBytes, output.Budgets.NativeExpandedBytes);
    private long Input(Projection output) => Math.Min(_options.MaxInputBytes, output.Budgets.MaxInputBytes);
    private int NativeCount(Projection output) => (int)Math.Min(_options.MaxSourceRecords, Math.Max(1, Expanded(output) / 64));
    private static int IntLimit(long value) => (int)Math.Min(int.MaxValue, value);

    private OfficePackageSecurityOptions Package(Projection output) => new()
    {
        MaxPackageBytes = Input(output), MaxPartCount = NativeCount(output),
        MaxPartUncompressedBytes = Expanded(output), MaxTotalUncompressedBytes = Expanded(output),
        MaxXmlCharactersInPart = Expanded(output), MaxCompressionRatio = _options.MaxCompressionRatio,
        Macros = OfficePackageContentPolicy.Allow, EmbeddedPayloads = OfficePackageContentPolicy.Allow,
        ActiveX = OfficePackageContentPolicy.Allow, ExternalRelationships = OfficePackageContentPolicy.Allow
    };

    private ReaderOptions Reader(Projection output) => new()
    {
        Projection = ReaderProjection.TextAndMetadata, ComputeHashes = false,
        MaxInputBytes = Input(output), MaxChars = Math.Max(256, Math.Min(8192, output.Budgets.MaxTextCharacters)),
        MaxTableRows = Math.Min(200, NativeCount(output)),
        ResourceLimits = new ReaderResourceLimits
        {
            MaxChunks = NativeCount(output), MaxBlocks = NativeCount(output),
            MaxChunkCharacters = Expanded(output) / 2,
            MaxAssets = 0, MaxAssetBytes = 0, MaxNestedDocuments = 0, MaxNestedInputBytes = 0, MaxNestedDepth = 0
        },
        Inspection = new ReaderInspectionOptions
        {
            IncludeComments = true, IncludeRevisions = true, IncludeFormulas = true,
            IncludeVisibility = true, IncludePackageContent = true, IncludeContentSafety = true,
            MaxRecords = NativeCount(output), MaxCharacters = Math.Max(1, Expanded(output) / 2)
        }
    };

    private PdfLoadOptions PdfLoad(Projection output) => new()
    {
        ParsingMode = PdfParsingMode.Lenient, PermissionPolicy = PdfPermissionPolicy.Enforce,
        PreferToUnicode = true, UseWinAnsiFallback = true, AdjustKerningFromTJ = true, IncludeArtifactText = false,
        Limits = new PdfReadLimits
        {
            MaxInputBytes = Input(output), MaxRawStreamBytes = IntLimit(Input(output)),
            MaxDecodedStreamBytes = IntLimit(Expanded(output)), MaxTotalDecodedStreamBytes = Expanded(output),
            MaxPageContentBytes = IntLimit(Expanded(output)), MaxRetainedContentBytes = Expanded(output),
            MaxActualTextCharacters = IntLimit(Expanded(output) / 2), MaxDecodedTextCharacters = IntLimit(Expanded(output) / 2),
            MaxIndirectObjects = NativeCount(output), MaxPages = NativeCount(output), MaxPageTreeNodes = NativeCount(output),
            MaxObjectCharacters = IntLimit(Expanded(output) / 2), MaxTokensPerObject = NativeCount(output),
            MaxContentOperations = IntLimit(Expanded(output) / 16), MaxContentOperands = IntLimit(Expanded(output) / 8),
            MaxObjectNestingDepth = _options.MaxXmlDepth, MaxPageTreeDepth = _options.MaxXmlDepth,
            MaxAttachments = NativeCount(output), MaxTotalAttachmentBytes = Expanded(output),
            MaxPositionedTextCharactersPerPage = IntLimit(Expanded(output) / 2),
            MaxPositionedTextWorkCharactersPerPage = IntLimit(Expanded(output) / 2),
            MaxPositionedTextProjectionCharactersPerPage = IntLimit(Expanded(output) / 2),
            MaxClippedTextFontCopyWorkPerPage = IntLimit(Expanded(output) / 2)
        }
    };

    private PdfReadOptions PdfRead(Projection output) => new()
    {
        Profile = PdfReadProfile.Fast, IncludeImages = false, IncludeFormWidgets = false,
        Pipeline = new PdfUnderstandingPipelineOptions
        {
            MaxPages = NativeCount(output), MaxRunsPerPage = NativeCount(output),
            MaxTextCharactersPerPage = IntLimit(Expanded(output) / 2), MaxWordsPerPage = NativeCount(output),
            MaxLinesPerPage = NativeCount(output), MaxTableCandidatesPerPage = NativeCount(output),
            MaxRegionsPerPage = NativeCount(output), MaxImageRegionsPerPage = NativeCount(output),
            MaxImageCaptionCandidatesPerPage = NativeCount(output),
            MaxWorkUnitsPerPage = Expanded(output), MaxDocumentWorkUnits = Expanded(output)
        }
    };
}
