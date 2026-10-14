using System.Threading;
using OfficeIMO;
using OfficeIMO.Excel;
using OfficeIMO.OpenDocument;
using OfficeIMO.Pdf;
using OfficeIMO.PowerPoint;
using OfficeIMO.Reader;
using OfficeIMO.Reader.Excel;
using OfficeIMO.Reader.OpenDocument;
using OfficeIMO.Reader.Pdf;
using OfficeIMO.Reader.PowerPoint;
using OfficeIMO.Reader.Rtf;
using OfficeIMO.Reader.Word;
using OfficeIMO.Rtf;
using OfficeIMO.Word;

namespace FileInspectorX.OfficeIMO;

public sealed partial class OfficeImoContentReader
{
    private void ReadDocument(NativeReadStream source, Projection output, string family, CancellationToken token)
    {
        output.ChargeUnknownExpansion();
        ReaderOptions reader = Reader(output);
        switch (family)
        {
            case "word":
            {
                // The native async loader uses ConfigureAwait(false); this synchronous SPI waits without capturing a UI context.
                // Cancellation bounds source capture and projection; SDK model construction retains its bounded synchronous interval.
                using var document = WordDocument.LoadAsync(source, new WordLoadOptions
                {
                    AccessMode = DocumentAccessMode.ReadOnly, PersistenceMode = DocumentPersistenceMode.Explicit,
                    MaxInputBytes = Input(output), AllowLegacyProjection = false, CaptureSourcePackageSecurity = true,
                    PackageSecurity = Package(output), OpenSettings = new OfficeOpenXmlLoadSettings { MaxCharactersInPart = Expanded(output) }
                }, token).ConfigureAwait(false).GetAwaiter().GetResult();
                if (document.SourceFormatDescriptor.Encoding != OfficeFormatEncoding.OpenXml) throw new NotSupportedException();
                output.Map(document.ReadDocument(output.Name, reader, new ReaderWordOptions { IncludeFootnotes = true, IncludePageLocations = false }, token), token);
                ReadPayloads(output, options => document.InspectEmbeddedPayloads(options, token), source, token);
                break;
            }
            case "excel":
            {
                using var document = ExcelDocument.LoadAsync(source, new ExcelLoadOptions
                {
                    AccessMode = DocumentAccessMode.ReadOnly, PersistenceMode = DocumentPersistenceMode.Explicit,
                    MaxInputBytes = Input(output), AllowBinaryProjection = false, CaptureSourcePackageSecurity = true,
                    PackageSecurity = Package(output), OpenSettings = new OfficeOpenXmlLoadSettings { MaxCharactersInPart = Expanded(output) }
                }, token).ConfigureAwait(false).GetAwaiter().GetResult();
                if (document.SourceFormatDescriptor.Encoding != OfficeFormatEncoding.OpenXml) throw new NotSupportedException();
                output.Map(document.ReadDocument(output.Name, reader, new ReaderExcelOptions
                {
                    HeadersInFirstRow = true, ChunkRows = 200,
                    ReadOptions = new ExcelReadOptions
                    {
                        MaxInputBytes = Input(output), MaxSharedStringItems = NativeCount(output),
                        MaxSharedStringItemCharacters = IntLimit(Expanded(output) / 2), MaxSharedStringCharacters = Expanded(output) / 2,
                        MaxWorksheets = NativeCount(output), MaxMetadataPartBytes = IntLimit(Expanded(output)),
                        MaxRangeCells = Math.Max(1, Expanded(output) / 64), MaxXmlDataReaderBufferedCharacters = Math.Max(1, Expanded(output) / 2),
                        UseCachedFormulaResult = _options.UseCachedFormulaResults, CancellationToken = token
                    }
                }, token), token);
                ReadPayloads(output, options => document.InspectEmbeddedPayloads(options, token), source, token);
                break;
            }
            case "powerpoint":
            {
                using var document = PowerPointPresentation.Load(source, new PowerPointLoadOptions
                {
                    AccessMode = DocumentAccessMode.ReadOnly, PersistenceMode = DocumentPersistenceMode.Explicit,
                    MaxInputBytes = Input(output), AllowLegacyProjection = false, CaptureSourcePackageSecurity = true,
                    PackageSecurity = Package(output), OpenSettings = new OfficeOpenXmlLoadSettings { MaxCharactersInPart = Expanded(output) }
                }, token);
                if (document.SourceFormatDescriptor.Encoding != OfficeFormatEncoding.OpenXml) throw new NotSupportedException();
                output.Map(document.ReadDocument(output.Name, reader, new ReaderPowerPointOptions
                { IncludeNotes = _options.IncludeNotes, IncludeTables = true, IncludeHiddenShapes = _options.IncludeHiddenShapes }, token), token);
                ReadPayloads(output, options => document.InspectEmbeddedPayloads(options, token), source, token);
                break;
            }
            case "opendocument":
            {
                var nativeOptions = new OdfLoadOptions
                {
                    DeferBinaryPayloads = true, MaxPackageBytes = Math.Min(Input(output), Expanded(output)), MaxEntries = NativeCount(output),
                    MaxEntryUncompressedBytes = Expanded(output), MaxTotalUncompressedBytes = Expanded(output),
                    MaxXmlCharacters = Expanded(output), MaxXmlDepth = _options.MaxXmlDepth,
                    MaxCompressionRatio = _options.MaxCompressionRatio, MaxDepth = 32, MaxTotalKdfIterations = Expanded(output)
                };
                var document = OdfDocument.LoadAsync(source, nativeOptions, token).ConfigureAwait(false).GetAwaiter().GetResult();
                output.Map(document.ReadDocument(output.Name, reader, new ReaderOpenDocumentOptions
                {
                    MaxXmlCharacters = nativeOptions.MaxXmlCharacters, MaxExtractedCharacters = Math.Max(1, Expanded(output) / 2),
                    IncludeSpeakerNotes = _options.IncludeNotes, HeadersInFirstRow = true,
                    MaxRichBlocks = NativeCount(output), MaxLinks = NativeCount(output), MaxLinkCharacters = Expanded(output) / 2
                }, token), token);
                ReadPayloads(output, options => document.InspectEmbeddedPayloads(options, token), source, token);
                break;
            }
            case "rtf":
            {
                var nativeOptions = new RtfReadOptions
                {
                    DeferBinaryPayloads = true, MaxDepth = _options.MaxXmlDepth, MaxInputBytes = Input(output),
                    MaxInputCharacters = IntLimit(Input(output)), MaxTokenCount = NativeCount(output), MaxGroupCount = NativeCount(output),
                    MaxTextCharacters = Expanded(output) / 2, MaxBinaryBytesPerPayload = IntLimit(Expanded(output)),
                    MaxTotalBinaryBytes = Expanded(output), MaxImageCount = NativeCount(output),
                    MaxImageBytesPerImage = IntLimit(Expanded(output)), MaxTotalImageBytes = Expanded(output),
                    MaxObjectCount = NativeCount(output), MaxObjectBytesPerObject = IntLimit(Expanded(output)),
                    MaxTotalObjectBytes = Expanded(output), MaxSemanticBlockCount = NativeCount(output),
                    ReadEmbeddedObjects = false, ReadFileReferences = false, HyperlinkPolicy = RtfHyperlinkReadPolicy.WebAndMailOnly
                };
                RtfReadResult document = RtfDocument.LoadResult(source, nativeOptions, cancellationToken: token);
                output.Map(document.ReadDocument(output.Name, reader, new ReaderRtfOptions
                {
                    RtfReadOptions = nativeOptions, IncludeDiagnostics = true, IncludeImagePlaceholders = false,
                    IncludePageLocations = false, IncludeHeadersAndFooters = true, IncludeNotes = _options.IncludeNotes
                }, token), token);
                ReadPayloads(output, options => document.InspectEmbeddedPayloads(options, token), source, token);
                break;
            }
            case "pdf":
            {
                var document = PdfDocument.Load(source, PdfLoad(output), token);
                var inspection = document.ReadForInspection(PdfRead(output), token);
                output.Map(inspection.Document.ReadDocument(output.Name, reader, new ReaderPdfOptions
                { ChunkByPage = true, IncludeParagraphContinuationMetadata = false }, token), token);
                output.MapPdfInspection(inspection, token);
                ReadPdfAttachments(document, inspection, output, source, token);
                break;
            }
        }
    }
}
