using System.Text;
using System.Threading;
using System.Xml;
using OfficeIMO;
using OfficeIMO.Pdf;
using OfficeIMO.Reader;
using OfficeIMO.Rtf;

namespace FileInspectorX.OfficeIMO;

/// <summary>Explicit optional composition of the selected OfficeIMO native inspection owners.</summary>
/// <remarks>The instance is caller owned. FileInspectorX serializes its invocation and owns descendant dispatch.
/// Passwords, legacy conversion, OCR, rendering and external resolution are outside this finite profile.</remarks>
public sealed partial class OfficeImoContentReader : IInspectionContentReader
{
    private readonly OfficeImoContentReaderOptions _options;

    /// <summary>Creates a reader with a defensive snapshot of a finite native profile.</summary>
    public OfficeImoContentReader(OfficeImoContentReaderOptions? options = null) =>
        _options = (options ?? new OfficeImoContentReaderOptions()).Snapshot();

    /// <summary>Reads one immutable core snapshot through exactly one selected native owner.</summary>
    public InspectionContentReadResult Read(InspectionContentReadRequest request, CancellationToken cancellationToken = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        cancellationToken.ThrowIfCancellationRequested();
        string extension = (request.DetectedExtension ?? string.Empty).TrimStart('.').ToLowerInvariant();
        string family = Family(extension, request.DetectedMimeType);
        if (family.Length == 0) return new InspectionContentReadResult(InspectionContentReadDisposition.NotApplicable,
            new ContentProfile(), Array.Empty<InspectionContentMember>(), new InspectionContentWork(0, 0, 0, 0));

        var result = new Projection(request, _options, family);
        if (family == "legacy") return result.Failure(InspectionContentReadDisposition.Refused,
            "officeimo:legacy-profile-refused", "The finite inspection profile requires a modern XML source; legacy conversion is disabled.");
        if (Math.Min(_options.MaxNativeExpandedBytes, request.Budgets.NativeExpandedBytes) < 256 || request.Budgets.NativeReadBytes <= 0 ||
            request.Budgets.RemainingContentCharacters <= 0)
            return result.Failure(InspectionContentReadDisposition.Refused, "officeimo:zero-native-allowance",
                "No finite native or response allowance remains for this input.");
        long inputLimit = Math.Min(_options.MaxInputBytes, request.Budgets.MaxInputBytes);
        if (request.SizeBytes > inputLimit) throw Limit("MaxInputBytes", inputLimit, request.SizeBytes);
        try
        {
            return request.OpenRead(stream =>
            {
                using var measured = new NativeReadStream(stream, request.Budgets.NativeReadBytes, cancellationToken);
                try
                {
                    switch (family)
                    {
                        case "image": ReadImage(measured, result, cancellationToken); break;
                        case "archive": ReadArchive(measured, result, cancellationToken); break;
                        default: ReadDocument(measured, result, family, cancellationToken); break;
                    }
                    cancellationToken.ThrowIfCancellationRequested();
                    result.SnapshotReadBytes = measured.BytesRead;
                    return result.Complete();
                }
                finally { result.SnapshotReadBytes = measured.BytesRead; }
            });
        }
        catch (ReaderAdmissionLimitException ex) { throw Translate(InspectionContentLimitDomain.Admission, "officeimo:reader-admission", ex.LimitName, ex.Maximum, ex.Actual, ex); }
        catch (ReaderResourceLimitException ex) { throw Translate(InspectionContentLimitDomain.Resource, "officeimo:reader-resource", ex.LimitName, ex.Maximum, null, ex); }
        catch (OfficeInspectionResourceLimitException ex) { throw Translate(InspectionContentLimitDomain.Resource, "officeimo:" + ex.Owner + "-resource", ex.LimitName, ex.Maximum, null, ex); }
        catch (OfficePackageSecurityException ex) { throw Translate(InspectionContentLimitDomain.Admission, "officeimo:package-admission", ex.Rule.ToString(), ex.Limit, ex.ObservedValue, ex); }
        catch (PdfReadLimitException ex) { throw Translate(InspectionContentLimitDomain.Resource, "officeimo:pdf-resource", ex.Kind.ToString(), ex.Limit, ex.Actual, ex); }
        catch (RtfReadLimitException ex) { throw Translate(InspectionContentLimitDomain.Resource, ex.Code, ex.LimitSource, ex.Limit, ex.Actual, ex); }
        catch (PdfPermissionDeniedException) { return result.Failure(InspectionContentReadDisposition.Refused, "officeimo:pdf-permission-refused", "The authenticated PDF policy forbids content extraction."); }
        catch (NotSupportedException ex) { return result.Failure(InspectionContentReadDisposition.Refused, "officeimo:source-profile-refused", ex.Message); }
        catch (PdfParseException ex) { return result.Failure(InspectionContentReadDisposition.Malformed, "officeimo:pdf-" + ex.Code, ex.Message,
            new Dictionary<string, string> { ["nativeCode"] = ex.Code, ["objectNumber"] = ex.ObjectNumber?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty }); }
        catch (InvalidDataException ex) { return result.Failure(InspectionContentReadDisposition.Malformed, "officeimo:malformed-input", ex.Message); }
        catch (DocumentFormat.OpenXml.Packaging.OpenXmlPackageException ex) { return result.Failure(InspectionContentReadDisposition.Malformed, "officeimo:malformed-package", ex.Message); }
        catch (XmlException ex) { return result.Failure(InspectionContentReadDisposition.Malformed, "officeimo:malformed-xml", ex.Message,
            new Dictionary<string, string> { ["xmlLineNumber"] = ex.LineNumber.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["xmlLinePosition"] = ex.LinePosition.ToString(System.Globalization.CultureInfo.InvariantCulture) }); }
        catch (DecoderFallbackException) { return result.Failure(InspectionContentReadDisposition.Malformed, "officeimo:invalid-text-encoding", "The native owner rejected invalid text encoding."); }
        catch (FormatException) { return result.Failure(InspectionContentReadDisposition.Malformed, "officeimo:malformed-value", "The native owner rejected a malformed source value."); }
    }

    private static string Family(string extension, string? mime) => extension switch
    {
        "docx" or "docm" or "dotx" or "dotm" => "word",
        "xlsx" or "xlsm" or "xltx" or "xltm" => "excel",
        "pptx" or "pptm" or "potx" or "potm" or "ppsx" or "ppsm" => "powerpoint",
        "doc" or "dot" or "xls" or "xlt" or "xlsb" or "ppt" or "pot" or "pps" => "legacy",
        "pdf" => "pdf", "rtf" => "rtf",
        "odt" or "ods" or "odp" or "odg" or "fodg" => "opendocument",
        "cab" or "msi" => "archive",
        "png" or "jpg" or "jpeg" or "gif" or "bmp" or "tif" or "tiff" or "webp" or "ico" => "image",
        _ => mime?.ToLowerInvariant() switch
        {
            "application/vnd.oasis.opendocument.text" or "application/vnd.oasis.opendocument.spreadsheet" or
                "application/vnd.oasis.opendocument.presentation" or "application/vnd.oasis.opendocument.graphics" => "opendocument",
            _ => string.Empty
        }
    };

    private static InspectionContentLimitException Translate(InspectionContentLimitDomain domain, string code,
        string name, double? maximum, double? actual, Exception ex) => new(domain, code, name, maximum, actual, ex);
    private static InspectionContentLimitException Limit(string name, long maximum, long? actual = null) =>
        new(InspectionContentLimitDomain.Resource, "officeimo:bridge-resource", name, maximum, actual);
}
