using System.Globalization;
using System.Threading;
using OfficeIMO.Drawing;

namespace FileInspectorX.OfficeIMO;

public sealed partial class OfficeImoContentReader
{
    private void ReadImage(NativeReadStream source, Projection output, CancellationToken token)
    {
        long maximum = Math.Min(Math.Min(Input(output), Expanded(output)), 128L * 1024 * 1024);
        if (source.Length > maximum) throw Limit("ImageInputBytes", maximum, source.Length);
        output.ChargeUnknownExpansion();
        byte[] bytes = new byte[(int)source.Length];
        int offset = 0;
        while (offset < bytes.Length)
        {
            int read = source.Read(bytes, offset, Math.Min(81920, bytes.Length - offset));
            if (read == 0) throw new InvalidDataException("The admitted image snapshot ended early.");
            offset += read;
        }
        token.ThrowIfCancellationRequested();
        if (!OfficeImageReader.TryIdentifyByContent(bytes, output.Name, out OfficeImageInfo info)) throw new InvalidDataException("The native owner could not identify the image header.");
        int profileBytes = IntLimit(Math.Min(16L * 1024 * 1024, Expanded(output)));
        var metadata = OfficeImageMetadata.Inspect(bytes, new OfficeImageMetadataInspectionOptions
        {
            MaximumInputBytes = (int)maximum, MaximumProfileBytes = profileBytes,
            MaximumExifFields = Math.Min(65535, NativeCount(output)), MaximumExifValueBytes = Math.Min(65536, profileBytes),
            MaximumRetainedExifBytes = IntLimit(Math.Min(64L * 1024 * 1024, Expanded(output))),
            MaximumXmpProperties = Math.Min(65535, NativeCount(output)), MaximumXmlNodes = Math.Min(65535, NativeCount(output)),
            MaximumValueCharacters = IntLimit(Math.Min(1024 * 1024, Expanded(output) / 2)),
            MaximumRetainedXmpCharacters = IntLimit(Math.Min(4 * 1024 * 1024, Expanded(output) / 2)),
            MaximumIccTags = Math.Min(65535, NativeCount(output))
        }, token);
        output.Fact("image.format", info.Format.ToString(), ReportFactOrigin.Derived);
        // Dimensions are authored header declarations. No pixel decode establishes actual raster content here.
        output.Fact("image.width", Number(info.Width), ReportFactOrigin.Embedded, ReportFactKind.Integer);
        output.Fact("image.height", Number(info.Height), ReportFactOrigin.Embedded, ReportFactKind.Integer);
        output.Fact("image.resolution.presenceKnown", metadata.Resolution.IsPresenceKnown.ToString(), ReportFactOrigin.Derived, ReportFactKind.Boolean);
        output.Fact("image.resolution.declared", metadata.Resolution.IsDeclared.ToString(), ReportFactOrigin.Derived, ReportFactKind.Boolean);
        output.Fact("image.resolution.valid", metadata.Resolution.IsValid.ToString(), ReportFactOrigin.Derived, ReportFactKind.Boolean);
        if (metadata.Resolution.Resolution is OfficeImageResolution resolution && metadata.Resolution.IsDeclared)
        {
            output.Fact("image.resolution.horizontal", resolution.Horizontal.ToString("R", CultureInfo.InvariantCulture), kind: ReportFactKind.Decimal,
                attributes: new Dictionary<string, string> { ["unit"] = resolution.Unit.ToString(), ["source"] = metadata.Resolution.Source });
            output.Fact("image.resolution.vertical", resolution.Vertical.ToString("R", CultureInfo.InvariantCulture), kind: ReportFactKind.Decimal);
        }
        foreach (OfficeExifFieldEvidence field in metadata.ExifFields)
        {
            token.ThrowIfCancellationRequested();
            object? nativeValue = field.Value?.Value;
            string? value = nativeValue is Array ? null : Convert.ToString(nativeValue, CultureInfo.InvariantCulture);
            var attributes = new Dictionary<string, string>
            {
                ["directory"] = field.Directory.ToString(), ["tagId"] = Number(field.TagId), ["rawDataType"] = Number(field.RawDataType),
                ["count"] = field.Count.ToString(CultureInfo.InvariantCulture), ["directoryOffset"] = Number(field.DirectoryOffset),
                ["entryOffset"] = Number(field.EntryOffset), ["omission"] = field.Omission ?? (nativeValue is Array ? "array-value-not-projected" : string.Empty)
            };
            output.Fact("image.exif.field", value ?? "descriptor-only", attributes: attributes, source: new ReportSourceLocation
            {
                Part = output.Exact(field.Source), Record = output.Exact(field.Directory + ":" + Number(field.TagId)),
                ByteSpace = ReportByteSpace.ProfileBytes, ByteOffset = field.ValueOffset, ByteLength = field.ValueLengthBytes
            });
            if (field.Omission != null || nativeValue is Array)
                output.Omit(field.Omission ?? "officeimo:exif-array-value-not-projected", "image-exif-field", 1);
        }
        foreach (OfficeExifTimestamp timestamp in metadata.Timestamps)
        {
            token.ThrowIfCancellationRequested();
            output.Fact("image.exif.timestamp." + timestamp.FieldName, timestamp.Instant?.ToString("O", CultureInfo.InvariantCulture) ?? timestamp.RawValue,
                kind: timestamp.HasKnownTimezone ? ReportFactKind.Timestamp : ReportFactKind.Text,
                attributes: new Dictionary<string, string>
                {
                    ["source"] = timestamp.Source ?? string.Empty, ["rawValue"] = timestamp.RawValue,
                    ["rawOffset"] = timestamp.RawOffset ?? string.Empty, ["rawSubseconds"] = timestamp.RawSubseconds ?? string.Empty,
                    ["localDateTime"] = timestamp.LocalDateTime?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty,
                    ["hasKnownTimezone"] = timestamp.HasKnownTimezone.ToString(), ["issue"] = timestamp.Issue ?? string.Empty
                });
        }
        if (metadata.GpsCoordinate is OfficeExifGpsCoordinate gps)
        {
            output.Fact("image.exif.gps.latitude", gps.Latitude.ToString("R", CultureInfo.InvariantCulture), kind: ReportFactKind.Decimal);
            output.Fact("image.exif.gps.longitude", gps.Longitude.ToString("R", CultureInfo.InvariantCulture), kind: ReportFactKind.Decimal);
        }
        foreach (OfficeXmpProperty property in metadata.XmpProperties)
        {
            token.ThrowIfCancellationRequested();
            output.Fact("image.xmp." + property.Name, property.Value, attributes: new Dictionary<string, string>
            {
                ["namespace"] = property.NamespaceUri, ["kind"] = property.Kind.ToString(), ["isResource"] = property.IsResource.ToString(),
                ["language"] = property.Language ?? string.Empty, ["itemIndex"] = property.ItemIndex?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                ["source"] = property.Source, ["isTruncated"] = property.IsTruncated.ToString()
            });
        }
        if (metadata.IccProfile is OfficeIccProfileInspection icc)
        {
            output.Fact("image.icc.structurallyValid", icc.IsStructurallyValid.ToString(), ReportFactOrigin.Derived, ReportFactKind.Boolean);
            output.Fact("image.icc.supportedInputTransform", icc.HasSupportedInputTransform?.ToString() ?? "unknown", ReportFactOrigin.Derived);
            output.Fact("image.icc.deviceColorSpace", icc.DeviceColorSpaceSignature);
            output.Fact("image.icc.connectionSpace", icc.ConnectionSpaceSignature);
            foreach (OfficeIccTagEvidence tag in icc.Tags) output.Fact("image.icc.tag", tag.Signature, attributes: new Dictionary<string, string>
            { ["offset"] = tag.Offset.ToString(CultureInfo.InvariantCulture), ["length"] = tag.LengthBytes.ToString(CultureInfo.InvariantCulture), ["type"] = tag.TypeSignature });
        }
        foreach (string issue in metadata.Issues) output.Diagnostic(issue, "The native image metadata inspection reported a bounded profile issue.");
        output.Fact("image.metadata.completeWithinProfile", metadata.IsComplete.ToString(), ReportFactOrigin.Derived, ReportFactKind.Boolean);
    }
    private static string Number(long value) => value.ToString(CultureInfo.InvariantCulture);
}
