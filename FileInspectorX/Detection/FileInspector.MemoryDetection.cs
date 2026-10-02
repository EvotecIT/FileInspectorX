using System.IO.Compression;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace FileInspectorX;

public static partial class FileInspector
{
    /// <summary>
    /// Detects content type from an in-memory byte array without copying the buffer.
    /// </summary>
    public static ContentTypeDetectionResult? Detect(byte[] data, DetectionOptions? options = null, string? declaredExtension = null)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        return Detect(data.AsMemory(), options, declaredExtension);
    }

    /// <summary>
    /// Detects content type from in-memory data without copying the underlying buffer.
    /// </summary>
    public static ContentTypeDetectionResult? Detect(ReadOnlyMemory<byte> data, DetectionOptions? options = null, string? declaredExtension = null)
    {
        return DetectCore(data.Span, data, options, declaredExtension);
    }

    /// <summary>
    /// Detects content type from an in-memory span of bytes.
    /// Prefer the <see cref="Detect(byte[], DetectionOptions?, string?)"/> or
    /// <see cref="Detect(ReadOnlyMemory{byte}, DetectionOptions?, string?)"/> overloads when the input is array-backed,
    /// because crypto ASN.1 parsing needs ReadOnlyMemory and span-only callers pay a bridge allocation.
    /// </summary>
    public static ContentTypeDetectionResult? Detect(ReadOnlySpan<byte> data, DetectionOptions? options)
    {
        return DetectCore(data, null, options, null);
    }

    /// <summary>Detects content type from a byte span with an optional declared extension hint.</summary>
    public static ContentTypeDetectionResult? Detect(ReadOnlySpan<byte> data, DetectionOptions? options = null, string? declaredExtension = null)
    {
        return DetectCore(data, null, options, declaredExtension);
    }

    private static ContentTypeDetectionResult? DetectCore(ReadOnlySpan<byte> data, ReadOnlyMemory<byte>? dataMemory, DetectionOptions? options, string? declaredExtension) {
        options ??= new DetectionOptions();
        ValidateLearnedClassificationMode(options);
        var learnedData = options.LearnedClassificationMode != LearnedClassificationMode.Off
            ? dataMemory ?? new ReadOnlyMemory<byte>(data.ToArray())
            : default(ReadOnlyMemory<byte>?);
        ContentTypeDetectionResult? Finish(ContentTypeDetectionResult? det)
        {
            var biased = ApplyDeclaredBias(det, declaredExtension);
            return learnedData.HasValue
                ? ApplyLearnedClassification(biased, learnedData.Value, options)
                : biased;
        }
        if (Signatures.TryMatchCompleteContainers(data, out var completeContainer)) return Finish(Enrich(completeContainer, data, null, options));
        if (Signatures.TryMatchCommonBinary(data, data.Length, out var commonBinary)) return Finish(Enrich(commonBinary, data, null, options));
        if (Signatures.TryMatchHdf5(data, out var hdf5)) return Finish(Enrich(hdf5, data, null, options));
        if (Signatures.TryMatchRegistryExport(data, out var registryExport)) return Finish(Enrich(registryExport, data, null, options));
        if (Signatures.TryMatchZip(data, out var validatedZip)) return Finish(Enrich(RefineZip(data, dataMemory, validatedZip), data, null, options));
        if (Signatures.TryMatchOle2(data, out var validatedOle)) return Finish(Enrich(validatedOle, data, null, options));
        if (Signatures.TryMatchExtendedHeaderFormats(data, out var extendedBinary)) return Finish(Enrich(extendedBinary, data, null, options));
        if (Signatures.TryMatchTar(data, out var tar)) return Finish(Enrich(tar, data, null, options));
        if (Signatures.TryMatchRiff(data, out var riff)) return Finish(Enrich(riff, data, null, options));
        if (Signatures.TryMatchEvtx(data, out var evtx2)) return Finish(Enrich(evtx2, data, null, options));
        if (Signatures.TryMatchMinidump(data, out var minidump2)) return Finish(Enrich(minidump2, data, null, options));
        if (Signatures.TryMatchProtectedDump(data, out var protectedDump2)) return Finish(Enrich(protectedDump2, data, null, options));
        if (Signatures.TryMatchShellLink(data, out var shellLink)) return Finish(Enrich(shellLink, data, null, options));
        if (Signatures.TryMatchEse(data, out var ese2)) return Finish(Enrich(ese2, data, null, options));
        if (Signatures.TryMatchRegistryHive(data, out var hive2)) return Finish(Enrich(hive2, data, null, options));
        if (Signatures.TryMatchRegistryPol(data, out var pol2)) return Finish(Enrich(pol2, data, null, options));
        if (Signatures.TryMatchFtyp(data, out var ftyp)) return Finish(Enrich(ftyp, data, null, options));
        if (Signatures.TryMatchSqlite(data, out var sqlite)) return Finish(Enrich(sqlite, data, null, options));
        if (Signatures.TryMatchNetCdf(data, out var netCdf)) return Finish(Enrich(netCdf, data, null, options));
        if (Signatures.TryMatchFont(data, out var font)) return Finish(Enrich(font, data, null, options));
        if (Signatures.TryMatchOpenExr(data, data.Length, out var openExr)) return Finish(Enrich(openExr, data, null, options));
        if (Signatures.TryMatchPhotoshop(data, data.Length, out var photoshop)) return Finish(Enrich(photoshop, data, null, options));
        if (Signatures.TryMatchJpeg2000(data, out var jpeg2000)) return Finish(Enrich(jpeg2000, data, null, options));
        if (dataMemory.HasValue)
        {
            if (Signatures.TryMatchPkcs12(dataMemory.Value, out var p12Mem)) return Finish(Enrich(p12Mem, data, null, options));
            if (Signatures.TryMatchPkcs7SignedData(dataMemory.Value, out var pkcs7Mem)) return Finish(Enrich(pkcs7Mem, data, null, options));
            if (Signatures.TryMatchDerCertificate(dataMemory.Value, out var derMem)) return Finish(Enrich(derMem, data, null, options));
        }
        else
        {
            if (data.Length >= 16 && data[0] == 0x30)
            {
                var cryptoMemory = new ReadOnlyMemory<byte>(data.ToArray());
                if (Signatures.TryMatchPkcs12(cryptoMemory, out var p12)) return Finish(Enrich(p12, data, null, options));
                if (Signatures.TryMatchPkcs7SignedData(cryptoMemory, out var pkcs7)) return Finish(Enrich(pkcs7, data, null, options));
                if (Signatures.TryMatchDerCertificate(cryptoMemory, out var der)) return Finish(Enrich(der, data, null, options));
            }
        }
        if (Signatures.TryMatchOpenPgpBinary(data, out var pgpbin)) return Finish(Enrich(pgpbin, data, null, options));
        if (Signatures.TryMatchKeePassKdbx(data, out var kdbx)) return Finish(Enrich(kdbx, data, null, options));
        if (Signatures.TryMatch7z(data, out var _7z)) return Finish(Enrich(_7z, data, null, options));
        if (Signatures.TryMatchRar(data, out var rar)) return Finish(Enrich(rar, data, null, options));
        if (Signatures.TryMatchElf(data, data.Length, out var elf)) return Finish(Enrich(elf, data, null, options));
        if (Signatures.TryMatchJavaClass(data, out var javaClass)) return Finish(Enrich(javaClass, data, null, options));
        if (Signatures.TryMatchDex(data, out var dex)) return Finish(Enrich(dex, data, null, options));
        if (Signatures.TryMatchMachO(data, out var macho)) return Finish(Enrich(macho, data, null, options));
        if (Signatures.TryMatchCab(data, out var cab)) return Finish(Enrich(cab, data, null, options));
        if (Signatures.TryMatchGlb(data, out var glb)) return Finish(Enrich(glb, data, null, options));
        if (Signatures.TryMatchTiff(data, out var tiff)) return Finish(Enrich(tiff, data, null, options));
        foreach (var sig in Signatures.All()) if (Signatures.Match(data, sig)) {
                var conf = sig.Confidence;
                var basic = new ContentTypeDetectionResult {
                    Extension = sig.Extension,
                    MimeType = NormalizeMime(sig.Extension, sig.MimeType),
                    Confidence = conf,
                    Reason = $"magic:{sig.Extension}"
                };
                return Finish(Enrich(basic, data, null, options));
            }
        if (Signatures.TryMatchText(data, out var text, declaredExtension)) return Finish(Enrich(text, data, null, options));
        return Finish(Enrich(null, data, null, options));
    }

}
