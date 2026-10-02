using System.IO.Compression;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace FileInspectorX;

public static partial class FileInspector
{
    /// <summary>
    /// Detects content type from a file path and enriches the result using <paramref name="options"/>.
    /// </summary>
    public static ContentTypeDetectionResult? Detect(string path, DetectionOptions? options)
    {
        using var operation = InspectionOperation.Begin(options, retainUnknownDetection: true);
        ContentTypeDetectionResult? result;
        using (operation.Measure(InspectionStage.Detection))
            result = DetectPathCore(path, operation.Options, propagateReadFailure: false);
        return CompleteDetection(result);
    }

    private static ContentTypeDetectionResult? DetectPathCore(string path, DetectionOptions? options, bool propagateReadFailure) {
        try {
            options ??= new DetectionOptions();
            ValidateLearnedClassificationMode(options);
            var deterministicOptions = options.LearnedClassificationMode == LearnedClassificationMode.Off
                ? options
                : WithoutLearnedClassification(options);
            using var fs = OpenReadShared(path);
            var extDeclared = System.IO.Path.GetExtension(path)?.Trim('.').ToLowerInvariant();
            ContentTypeDetectionResult? Finish(ContentTypeDetectionResult? result)
                => ApplyLearnedClassification(result, fs, options);
            var det = DetectStreamCore(fs, deterministicOptions, extDeclared);
            try {
                if (det != null && det.Extension != null && det.Extension.Equals("exe", StringComparison.OrdinalIgnoreCase) && PeReader.TryReadPe(fs, out var pe)) {
                    // A successful PE parse refines family details, but does not validate every section entry.
                    det.Confidence = "Medium";
                    det.Reason = AppendReason(det.Reason, "pe:header");
                    const ushort IMAGE_FILE_DLL = 0x2000;
                    if ((pe.Characteristics & IMAGE_FILE_DLL) != 0) { det.Extension = "dll"; det.Reason = AppendReason(det.Reason, "pe-family-precise"); }
                    else if (pe.Subsystem == 1) { det.Extension = "sys"; det.Reason = AppendReason(det.Reason, "pe-family-precise"); }
                }
            } catch { }
            // Special-case ETL: detect by magic (preferred) and optionally validate.
            var ext = System.IO.Path.GetExtension(path)?.Trim('.').ToLowerInvariant();
            bool declaredEtl = string.Equals(ext, "etl", StringComparison.OrdinalIgnoreCase);
            bool magicOk = false;
            try { magicOk = TryMatchEtlMagic(fs); } catch { magicOk = false; }
            if (magicOk || declaredEtl)
            {
                try
                {
                    Breadcrumbs.Write("ETL_VALIDATE_BEGIN", path: path);
                    var mime = MimeMaps.Default.TryGetValue("etl", out var mm) ? mm : "application/octet-stream";
                    if (!magicOk)
                    {
                        Breadcrumbs.Write("ETL_VALIDATE_END", message: "magic-mismatch", path: path);
                    }
                    else
                    {
                        var detEtl = det ?? new ContentTypeDetectionResult();
                        detEtl.Extension = "etl";
                        detEtl.MimeType = mime;
                        detEtl.Confidence = "Medium";
                        detEtl.Reason = "etl:magic";

                        var mode = OperationSettings.EtlValidation;
                        if (mode == Settings.EtlValidationMode.Off || mode == Settings.EtlValidationMode.MagicOnly)
                        {
                            Breadcrumbs.Write("ETL_VALIDATE_END", message: "magic-ok", path: path);
                            return Finish(detEtl);
                        }

                        bool? okNative = null;
                        if (mode == Settings.EtlValidationMode.NativeThenTracerpt)
                        {
                            try { okNative = EtlNative.TryOpen(path); }
                            catch (Exception ex) { Breadcrumbs.Write("ETL_NATIVE_ERROR", message: ex.GetType().Name + ":" + ex.Message, path: path); }
                            if (okNative == true)
                            {
                                Breadcrumbs.Write("ETL_VALIDATE_END", message: "native-ok", path: path);
                                detEtl.Confidence = "High";
                                detEtl.Reason = "etw:ok";
                                return Finish(detEtl);
                            }
                        }

                        if (mode == Settings.EtlValidationMode.TracerptOnly || mode == Settings.EtlValidationMode.NativeThenTracerpt)
                        {
                            bool? okTr = null;
                            try { okTr = EtlProbe.TryValidate(path, OperationSettings.EtlProbeTimeoutMs); }
                            catch (Exception ex) { Breadcrumbs.Write("ETL_TRACERPT_ERROR", message: ex.GetType().Name + ":" + ex.Message, path: path); }
                            if (okTr == true)
                            {
                                Breadcrumbs.Write("ETL_VALIDATE_END", message: "tracerpt-ok", path: path);
                                detEtl.Confidence = "High";
                                detEtl.Reason = "tracerpt:ok";
                                return Finish(detEtl);
                            }
                            if (okTr == false) detEtl.Reason = AppendReason(detEtl.Reason, "tracerpt-fail");
                            else if (okTr == null) detEtl.Reason = AppendReason(detEtl.Reason, "tracerpt-n/a");
                        }

                        Breadcrumbs.Write("ETL_VALIDATE_END", message: okNative == false ? "native-fail" : "no-success", path: path);
                        return Finish(detEtl);
                    }
                }
                catch (IOException ex)
                {
                    Breadcrumbs.Write("ETL_VALIDATE_IO_ERROR", message: ex.GetType().Name + ":" + ex.Message, path: path);
                    var mime = MimeMaps.Default.TryGetValue("etl", out var mm) ? mm : "application/octet-stream";
                    return Finish(new ContentTypeDetectionResult { Extension = "etl", MimeType = mime, Confidence = "Low", Reason = "etl:validation-error" });
                }
                catch (Exception ex) when (
                    ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException)
                {
                    Breadcrumbs.Write("ETL_VALIDATE_ERROR", message: ex.GetType().Name + ":" + ex.Message, path: path);
                    var mime = MimeMaps.Default.TryGetValue("etl", out var mm) ? mm : "application/octet-stream";
                    return Finish(new ContentTypeDetectionResult { Extension = "etl", MimeType = mime, Confidence = "Low", Reason = "etl:validation-error" });
                }
            }
            det = ApplyDeclaredBias(det, extDeclared);
            TryValidateStructuredTextWithBudget(fs, det, skipAdmxAdml: true);
            TryValidateAdmxAdmlXmlWellFormedness(fs, path, det, extDeclared);
            return Finish(det);
        } catch (OutOfMemoryException) { throw; }
        catch (LearnedClassificationException) { throw; }
        catch (ArgumentOutOfRangeException) { throw; }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (
            options?.LearnedClassificationMode == LearnedClassificationMode.Required &&
            ex is IOException or UnauthorizedAccessException) {
            throw new LearnedClassificationException(
                "The required learned content classifier could not read the file.", ex);
        }
        catch (Exception) when (!propagateReadFailure) { return null; }
    }

    /// <summary>
    /// Detects content type from a readable stream; the original position is restored where possible.
    /// Fast and minimal: does not perform container/PDF/PE/permission analysis.
    /// </summary>
    public static ContentTypeDetectionResult? Detect(Stream stream, DetectionOptions? options = null, string? declaredExtension = null) {
        if (stream == null) throw new ArgumentNullException(nameof(stream));
        using var operation = InspectionOperation.Begin(options, retainUnknownDetection: true);
        var originalPosition = stream.CanSeek ? stream.Position : (long?)null;
        try
        {
            ContentTypeDetectionResult? result;
            using (operation.Measure(InspectionStage.Detection))
                result = DetectStreamCore(OperationReadStream.Borrow(stream, operation.Options.CancellationToken), operation.Options, declaredExtension);
            return CompleteDetection(result);
        }
        finally
        {
            if (originalPosition.HasValue)
            {
                try { stream.Seek(originalPosition.Value, SeekOrigin.Begin); } catch { }
            }
        }
    }

    private static ContentTypeDetectionResult? DetectStreamCore(
        Stream stream,
        DetectionOptions? options,
        string? declaredExtension) {
        options ??= new DetectionOptions();
        ValidateLearnedClassificationMode(options);
        if (!stream.CanSeek && options.LearnedClassificationMode != LearnedClassificationMode.Off)
        {
            var unsupported = new NotSupportedException(
                "Learned classification requires a seekable stream containing the complete content.");
            if (options.LearnedClassificationMode == LearnedClassificationMode.Required)
                throw new LearnedClassificationException(unsupported.Message, unsupported);
            var deterministic = DetectStreamCore(
                stream,
                WithoutLearnedClassification(options),
                declaredExtension);
            return AttachLearnedFailure(deterministic, unsupported);
        }
        var headLen = Math.Max(256, Math.Min(OperationSettings.HeaderReadBytes, 1 << 20));
        var header = new byte[headLen];
        if (stream.CanSeek) stream.Seek(0, SeekOrigin.Begin);
        var read = ReadAvailable(stream, header, 0, headLen);
        bool nonSeekableEof = !stream.CanSeek && read < headLen;
        var src = new ReadOnlySpan<byte>(header, 0, read);
        var srcMemory = new ReadOnlyMemory<byte>(header, 0, read);
        // A short non-seekable read reached EOF and therefore has a known complete length.
        // Filling the sample buffer proves only the prefix length, not the whole-file length.
        long? completeLength = stream.CanSeek ? stream.Length : nonSeekableEof ? read : null;
        ContentTypeDetectionResult? Finish(ContentTypeDetectionResult? det)
            => ApplyLearnedClassification(ApplyDeclaredBias(det, declaredExtension), stream!, options);

        if (stream.CanSeek)
        {
            if (Signatures.TryMatchUdf(stream, out var udf)) return Finish(Enrich(udf, src, stream, options));
            if (Signatures.TryMatchIso(stream, out var iso)) return Finish(Enrich(iso, src, stream, options));
            if (Signatures.TryMatchDmg(stream, out var dmg)) return Finish(Enrich(dmg, src, stream, options));
            if (Signatures.TryMatchMsg(stream, out var msg)) return Finish(Enrich(msg, src, stream, options));
            if (TryMatchEtlMagic(stream)) return Finish(Enrich(new ContentTypeDetectionResult {
                Extension = "etl", MimeType = MimeMaps.Default.TryGetValue("etl", out var mime) ? mime : "application/octet-stream",
                Confidence = "Medium", Reason = "etl:magic"
            }, src, stream, options));
        }

        if (stream.CanSeek && Signatures.TryMatchSeekableContainers(stream, out var seekableContainer))
            return Finish(Enrich(seekableContainer, src, stream, options));
        if (!stream.CanSeek && completeLength.HasValue && Signatures.TryMatchCompleteContainers(src, out var completeContainer))
            return Finish(Enrich(completeContainer, src, stream, options));

        if ((stream.CanSeek ? Signatures.TryMatchPe(stream, out var validatedPe) : Signatures.TryMatchPe(src, completeLength, out validatedPe)))
            return Finish(Enrich(validatedPe, src, stream, options));
        if ((stream.CanSeek ? Signatures.TryMatchLegacyMz(stream, out var legacyMz) : Signatures.TryMatchLegacyMz(src, completeLength, out legacyMz)))
            return Finish(Enrich(legacyMz, src, stream, options));
        if (stream.CanSeek && Signatures.TryMatchPcapNg(stream, out var seekablePcapNg)) return Finish(Enrich(seekablePcapNg, src, stream, options));
        if (!stream.CanSeek && Signatures.TryMatchPcapNg(src, completeLength, out var sampledPcapNg)) return Finish(Enrich(sampledPcapNg, src, stream, options));
        if (stream.CanSeek && Signatures.TryMatchPcap(stream, out var seekablePcap)) return Finish(Enrich(seekablePcap, src, stream, options));
        if ((stream.CanSeek ? Signatures.TryMatchCrx(stream, out var seekableCrx) : Signatures.TryMatchCrx(src, completeLength, out seekableCrx)))
            return Finish(Enrich(seekableCrx, src, stream, options));
        if ((stream.CanSeek ? Signatures.TryMatchIcon(stream, out var validatedIcon) : Signatures.TryMatchIcon(src, completeLength, out validatedIcon)))
            return Finish(Enrich(validatedIcon, src, stream, options));
        if (Signatures.TryMatchCommonBinary(src, completeLength, out var commonBinary)) return Finish(Enrich(commonBinary, src, stream, options));
        // HDF5 user blocks may contain arbitrary bytes, but they must not override a validated
        // primary format such as PE/PDF/ZIP detected above.
        if (stream.CanSeek) {
            if (Signatures.TryMatchHdf5(stream, 0, out var seekableHdf5))
                return Finish(Enrich(seekableHdf5, src, stream, options));
        }
        else if (Signatures.TryMatchHdf5(src, completeLength, out var sampledHdf5)) {
            return Finish(Enrich(sampledHdf5, src, stream, options));
        }
        if (Signatures.TryMatchRegistryExport(src, out var registryExport))
            return Finish(Enrich(registryExport, src, stream, options));
        if ((stream.CanSeek ? Signatures.TryMatchZip(stream, out var validatedZip) : Signatures.TryMatchZip(src, completeLength, out validatedZip))) {
            return Finish(Enrich(RefineZip(stream, validatedZip), src, stream, options));
        }
        if (Signatures.TryMatchOle2(src, out var validatedOle)) {
            using var sample = stream.CanSeek ? null : new MemoryReadStream(srcMemory);
            var refined = TryRefineOle2Subtype(sample ?? stream);
            return Finish(Enrich(refined ?? validatedOle, src, stream, options));
        }
        if (stream.CanSeek && Signatures.TryMatchMatroska(stream, out var seekableMatroska)) return Finish(Enrich(seekableMatroska, src, stream, options));
        if (stream.CanSeek && Signatures.TryMatchQcow2(stream, out var seekableQcow2)) return Finish(Enrich(seekableQcow2, src, stream, options));
        if (stream.CanSeek && Signatures.TryMatchMidi(stream, out var seekableMidi)) return Finish(Enrich(seekableMidi, src, stream, options));
        if (stream.CanSeek && Signatures.TryMatchRpm(stream, out var seekableRpm)) return Finish(Enrich(seekableRpm, src, stream, options));
        if (stream.CanSeek && Signatures.TryMatchDicom(stream, out var seekableDicom)) return Finish(Enrich(seekableDicom, src, stream, options));
        if (Signatures.TryMatchExtendedHeaderFormats(src, completeLength, out var extendedBinary)) return Finish(Enrich(extendedBinary, src, stream, options));

        // TAR, RIFF, EVTX, ESE/Registry, SQLite quick checks first
        if (Signatures.TryMatchTar(src, out var tar)) return Finish(Enrich(tar, src, stream, options));
        if (Signatures.TryMatchRiff(src, out var riff)) return Finish(Enrich(riff, src, stream, options));
        if ((stream.CanSeek ? Signatures.TryMatchEvtx(stream, out var evtx) : Signatures.TryMatchEvtx(src, completeLength, out evtx)))
            return Finish(Enrich(evtx, src, stream, options));
        if ((stream.CanSeek ? Signatures.TryMatchMinidump(stream, out var minidump) : Signatures.TryMatchMinidump(src, completeLength, out minidump)))
            return Finish(Enrich(minidump, src, stream, options));
        if (Signatures.TryMatchProtectedDump(src, out var protectedDump)) return Finish(Enrich(protectedDump, src, stream, options));
        if (Signatures.TryMatchShellLink(src, completeLength, out var shellLink)) return Finish(Enrich(shellLink, src, stream, options));
        if (Signatures.TryMatchEse(src, out var ese)) return Finish(Enrich(ese, src, stream, options));
        if ((stream.CanSeek ? Signatures.TryMatchRegistryHive(stream, out var hive) : Signatures.TryMatchRegistryHive(src, completeLength, out hive)))
            return Finish(Enrich(hive, src, stream, options));
        if (Signatures.TryMatchRegistryPol(src, out var pol)) return Finish(Enrich(pol, src, stream, options));
        if ((stream.CanSeek ? Signatures.TryMatchFtyp(stream, out var ftyp) : Signatures.TryMatchFtyp(src, completeLength, out ftyp)))
            return Finish(Enrich(ftyp, src, stream, options));
        if (Signatures.TryMatchSqlite(src, out var sqlite)) return Finish(Enrich(sqlite, src, stream, options));
        if ((stream.CanSeek ? Signatures.TryMatchNetCdf(stream, out var netCdf) : Signatures.TryMatchNetCdf(src, completeLength, out netCdf)))
            return Finish(Enrich(netCdf, src, stream, options));
        if ((stream.CanSeek ? Signatures.TryMatchFont(stream, out var font) : Signatures.TryMatchFont(src, completeLength, out font)))
            return Finish(Enrich(font, src, stream, options));
        if (Signatures.TryMatchOpenExr(src, completeLength, out var openExr)) return Finish(Enrich(openExr, src, stream, options));
        if ((stream.CanSeek ? Signatures.TryMatchPhotoshop(stream, out var photoshop) : Signatures.TryMatchPhotoshop(src, completeLength, out photoshop)))
            return Finish(Enrich(photoshop, src, stream, options));
        if ((stream.CanSeek ? Signatures.TryMatchJpeg2000(stream, out var jpeg2000) : Signatures.TryMatchJpeg2000(src, completeLength, out jpeg2000)))
            return Finish(Enrich(jpeg2000, src, stream, options));
        var cryptoMemory = ReadCryptoSample(stream, srcMemory);
        if (Signatures.TryMatchPkcs12(cryptoMemory, out var p12)) return Finish(Enrich(p12, src, stream, options));
        if (Signatures.TryMatchPkcs7SignedData(cryptoMemory, out var pkcs7)) return Finish(Enrich(pkcs7, src, stream, options));
        if (Signatures.TryMatchDerCertificate(cryptoMemory, out var der)) return Finish(Enrich(der, src, stream, options));
        if (Signatures.TryMatchOpenPgpBinary(src, out var pgpbin)) return Finish(Enrich(pgpbin, src, stream, options));
        if (Signatures.TryMatchKeePassKdbx(src, out var kdbx)) return Finish(Enrich(kdbx, src, stream, options));
        if (Signatures.TryMatch7z(src, out var _7z)) return Finish(Enrich(_7z, src, stream, options));
        if (Signatures.TryMatchRar(src, out var rar)) return Finish(Enrich(rar, src, stream, options));
        if ((stream.CanSeek ? Signatures.TryMatchElf(stream, out var elf) : Signatures.TryMatchElf(src, completeLength, out elf)))
            return Finish(Enrich(elf, src, stream, options));
        if ((stream.CanSeek ? Signatures.TryMatchJavaClass(stream, out var javaClass) : Signatures.TryMatchJavaClass(src, completeLength, out javaClass)))
            return Finish(Enrich(javaClass, src, stream, options));
        if ((stream.CanSeek ? Signatures.TryMatchDex(stream, out var dex) : Signatures.TryMatchDex(src, completeLength, out dex)))
            return Finish(Enrich(dex, src, stream, options));
        if ((stream.CanSeek ? Signatures.TryMatchMachO(stream, out var macho) : Signatures.TryMatchMachO(src, completeLength, out macho)))
            return Finish(Enrich(macho, src, stream, options));
        if (Signatures.TryMatchCab(src, completeLength, out var cab)) return Finish(Enrich(cab, src, stream, options));
        if ((stream.CanSeek ? Signatures.TryMatchGlb(stream, out var glb) : Signatures.TryMatchGlb(src, completeLength, out glb)))
            return Finish(Enrich(glb, src, stream, options));
        if ((stream.CanSeek ? Signatures.TryMatchTiff(stream, out var tiff) : Signatures.TryMatchTiff(src, completeLength, out tiff)))
            return Finish(Enrich(tiff, src, stream, options));

        foreach (var sig in Signatures.All()) {
            if (Signatures.Match(src, sig)) {
                var conf = sig.Confidence;
                var basic = new ContentTypeDetectionResult {
                    Extension = sig.Extension,
                    MimeType = NormalizeMime(sig.Extension, sig.MimeType),
                    Confidence = conf,
                    Reason = $"magic:{sig.Extension}"
                };
                var enriched = Enrich(basic, src, stream, options);
                return Finish(enriched);
            }
        }

        if (Signatures.TryMatchText(src, out var text, declaredExtension)) {
            if (text is not null && text.Extension == "json") {
                var refined = stream.CanSeek ? TryRefineGltfJson(stream) : TryRefineGltfJson(srcMemory);
                if (refined != null) return Finish(Enrich(refined, src, stream, options));
            }
            var enriched = Enrich(text, src, stream, options);
            var deterministic = ApplyDeclaredBias(enriched, declaredExtension);
            TryValidateStructuredTextWithBudget(stream, deterministic, skipAdmxAdml: false);
            return ApplyLearnedClassification(deterministic, stream, options);
        }
        return Finish(Enrich(null, src, stream, options));
    }

    // ASN.1 import needs complete content, rather than a truncated recognition prefix.
    // Only candidate inputs within the existing certificate read budget receive a bridge.
    private static ReadOnlyMemory<byte> ReadCryptoSample(Stream stream, ReadOnlyMemory<byte> header)
    {
        if (header.IsEmpty || header.Span[0] != 0x30 || !stream.CanSeek) return header;
        long length = stream.Length;
        if (length <= header.Length || length > GetCertificateParseReadBudgetBytes()) return header;
        long position = stream.Position;
        try
        {
            stream.Seek(0, SeekOrigin.Begin);
            var complete = new byte[(int)length];
            return ReadAvailable(stream, complete, 0, complete.Length) == complete.Length ? complete : header;
        }
        finally { stream.Seek(position, SeekOrigin.Begin); }
    }

    internal static int ReadAvailable(Stream stream, byte[] buffer, int offset, int count)
    {
        var total = 0;
        while (total < count)
        {
            InspectionOperation.CheckCancellation();
            var read = stream.Read(buffer, offset + total, count - total);
            if (read <= 0) break;
            total += read;
        }
        return total;
    }

    private static ContentTypeDetectionResult? TryRefineGltfJson(Stream stream) {
        try {
            long pos = stream.CanSeek ? stream.Position : 0;
            if (stream.CanSeek) stream.Seek(0, SeekOrigin.Begin);
            using var reader = new StreamReader(stream, System.Text.Encoding.UTF8, true, 8192, leaveOpen: true);
            char[] buf = new char[8192];
            int n = reader.Read(buf, 0, buf.Length);
            var s = new string(buf, 0, n);
            if ((s.IndexOf("\"asset\"", StringComparison.OrdinalIgnoreCase) >= 0 && s.IndexOf("\"version\"", StringComparison.OrdinalIgnoreCase) >= 0) &&
                (s.IndexOf("\"scenes\"", StringComparison.OrdinalIgnoreCase) >= 0 || s.IndexOf("\"nodes\"", StringComparison.OrdinalIgnoreCase) >= 0)) {
                if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin);
                return new ContentTypeDetectionResult { Extension = "gltf", MimeType = "model/gltf+json", Confidence = "Medium", Reason = "gltf:json" };
            }
            if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin);
        } catch { }
        return null;
    }

}
