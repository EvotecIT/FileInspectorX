using System.IO.Compression;

namespace FileInspectorX;

public static partial class FileInspector
{
    private static void AnalyzeContainers(InspectionInput input, DetectionOptions options, ContentTypeDetectionResult det, FileAnalysis res)
    {
        var path = input.Name;
            // Encoded payloads (base64/hex/ascii85/uu) — bounded decode of head and inner type detection
            if (det.Extension is "b64" or "hex" or "b85" or "uu" or "qp")
            {
                try
                {
                    if (TryDecodeEncodedHead(input, det.Extension!, out var decoded, out var encKind))
                    {
                        res.EncodedKind = encKind;
                        if (encKind == "base64") res.Flags |= ContentFlags.EncodedBase64;
                        else if (encKind == "hex") res.Flags |= ContentFlags.EncodedHex;
                        else if (encKind == "base85") res.Flags |= ContentFlags.EncodedBase85;
                        else if (encKind == "uuencode") res.Flags |= ContentFlags.EncodedUu;
                        var toDetect = decoded;
                        // Optional gzip unwrap if the decoded bytes start with GZIP header
                        if (toDetect.Length >= 2 && toDetect[0] == 0x1F && toDetect[1] == 0x8B)
                        {
                            try {
                                using var ms = new MemoryStream(toDetect);
                                using var gz = new GZipStream(ms, CompressionMode.Decompress, leaveOpen: true);
                                using var outMs = new MemoryStream();
                                var buf = new byte[8192]; int read; int left = OperationSettings.EncodedDecodeMaxBytes;
                                while (left > 0 && (read = gz.Read(buf, 0, Math.Min(buf.Length, left))) > 0) { outMs.Write(buf, 0, read); left -= read; }
                                toDetect = outMs.ToArray();
                            } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { }
                        }
                        var detInner = Detect(new ReadOnlySpan<byte>(toDetect, 0, Math.Min(toDetect.Length, OperationSettings.EncodedDecodeMaxBytes)), null);
                        if (detInner != null) { res.EncodedInnerDetection = detInner; }
                        var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                        string encCode = encKind switch { "base64" => "enc:b64", "hex" => "enc:hex", "base85" => "enc:b85", "uuencode" => "enc:uu", "quoted-printable" => "enc:qp", _ => "enc:unk" };
                        list.Add(encCode);
                        if (detInner != null) list.Add($"enc:det:{detInner.Extension}");
                        res.SecurityFindings = list;
                    }
                }
                catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { }
            }

            // OOXML macros and ZIP container hints
            if ((options?.IncludeContainer != false) && (det.Extension is "docx" or "xlsx" or "pptx" || det.Extension == "zip")) {
                TryInspectZip(input, options, out bool hasMacros, out var subType, out int? count, out var topExt, out bool hasExec, out bool hasScripts, out bool hasNestedArchives,
                    out bool hasTraversal, out bool hasSymlink, out bool hasAbs, out bool hasInstallers, out bool hasRemoteTemplate, out bool hasDde, out bool hasExtLinks, out int extLinksCount,
                    out bool hasEncryptedEntries, out int encryptedCount, out bool isOoxmlEncrypted, out bool hasDisguisedExec, out List<string>? findings,
                    out List<Reference>? archiveReferences,
                    out int innerExecSampled, out int innerSignedAny, out int innerValid, out Dictionary<string,int>? innerPublishers, out Dictionary<string,int>? innerPublishersValid, out Dictionary<string,int>? innerPublishersSelf, out List<InnerEntryPreview>? previewOut, out Dictionary<string,int>? innerExecExtCounts,
                    out bool archiveInspectionComplete, out IReadOnlyList<string>? archiveInspectionIssues);
                if (hasMacros) res.Flags |= ContentFlags.HasOoxmlMacros;
                if (subType != null) res.ContainerSubtype = subType;
                if (count != null) res.ContainerEntryCount = count;
                if (topExt != null) res.ContainerTopExtensions = topExt;
                if (hasExec) res.Flags |= ContentFlags.ContainerContainsExecutables;
                if (hasScripts) res.Flags |= ContentFlags.ContainerContainsScripts;
                if (hasNestedArchives) res.Flags |= ContentFlags.ContainerContainsArchives;
                if (hasInstallers) res.Flags |= ContentFlags.ContainerContainsInstallers;
                if (hasTraversal) res.Flags |= ContentFlags.ArchiveHasPathTraversal;
                if (hasSymlink) res.Flags |= ContentFlags.ArchiveHasSymlinks;
                if (hasAbs) res.Flags |= ContentFlags.ArchiveHasAbsolutePaths;
                if (hasEncryptedEntries) res.Flags |= ContentFlags.ArchiveHasEncryptedEntries;
                if (isOoxmlEncrypted) res.Flags |= ContentFlags.OoxmlEncrypted;
                if (det.Extension is "docx" && hasMacros) res.GuessedExtension ??= "docm";
                if (det.Extension is "xlsx" && hasMacros) res.GuessedExtension ??= "xlsm";
                if (det.Extension is "pptx" && hasMacros) res.GuessedExtension ??= "pptm";
                // Package signature extraction is part of Authenticode analysis, while
                // installer manifest enrichment remains explicitly opt-in.
                if (subType is "appx" or "msix")
                {
                    TryPopulateAppxSignature(input, res);
                }
                if (hasRemoteTemplate) res.Flags |= ContentFlags.OfficeRemoteTemplate;
                if (hasDde) res.Flags |= ContentFlags.OfficePossibleDde;
                if (hasExtLinks) {
                    res.Flags |= ContentFlags.OfficeExternalLinks;
                    res.OfficeExternalLinksCount = extLinksCount;
                }
                if (hasDisguisedExec) res.Flags |= ContentFlags.ContainerHasDisguisedExecutables;
                if (encryptedCount > 0) res.EncryptedEntryCount = encryptedCount;
                if (findings != null && findings.Count > 0)
                {
                    var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                    list.AddRange(findings);
                    res.SecurityFindings = list;
                    res.InnerFindings = findings.Take(OperationSettings.DeepContainerMaxEntries).ToArray();
                }
                if (innerExecSampled > 0)
                {
                    res.InnerExecutablesSampled = innerExecSampled;
                    res.InnerSignedExecutables = innerSignedAny;
                    res.InnerValidSignedExecutables = innerValid;
                    if (innerPublishers != null && innerPublishers.Count > 0) res.InnerPublisherCounts = new Dictionary<string,int>(innerPublishers);
                    if (innerPublishersValid != null && innerPublishersValid.Count > 0) res.InnerPublisherValidCounts = new Dictionary<string,int>(innerPublishersValid);
                    if (innerPublishersSelf != null && innerPublishersSelf.Count > 0) res.InnerPublisherSelfSignedCounts = new Dictionary<string,int>(innerPublishersSelf);
                }
                if (previewOut != null && previewOut.Count > 0)
                {
                    res.ArchivePreviewEntries = previewOut.Take(OperationSettings.DeepContainerMaxEntries).ToList();
                }
                if (innerExecExtCounts != null && innerExecExtCounts.Count > 0)
                {
                    res.InnerExecutableExtCounts = innerExecExtCounts;
                }
                if (!archiveInspectionComplete)
                {
                    res.AnalysisComplete = false;
                    res.AnalysisIssues = MergeAnalysisIssues(res.AnalysisIssues, archiveInspectionIssues);
                }
                if ((options?.IncludeReferences != false) && archiveReferences != null && archiveReferences.Count > 0)
                {
                    res.References = MergeReferences(res.References, archiveReferences);
                }
            }

            // TAR scan hints
            if ((options?.IncludeContainer != false) && det.Extension == "tar") {
                TryInspectTar(input, options,
                    out int? count,
                    out var topExt,
                    out bool hasExec,
                    out bool hasScripts,
                    out bool hasNestedArchives,
                    out var tarPreview,
                    out int innerExecSampled,
                    out int innerSignedSampled,
                    out int innerValidSignedSampled,
                    out Dictionary<string, int>? innerPublisherSample, out var tarFlags, out var tarBudget);
                if (count != null) res.ContainerEntryCount = count;
                if (topExt != null) res.ContainerTopExtensions = topExt;
                if (hasExec) res.Flags |= ContentFlags.ContainerContainsExecutables;
                if (hasScripts) res.Flags |= ContentFlags.ContainerContainsScripts;
                if (hasNestedArchives) res.Flags |= ContentFlags.ContainerContainsArchives;
                if (tarPreview != null && tarPreview.Count > 0) res.ArchivePreviewEntries = tarPreview.Take(OperationSettings.DeepContainerMaxEntries).ToList();
                if (innerExecSampled > 0)
                {
                    res.InnerExecutablesSampled = innerExecSampled;
                    res.InnerSignedExecutables = innerSignedSampled;
                    res.InnerValidSignedExecutables = innerValidSignedSampled;
                    if (innerPublisherSample != null && innerPublisherSample.Count > 0)
                        res.InnerPublisherCounts = new Dictionary<string, int>(innerPublisherSample);
                }
                res.Flags |= tarFlags;
                ApplyArchiveInspectionBudget(res, tarBudget);
            }

            // RAR/7z quick flags + (best-effort) encrypted entries accounting under budget
            if ((options?.IncludeContainer != false) && (det.Extension == "rar"))
            {
                // Distinguish RAR4 vs RAR5 by signature
                try {
                    using var fsr = input.OpenRead();
                    var head = new byte[8]; int nr = ReadAvailable(fsr, head, 0, head.Length);
                    bool isRar5 = nr >= 8 && head[0]==0x52 && head[1]==0x61 && head[2]==0x72 && head[3]==0x21 && head[4]==0x1A && head[5]==0x07 && head[6]==0x01 && head[7]==0x00;
                    bool isRar4 = !isRar5;
                    if (isRar4)
                    {
                        if (TryInspectRarQuick(input))
                            res.Flags |= ContentFlags.ArchiveHasEncryptedEntries;
                        if (TryCountRar4EncryptedFiles(input, OperationSettings.DeepContainerMaxEntries, out int encCount, out int totalCount))
                        {
                            if (encCount > 0) res.Flags |= ContentFlags.ArchiveHasEncryptedEntries;
                            res.EncryptedEntryCount = encCount;
                            var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                            list.Add($"rar4:enc={encCount}/{totalCount}");
                            res.SecurityFindings = list;
                            res.InnerFindings = (res.InnerFindings ?? Array.Empty<string>()).Concat(new[]{ $"rar4:enc={encCount}/{totalCount}" }).ToArray();
                        }
                        if (TryInspectRar4Entries(input,
                            out int? entryCount,
                            out IReadOnlyList<string>? topExt,
                            out bool hasExecutables,
                            out bool hasScripts,
                            out bool hasNestedArchives,
                            out List<InnerEntryPreview>? previewOut,
                            out Dictionary<string,int>? innerExecExtCounts))
                        {
                            if (entryCount != null) res.ContainerEntryCount = entryCount;
                            if (topExt != null) res.ContainerTopExtensions = topExt;
                            if (hasExecutables) res.Flags |= ContentFlags.ContainerContainsExecutables;
                            if (hasScripts) res.Flags |= ContentFlags.ContainerContainsScripts;
                            if (hasNestedArchives) res.Flags |= ContentFlags.ContainerContainsArchives;
                            if (previewOut != null && previewOut.Count > 0)
                                res.ArchivePreviewEntries = previewOut.Take(OperationSettings.DeepContainerMaxEntries).ToList();
                            if (innerExecExtCounts != null && innerExecExtCounts.Count > 0)
                                res.InnerExecutableExtCounts = new Dictionary<string,int>(innerExecExtCounts);
                        }
                        // Optional deep signer sampling for uncompressed, non-encrypted entries (store-only), bounded by budgets
                        if (OperationSettings.DeepContainerScanEnabled)
                        {
                            if (TrySampleRar4InnerSigners(input, options, OperationSettings.DeepContainerMaxEntries, OperationSettings.DeepContainerMaxEntryBytes,
                                out int innerExecSampled, out int innerSignedAny, out int innerValid, out var innerPublishers, out var signerBudget))
                            {
                                if (innerExecSampled > 0)
                                {
                                    res.InnerExecutablesSampled = innerExecSampled;
                                    res.InnerSignedExecutables = innerSignedAny;
                                    res.InnerValidSignedExecutables = innerValid;
                                    if (innerPublishers != null && innerPublishers.Count > 0) res.InnerPublisherCounts = innerPublishers;
                                }
                            }
                            ApplyArchiveInspectionBudget(res, signerBudget);
                        }
                    }
                    else
                    {
                        if (TryInspectRarQuick(input))
                        {
                            res.Flags |= ContentFlags.ArchiveHasEncryptedEntries;
                            var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                            list.Add("rar5:headers-encrypted");
                            res.SecurityFindings = list;
                        }
                    }
                } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { if (TryInspectRarQuick(input)) res.Flags |= ContentFlags.ArchiveHasEncryptedEntries; }
            }
            if ((options?.IncludeContainer != false) && (det.Extension == "7z"))
            {
                if (TryDetect7zEncryptedHeaders(input))
                {
                    res.Flags |= ContentFlags.ArchiveHasEncryptedEntries;
                    var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                    list.Add("7z:headers-encrypted");
                    res.SecurityFindings = list;
                }
                else if (TryCount7zFilesQuick(input, OperationSettings.DetectionReadBudgetBytes, out int files))
                {
                    res.ContainerEntryCount = files;
                    var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                    list.Add($"7z:files={files}");
                    res.SecurityFindings = list;
                    // Best-effort: extract plain entry names from an unencoded Next Header
                    if (TryRead7zEntryNamesFromHeader(input, OperationSettings.DetectionReadBudgetBytes, out var entryNames))
                    {
                        var exts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                        var previews = new List<InnerEntryPreview>();
                        var innerExecExtCounts = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
                        bool hasExecutables = false, hasScripts = false, hasNestedArchives = false;

                        foreach (var name in entryNames)
                        {
                            var ext = GetExtension(name);
                            if (!string.IsNullOrEmpty(ext))
                                exts[ext] = exts.TryGetValue(ext, out var c) ? c + 1 : 1;

                            if (IsExecutableName(name))
                            {
                                hasExecutables = true;
                                if (!string.IsNullOrEmpty(ext))
                                    innerExecExtCounts[ext] = innerExecExtCounts.TryGetValue(ext, out var c) ? c + 1 : 1;
                            }
                            if (IsScriptName(name)) hasScripts = true;
                            if (IsArchiveLikeExtension(ext)) hasNestedArchives = true;

                            if (previews.Count < Math.Min(5, OperationSettings.DeepContainerMaxEntries))
                                previews.Add(new InnerEntryPreview { Name = name, DetectedExtension = string.IsNullOrEmpty(ext) ? null : ext });
                        }

                        if (exts.Count > 0)
                            res.ContainerTopExtensions = exts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).Take(5).Select(kv => kv.Key).ToArray();
                        if (hasExecutables) res.Flags |= ContentFlags.ContainerContainsExecutables;
                        if (hasScripts) res.Flags |= ContentFlags.ContainerContainsScripts;
                        if (hasNestedArchives) res.Flags |= ContentFlags.ContainerContainsArchives;
                        if (innerExecExtCounts.Count > 0) res.InnerExecutableExtCounts = innerExecExtCounts;
                        if (previews.Count > 0) res.ArchivePreviewEntries = previews;

                        int exeLikeCount = entryNames.Count(n => IsExecutableName(n));
                        if (exeLikeCount > 0)
                        {
                            var list2 = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                            list2.Add($"7z:names-exe={exeLikeCount}");
                            res.SecurityFindings = list2;
                        }
                    }
                }
            }
            // 7z encryption detection is non-trivial; reserved for a deeper pass in future

    }
}
