namespace FileInspectorX;

public static partial class FileInspector
{
    private static void TryInspectTar(
        InspectionInput input, DetectionOptions? options,
        out int? entryCount,
        out IReadOnlyList<string>? topExtensions,
        out bool hasExecutables,
        out bool hasScripts,
        out bool hasNestedArchives,
        out List<InnerEntryPreview>? previews,
        out int innerExecSampled,
        out int innerSignedSampled,
        out int innerValidSignedSampled,
        out Dictionary<string, int>? innerPublisherSample, out ContentFlags safetyFlags, out ArchiveInspectionBudget budget) {
        var path = input.Name;
        safetyFlags = ContentFlags.None;
        budget = ArchiveInspectionBudget.FromSettings();
        entryCount = null; topExtensions = null; hasExecutables = false; hasScripts = false; hasNestedArchives = false; previews = null;
        innerExecSampled = 0; innerSignedSampled = 0; innerValidSignedSampled = 0; innerPublisherSample = null;
        var localPreviews = new List<InnerEntryPreview>();
        int innerExecutablesSampled = 0, innerSignedExecutables = 0, innerValidSignedExecutables = 0;
        var innerPublishers = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
        int deepScanned = 0; int deepMax = OperationSettings.DeepContainerMaxEntries; int deepBytes = OperationSettings.DeepContainerMaxEntryBytes; bool deep = OperationSettings.DeepContainerScanEnabled;
        try {
            using var fs = input.OpenRead();
            var exts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            int count = 0;
            var reader = new TarInspectionReader(fs, budget);
            while (reader.MoveNext()) {
                string name = reader.Name;
                long size = reader.Size;
                if (ArchivePathSafety.HasTraversal(name) || ArchivePathSafety.HasTraversal(reader.LinkName)) safetyFlags |= ContentFlags.ArchiveHasPathTraversal;
                if (ArchivePathSafety.IsAbsolute(name) || ArchivePathSafety.IsAbsolute(reader.LinkName)) safetyFlags |= ContentFlags.ArchiveHasAbsolutePaths;
                if (reader.Type is (byte)'1' or (byte)'2') safetyFlags |= ContentFlags.ArchiveHasSymlinks;
                if (reader.Type != (byte)'5' && !string.IsNullOrEmpty(name) && !name.EndsWith("/")) {
                    var ext = GetExtension(name);
                    if (!string.IsNullOrEmpty(ext)) exts[ext] = exts.TryGetValue(ext, out var c) ? c + 1 : 1;
                    if (IsExecutableName(name)) hasExecutables = true;
                    if (IsScriptName(name)) hasScripts = true;
                    count++;
                    // Deep sampling for small executables/scripts and nested-archive head peeks
                    if (size > 0)
                    {
                        long pad = ((size + 511) / 512) * 512;
                        long entryDataStart = fs.Position;
                        long nextHeaderPos = entryDataStart + pad;
                        // 1) Quick nested-archive peek (up to 64 bytes) without moving beyond current entry
                        if (!hasNestedArchives && size <= 128)
                        {
                            int sample = (int)Math.Min(64, size);
                            var head = new byte[sample];
                            using var payload = budget.OpenTarPayload(fs, size, sample);
                            int nhead = payload == null ? 0 : ReadAvailable(payload, head, 0, head.Length);
                            if (nhead > 0)
                            {
                                var span = new ReadOnlySpan<byte>(head, 0, nhead);
                                var det = Detect(span, null);
                                if (det != null)
                                {
                                    var de = det.Extension?.ToLowerInvariant();
                                    if (de is "zip" or "7z" or "rar" or "tar" or "gz" or "bz2" or "xz" or "zst" or "iso" or "udf")
                                        hasNestedArchives = true;
                                    if (IsExecutableName(name) && localPreviews.Count < 10)
                                        localPreviews.Add(new InnerEntryPreview { Name = name, DetectedExtension = de ?? ext });
                                }
                            }
                            if (nextHeaderPos <= fs.Length) fs.Seek(nextHeaderPos, SeekOrigin.Begin);
                            else fs.Seek(0, SeekOrigin.End);
                            continue;
                        }

                        // 2) Deep signers sampling for executable entries within budget
                        if (deep && IsExecutableName(name) && size <= deepBytes && deepScanned < deepMax)
                        {
                            try
                            {
                                int cap = (int)Math.Min(size, deepBytes);
                                using var payload = budget.OpenTarPayload(fs, size, cap);
                                if (payload == null) continue;
                                int left = cap;
                                using var entryInput = new MemoryStream();
                                {
                                    var buf = new byte[Math.Min(8192, cap)];
                                    while (left > 0)
                                    {
                                        int r = payload.Read(buf, 0, Math.Min(buf.Length, left));
                                        if (r <= 0) break;
                                        entryInput.Write(buf, 0, r);
                                        left -= r;
                                    }
                                }
                                if (nextHeaderPos <= fs.Length) fs.Seek(nextHeaderPos, SeekOrigin.Begin);
                                else fs.Seek(0, SeekOrigin.End);

                                if (left > 0) continue;

                                var childOptions = CreateInnerAnalysisOptions(options, GetNestedContainerBudget(options), options?.NestedContainerDepth ?? 0, includeContainer: false);
                                var ia = AnalyzeArchiveChild(input, entryInput, name, childOptions, budget, nativeSignerSampling: true);
                                deepScanned++;
                                innerExecutablesSampled++;
                                if (ia?.Authenticode?.Present == true)
                                {
                                    innerSignedExecutables++;
                                    bool v = GetSignatureStatus(ia)?.IsValid == true;
                                    if (v) innerValidSignedExecutables++;
                                    var pub = ia.Authenticode.SignerSubjectCN ?? ia.Authenticode.SignerSubject ?? "<unknown>";
                                    if (innerPublishers.TryGetValue(pub, out var pc)) innerPublishers[pub] = pc + 1; else innerPublishers[pub] = 1;
                                }
                                continue;
                            }
                            catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException)
                            {
                                // On error, seek to next padded header position to keep parser stable.
                                if (nextHeaderPos <= fs.Length) fs.Seek(nextHeaderPos, SeekOrigin.Begin);
                                else fs.Seek(0, SeekOrigin.End);
                                continue;
                            }
                        }
                        // 3) Not sampled – skip entire entry payload to next header
                        if (nextHeaderPos <= fs.Length) fs.Seek(nextHeaderPos, SeekOrigin.Begin);
                        else fs.Seek(0, SeekOrigin.End);
                        continue;
                    }
                }
                long toSkip = ((size + 511) / 512) * 512;
                if (toSkip > 0) fs.Seek(toSkip, SeekOrigin.Current);
            }
            entryCount = count;
            topExtensions = exts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).Take(5).Select(kv => kv.Key).ToArray();
            if (localPreviews.Count > 0) previews = localPreviews;
            innerExecSampled = innerExecutablesSampled;
            innerSignedSampled = innerSignedExecutables;
            innerValidSignedSampled = innerValidSignedExecutables;
            if (innerPublishers.Count > 0) innerPublisherSample = innerPublishers;
            // TAR is not a JAR/APK container; subtype/signing hints handled in ZIP logic.
        } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { budget.AddIssue("tar:inspection-failed"); }
    }

}
