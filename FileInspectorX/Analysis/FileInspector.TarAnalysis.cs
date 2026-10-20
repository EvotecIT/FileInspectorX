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
        out Dictionary<string, int>? innerPublisherSample, out ContentFlags safetyFlags, out ArchiveInspectionBudget budget,
        out IReadOnlyList<string>? findings) {
        var path = input.Name;
        safetyFlags = ContentFlags.None;
        budget = ArchiveInspectionBudget.FromSettings();
        findings = null;
        var localFindings = new List<string>();
        var urls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var uncPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var suspicious = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        bool encoded = false, exec = false, download = false, hosts = false, unc = false, disguisedScript = false;
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
                        bool looksExecutable = IsExecutableName(name);
                        // Inspect a bounded prefix regardless of the member's complete size.
                        {
                            int sample = (int)Math.Min(512, size);
                            var head = new byte[sample];
                            using var payload = budget.OpenTarPayload(fs, size, sample);
                            int nhead = payload == null ? 0 : ReadAvailable(payload, head, 0, head.Length);
                            if (nhead > 0)
                            {
                                var span = new ReadOnlySpan<byte>(head, 0, nhead);
                                var det = Signatures.TryMatchZip(span, size, out var zipPrefix) ? zipPrefix : Detect(span, null);
                                if (det != null)
                                {
                                    var de = det.Extension?.ToLowerInvariant();
                                    hasScripts |= IsScriptLikeExtension(de);
                                    if (de is "exe" or "dll" or "msi")
                                    {
                                        looksExecutable = true;
                                        hasExecutables = true;
                                        if (!IsExecutableName(name)) safetyFlags |= ContentFlags.ContainerHasDisguisedExecutables;
                                    }
                                    if (de is "zip" or "7z" or "rar" or "tar" or "gz" or "bz2" or "xz" or "zst" or "iso" or "udf")
                                        hasNestedArchives = true;
                                    if (IsExecutableName(name) && localPreviews.Count < 10)
                                        localPreviews.Add(new InnerEntryPreview { Name = name, DetectedExtension = de ?? ext });
                                }
                            }
                            fs.Seek(entryDataStart, SeekOrigin.Begin);
                        }

                        // 2) Deep signers sampling for executable entries within budget
                        if (deep && budget.TryBeginDeepEntry(size, deepScanned, deepMax, deepBytes))
                        {
                            deepScanned++;
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
                                var ia = AnalyzeArchiveChild(input, entryInput, name, childOptions, budget,
                                    nativeSignerSampling: looksExecutable && size <= deepBytes);
                                var detected = ia.Detection?.Extension;
                                bool executable = detected is "exe" or "dll" or "msi";
                                if (executable) innerExecutablesSampled++;
                                hasScripts |= IsScriptLikeExtension(detected);
                                hasExecutables |= executable;
                                if (executable && !IsExecutableName(name)) safetyFlags |= ContentFlags.ContainerHasDisguisedExecutables;
                                if (ShouldDeepAnalyzeNestedArchiveEntry(name, ext, detected)) budget.AddIssue("tar:nested-content-unavailable");
                                CollectArchiveInnerSignals(name, ia, urls, uncPaths, suspicious,
                                    ref encoded, ref exec, ref download, ref hosts, ref unc, ref disguisedScript);
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
                                budget.AddIssue("tar:deep-inspection-failed");
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
            if (encoded) localFindings.Add("archive:inner-script-encoded");
            if (exec) localFindings.Add("archive:inner-script-exec");
            if (download) localFindings.Add("archive:inner-script-download");
            if (hosts) localFindings.Add("archive:inner-external-hosts");
            if (unc) localFindings.Add("archive:inner-unc");
            if (disguisedScript) localFindings.Add("archive:inner-disguised-script");
            if (suspicious.Count > 0) localFindings.Add("archive:inner-files=" + string.Join(", ", suspicious.Take(3)));
            findings = localFindings.Count == 0 ? null : localFindings;
            // TAR is not a JAR/APK container; subtype/signing hints handled in ZIP logic.
        } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { budget.AddIssue("tar:inspection-failed"); }
    }

}
