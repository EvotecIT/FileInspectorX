using System.IO.Compression;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace FileInspectorX;

public static partial class FileInspector
{
    private static void TryInspectZip(string path, DetectionOptions? options, out bool hasMacros, out string? containerSubtype, out int? entryCount, out IReadOnlyList<string>? topExtensions, out bool hasExecutables, out bool hasScripts, out bool hasNestedArchives,
        out bool hasTraversal, out bool hasSymlinks, out bool hasAbs, out bool hasInstallers, out bool hasRemoteTemplate, out bool hasDde, out bool hasExternalLinks, out int externalLinksCount,
        out bool hasEncryptedEntries, out int encryptedEntryCount, out bool isOoxmlEncrypted, out bool hasDisguisedExecutables, out List<string>? findingsOut, out List<Reference>? referencesOut,
        out int innerExecutablesSampled, out int innerSignedExecutables, out int innerValidSignedExecutables, out Dictionary<string,int>? innerPublisherCounts, out Dictionary<string,int>? innerPublisherValidCounts, out Dictionary<string,int>? innerPublisherSelfCounts, out List<InnerEntryPreview>? previewOut, out Dictionary<string,int>? innerExecExtCounts,
        out bool inspectionComplete, out IReadOnlyList<string>? inspectionIssues) {
        hasMacros = false; containerSubtype = null; entryCount = null; topExtensions = null; hasExecutables = false; hasScripts = false; hasNestedArchives = false; hasTraversal = false; hasSymlinks = false; hasAbs = false; hasInstallers = false; hasRemoteTemplate = false; hasDde = false; hasExternalLinks = false; externalLinksCount = 0; hasEncryptedEntries = false; encryptedEntryCount = 0; isOoxmlEncrypted = false; hasDisguisedExecutables = false; findingsOut = null; referencesOut = null;
        innerExecutablesSampled = 0; innerSignedExecutables = 0; innerValidSignedExecutables = 0; innerPublisherCounts = null; innerPublisherValidCounts = null; innerPublisherSelfCounts = null; previewOut = null; innerExecExtCounts = null;
        inspectionComplete = true; inspectionIssues = null;
        var budget = ArchiveInspectionBudget.FromSettings();
        int nestedDepth = options?.NestedContainerDepth ?? 0;
        long nestedByteBudget = (long)Math.Max(0, OperationSettings.DeepContainerMaxEntries) *
                                Math.Max(0, OperationSettings.DeepContainerMaxEntryBytes);
        var nestedBudget = options?.NestedContainerBudget ??
                           new NestedContainerBudgetState(OperationSettings.DeepContainerMaxEntries, nestedByteBudget);
        try {
            using var fs = OperationReadStream.Open(path);
            if (!budget.CheckCentralDirectory(fs, out var declaredEntryCount))
            {
                entryCount = declaredEntryCount;
                return;
            }
            using var za = new ZipArchive(fs, ZipArchiveMode.Read, leaveOpen: true);
            var exts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            int count = 0;
            hasNestedArchives = false;
            int sampled = 0; int maxSamples = 16; int headSample = 64;
            bool ooxmlRemoteTemplate = false; bool ooxmlDde = false; bool ooxmlExtLinks = false; int extLinksCount = 0;
            int ooxmlAllowed = 0, ooxmlDisallowed = 0, ooxmlUnc = 0;
            var ooxmlHosts = new List<string>(5);
            bool sawEncryptionInfo = false; bool sawEncryptedPackage = false;
            int deepScanned = 0; int deepMax = OperationSettings.DeepContainerMaxEntries;
            int deepBytes = OperationSettings.DeepContainerMaxEntryBytes;
            bool deep = OperationSettings.DeepContainerScanEnabled;
            var localFindings = new List<string>(8);
            var innerPublishers = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
            var innerPublisherValid = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
            var innerPublisherSelf = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
            var aggregateInnerExecExtCounts = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
            var previews = new List<InnerEntryPreview>();
            bool innerScriptEncoded = false, innerScriptExec = false, innerScriptDownload = false, innerExternalHosts = false, innerUnc = false, innerDisguisedScript = false;
            var innerUrlSamples = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var innerUncSamples = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var innerSuspiciousEntries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            // JAR/APK/Vendored package cues
            bool hasManifestMf = false; bool hasClass = false; bool hasJarSig = false;
            bool hasAndroidManifest = false; bool hasDex = false; bool hasApkSig = false;
            foreach (var e in za.Entries) {
                if (!budget.TryVisitEntry()) break;
                if (string.IsNullOrEmpty(e.FullName) || e.FullName.EndsWith("/")) continue;
                count++;
                var name = e.FullName;
                if (name.Equals("EncryptionInfo", StringComparison.OrdinalIgnoreCase)) sawEncryptionInfo = true;
                if (name.Equals("EncryptedPackage", StringComparison.OrdinalIgnoreCase)) sawEncryptedPackage = true;
                if (name.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase)) hasMacros = true;
                var ext = GetExtension(name);
                if (!string.IsNullOrEmpty(ext)) exts[ext] = exts.TryGetValue(ext, out var c) ? c + 1 : 1;
                if (IsExecutableName(name)) hasExecutables = true;
                if (IsScriptName(name)) hasScripts = true;
                if (!hasInstallers && IsInstallerName(name)) hasInstallers = true;

                // JAR/APK cues
                var low = name.ToLowerInvariant();
                if (low == "meta-inf/manifest.mf") hasManifestMf = true;
                if (low.StartsWith("meta-inf/") && (low.EndsWith(".rsa") || low.EndsWith(".dsa"))) { hasJarSig = true; hasApkSig = true; }
                if (low.EndsWith(".class")) hasClass = true;
                if (low == "androidmanifest.xml") hasAndroidManifest = true;
                if (low == "classes.dex") hasDex = true;

                // GPO/SYSVOL indicators within archives
                if (OperationSettings.DeepContainerScanEnabled)
                {
                    var nlow = name.ToLowerInvariant();
                    if (nlow.EndsWith("/gpt.ini") || nlow.EndsWith("\\gpt.ini") || nlow.Contains("/policies/") || nlow.Contains("\\policies\\") || nlow.EndsWith("registry.pol", StringComparison.OrdinalIgnoreCase))
                    {
                        if (!localFindings.Contains("gpo:backup")) localFindings.Add("gpo:backup");
                    }
                    if (nlow.Contains("sysvol") && (nlow.Contains("policies") || nlow.Contains("scripts")))
                    {
                        if (!localFindings.Contains("sysvol:policy")) localFindings.Add("sysvol:policy");
                    }
                }

                // OOXML remote template / DDE cues (Word primary targets)
                try {
                    if (!ooxmlRemoteTemplate && (name.EndsWith("word/_rels/document.xml.rels", StringComparison.OrdinalIgnoreCase) || name.EndsWith("_rels/.rels", StringComparison.OrdinalIgnoreCase)))
                    {
                        var rels = budget.ReadText(e) ?? string.Empty;
                        if (rels.IndexOf("attachedTemplate", StringComparison.OrdinalIgnoreCase) >= 0 && (rels.IndexOf("TargetMode=\"External\"", StringComparison.OrdinalIgnoreCase) >= 0 || rels.IndexOf("http://", StringComparison.OrdinalIgnoreCase) >= 0 || rels.IndexOf("https://", StringComparison.OrdinalIgnoreCase) >= 0 || rels.IndexOf("\\\\", StringComparison.OrdinalIgnoreCase) >= 0))
                            ooxmlRemoteTemplate = true;
                    }
                    if (!ooxmlDde && (name.Equals("word/document.xml", StringComparison.OrdinalIgnoreCase) || name.EndsWith("/document.xml", StringComparison.OrdinalIgnoreCase)))
                    {
                        var docxml = budget.ReadText(e) ?? string.Empty;
                        if (docxml.IndexOf("DDEAUTO", StringComparison.OrdinalIgnoreCase) >= 0 || docxml.IndexOf(" DDE ", StringComparison.OrdinalIgnoreCase) >= 0)
                            ooxmlDde = true;
                    }
                    if (name.StartsWith("xl/externalLinks/", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
                    {
                        ooxmlExtLinks = true; extLinksCount++;
                    }
                    if (name.Equals("xl/_rels/workbook.xml.rels", StringComparison.OrdinalIgnoreCase))
                    {
                        var rels = budget.ReadText(e) ?? string.Empty;
                        // Count targets that point to externalLinks folder
                        int pos = 0; int local = 0; while (true) { int at = rels.IndexOf("externalLinks/", pos, StringComparison.OrdinalIgnoreCase); if (at < 0) break; local++; pos = at + 8; }
                        if (local > 0) { ooxmlExtLinks = true; extLinksCount += local; }
                        // Roughly count external http(s) and UNC targets in workbook relationships
                        CountOoxmlExternalTargets(rels, ref ooxmlAllowed, ref ooxmlDisallowed, ref ooxmlUnc, ooxmlHosts);
                    }
                    if (name.StartsWith("xl/externalLinks/_rels/", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".rels", StringComparison.OrdinalIgnoreCase))
                    {
                        var rels2 = budget.ReadText(e) ?? string.Empty;
                        CountOoxmlExternalTargets(rels2, ref ooxmlAllowed, ref ooxmlDisallowed, ref ooxmlUnc, ooxmlHosts);
                    }
                } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { }

                // Safety preflight: traversal/absolute
                if (ArchivePathSafety.HasTraversal(name)) hasTraversal = true;
                if (ArchivePathSafety.IsAbsolute(name)) hasAbs = true;
                if (!hasAbs && (name.StartsWith("/") || (name.Length >= 3 && char.IsLetter(name[0]) && name[1] == ':' && (name[2] == '/' || name[2] == '\\')))) hasAbs = true;

                // Symlink check (POSIX mode in external attributes high 16 bits: 0120000)
                try {
#if NET8_0_OR_GREATER || NET472
                    int attrs = e.ExternalAttributes;
                    int unixMode = (attrs >> 16) & 0xFFFF;
                    const int IFMT = 0xF000, IFLNK = 0xA000;
                    if ((unixMode & IFMT) == IFLNK) hasSymlinks = true;
#endif
                } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { }

                // Light inner-archive sampler: detect nested archives by magic (bounded by samples and size)
                if (!hasNestedArchives && sampled < maxSamples && e.Length >= 4) {
                    try {
                        using var es = budget.OpenEntry(e, headSample);
                        if (es == null) throw new InvalidDataException("zip:entry-budget");
                        var head = new byte[Math.Min(headSample, (int)Math.Min(e.Length, headSample))];
                        int n = es.Read(head, 0, head.Length);
                        if (n > 0) {
                            var span = new ReadOnlySpan<byte>(head, 0, n);
                            var det = Detect(span, null);
                            if (det != null) {
                                var de = det.Extension?.ToLowerInvariant();
                                if (de is "zip" or "7z" or "rar" or "tar" or "gz" or "bz2" or "xz" or "zst" or "iso" or "udf") {
                                    hasNestedArchives = true;
                                }
                            }
                        }
                    } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { /* ignore per-entry errors */ }
                    sampled++;
                }

                // Deep scan of entries for disguised executables and known tool names (bounded by budgets)
                if (deep && deepScanned < deepMax)
                {
                    try {
                        // Known tool names by filename
                        var lowerName = name.ToLowerInvariant();
                        foreach (var ind in OperationSettings.KnownToolNameIndicators)
                        {
                            if (!string.IsNullOrWhiteSpace(ind) && lowerName.Contains(ind))
                            {
                                localFindings.Add($"tool:{ind}"); break;
                            }
                        }
                        // Content-based disguise check
                        using var es2 = budget.OpenEntry(e, deepBytes);
                        if (es2 == null) throw new InvalidDataException("zip:entry-budget");
                        int cap = (int)Math.Min(Math.Min(e.Length, deepBytes), deepBytes);
                        var buf = new byte[Math.Max(64, cap)];
                        int nn = es2.Read(buf, 0, buf.Length);
                        if (nn > 0)
                        {
                            var det2 = Detect(new ReadOnlySpan<byte>(buf, 0, nn), null);
                            var declExt = GetExtension(name);
                            var looksExe = det2?.Extension is "exe" or "dll" || (nn >= 2 && buf[0] == (byte)'M' && buf[1] == (byte)'Z');
                            var looksInstaller = det2?.Extension is "msi" or "msix" or "appx" or "msixbundle" || IsInstallerName(name);
                            if (looksExe)
                            {
                                // if declared ext does not indicate executable
                                if (!(declExt is "exe" or "dll")) hasDisguisedExecutables = true;
                                hasExecutables = true;
                                if (previews.Count < 10)
                                    previews.Add(new InnerEntryPreview { Name = name, DetectedExtension = det2?.Extension ?? declExt });
                            }
                            // Installer hint by name or magic (best-effort)
                            if (looksInstaller)
                            {
                                hasInstallers = true;
                                var installerPreviewExt = declExt is "msi" or "msix" or "appx" or "msixbundle" or "msu"
                                    ? declExt
                                    : (det2?.Extension ?? declExt);
                                if (previews.Count < 10 && !previews.Any(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)))
                                    previews.Add(new InnerEntryPreview { Name = name, DetectedExtension = installerPreviewExt });
                            }

                            // Optional hash match for known tools (only when entry small enough)
                            if (OperationSettings.KnownToolHashes.Count > 0 && nn > 0 && e.Length <= deepBytes)
                            {
                                try {
                                    byte[] ReadEntryBytesBounded()
                                    {
                                        using var rs = budget.OpenEntry(e, cap);
                                        if (rs == null) throw new InvalidDataException("zip:entry-budget");
                                        using var ms = new System.IO.MemoryStream();
                                        int left = cap;
                                        var tmpbuf = new byte[8192];
                                        while (left > 0)
                                        {
                                            int r2 = rs.Read(tmpbuf, 0, Math.Min(tmpbuf.Length, left));
                                            if (r2 <= 0) break;
                                            ms.Write(tmpbuf, 0, r2);
                                            left -= r2;
                                        }
                                        return ms.ToArray();
                                    }

                                    using var sha = System.Security.Cryptography.SHA256.Create();
                                    var hashBytes = ReadEntryBytesBounded();
                                    if (hashBytes.Length == 0) throw new InvalidDataException("zip:empty-entry");
                                    var hash = sha.ComputeHash(hashBytes);
                                    var hex = ToLowerHex(hash);
                                    foreach (var kv in OperationSettings.KnownToolHashes)
                                    {
                                        if (string.Equals(kv.Value, hex, StringComparison.OrdinalIgnoreCase)) { localFindings.Add($"toolhash:{kv.Key}"); break; }
                                    }
                                } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { }
                            }
                            // Inner signer sampling for executables
                            if (looksExe && e.Length > 0 && e.Length <= deepBytes)
                            {
                                string? tmp = null;
                                try
                                {
                                    tmp = System.IO.Path.GetTempFileName();
                                    byte[] entryBytes;
                                    using (var rs = budget.OpenEntry(e, cap))
                                    using (var ms = new System.IO.MemoryStream())
                                    {
                                        if (rs == null) throw new InvalidDataException("zip:entry-budget");
                                        int left = cap;
                                        var tmpbuf = new byte[8192];
                                        while (left > 0)
                                        {
                                            int r2 = rs.Read(tmpbuf, 0, Math.Min(tmpbuf.Length, left));
                                            if (r2 <= 0) break;
                                            ms.Write(tmpbuf, 0, r2);
                                            left -= r2;
                                        }
                                        entryBytes = ms.ToArray();
                                    }
                                    if (entryBytes.Length == 0) throw new InvalidDataException("zip:empty-entry");
                                    using (var fsout = System.IO.File.Create(tmp))
                                    {
                                        fsout.Write(entryBytes, 0, entryBytes.Length);
                                    }
                                    var ia = FileInspector.Analyze(tmp,
                                        CreateInnerAnalysisOptions(options, nestedBudget, nestedDepth, includeContainer: false));
                                    innerExecutablesSampled++;
                                    if (ia?.Authenticode?.Present == true)
                                    {
                                        innerSignedExecutables++;
                                        bool v = GetSignatureStatus(ia)?.IsValid == true;
                                        if (v) innerValidSignedExecutables++;
                                        var pub = ia.Authenticode.SignerSubjectCN ?? ia.Authenticode.SignerSubject ?? "<unknown>";
                                        if (innerPublishers.TryGetValue(pub, out var pc)) innerPublishers[pub] = pc + 1; else innerPublishers[pub] = 1;
                                        if (v) { if (innerPublisherValid.TryGetValue(pub, out var pv)) innerPublisherValid[pub] = pv + 1; else innerPublisherValid[pub] = 1; }
                                        if (ia.Authenticode.IsSelfSigned == true) { if (innerPublisherSelf.TryGetValue(pub, out var ps)) innerPublisherSelf[pub] = ps + 1; else innerPublisherSelf[pub] = 1; }
                                    }
                                } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { }
                                finally { if (!string.IsNullOrEmpty(tmp)) { try { System.IO.File.Delete(tmp); } catch { } } }
                            }
                            else if (e.Length > 0 && e.Length <= deepBytes && ShouldDeepAnalyzeArchiveInnerTextEntry(name, declExt, det2?.Extension))
                            {
                                string? tmp = null;
                                try
                                {
                                    tmp = System.IO.Path.GetTempFileName();
                                    using (var rs = budget.OpenEntry(e, cap))
                                    using (var outFs = System.IO.File.Create(tmp))
                                    {
                                        if (rs == null) throw new InvalidDataException("zip:entry-budget");
                                        int left = cap;
                                        var tmpbuf = new byte[8192];
                                        while (left > 0)
                                        {
                                            int r2 = rs.Read(tmpbuf, 0, Math.Min(tmpbuf.Length, left));
                                            if (r2 <= 0) break;
                                            outFs.Write(tmpbuf, 0, r2);
                                            left -= r2;
                                        }
                                    }

                                    var ia = FileInspector.Analyze(tmp,
                                        CreateInnerAnalysisOptions(options, nestedBudget, nestedDepth, includeContainer: false));
                                    if (CollectArchiveInnerSignals(
                                        name,
                                        ia,
                                        innerUrlSamples,
                                        innerUncSamples,
                                        innerSuspiciousEntries,
                                        ref innerScriptEncoded,
                                        ref innerScriptExec,
                                        ref innerScriptDownload,
                                        ref innerExternalHosts,
                                        ref innerUnc,
                                        ref innerDisguisedScript) && previews.Count < 10)
                                    {
                                        previews.Add(new InnerEntryPreview
                                        {
                                            Name = name,
                                            DetectedExtension = ia?.DetectedExtension ?? ia?.Detection?.Extension ?? det2?.Extension ?? declExt
                                        });
                                    }
                                } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { }
                                finally { if (!string.IsNullOrEmpty(tmp)) { try { System.IO.File.Delete(tmp); } catch { } } }
                            }
                            else if (nestedDepth < Math.Max(0, OperationSettings.DeepContainerMaxDepth) &&
                                     e.Length > 0 && e.Length <= GetNestedArchiveDeepScanBytes() &&
                                     ShouldDeepAnalyzeNestedArchiveEntry(name, declExt, det2?.Extension))
                            {
                                string? tmp = null;
                                try
                                {
                                    int nestedCap = (int)Math.Min(e.Length, GetNestedArchiveDeepScanBytes());
                                    if (!nestedBudget.TryConsume(nestedCap)) throw new InvalidDataException("zip:nested-budget");
                                    tmp = System.IO.Path.GetTempFileName();
                                    using (var rs = budget.OpenEntry(e, nestedCap))
                                    using (var outFs = System.IO.File.Create(tmp))
                                    {
                                        if (rs == null) throw new InvalidDataException("zip:entry-budget");
                                        int left = nestedCap;
                                        var tmpbuf = new byte[8192];
                                        while (left > 0)
                                        {
                                            int r2 = rs.Read(tmpbuf, 0, Math.Min(tmpbuf.Length, left));
                                            if (r2 <= 0) break;
                                            outFs.Write(tmpbuf, 0, r2);
                                            left -= r2;
                                        }
                                    }

                                    var ia = FileInspector.Analyze(tmp,
                                        CreateInnerAnalysisOptions(options, nestedBudget, nestedDepth + 1, includeContainer: true));
                                    MergeNestedArchiveContainerSignals(
                                        name,
                                        ia,
                                        ref hasExecutables,
                                        ref hasScripts,
                                        ref hasInstallers,
                                        ref innerExecutablesSampled,
                                        ref innerSignedExecutables,
                                        ref innerValidSignedExecutables,
                                        innerPublishers,
                                        innerPublisherValid,
                                        innerPublisherSelf,
                                        aggregateInnerExecExtCounts,
                                        previews);
                                    if (CollectArchiveInnerSignals(
                                        name,
                                        ia,
                                        innerUrlSamples,
                                        innerUncSamples,
                                        innerSuspiciousEntries,
                                        ref innerScriptEncoded,
                                        ref innerScriptExec,
                                        ref innerScriptDownload,
                                        ref innerExternalHosts,
                                        ref innerUnc,
                                        ref innerDisguisedScript) && previews.Count < 10)
                                    {
                                        previews.Add(new InnerEntryPreview
                                        {
                                            Name = name,
                                            DetectedExtension = ia?.DetectedExtension ?? ia?.Detection?.Extension ?? det2?.Extension ?? declExt
                                        });
                                    }
                                } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { }
                                finally { if (!string.IsNullOrEmpty(tmp)) { try { System.IO.File.Delete(tmp); } catch { } } }
                            }
                        }
                    } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { }
                    deepScanned++;
                }
            }
            entryCount = count;
            topExtensions = exts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).Take(5).Select(kv => kv.Key).ToArray();
            // Export counts for executable extensions (by names)
            try {
                var execExts = new [] { "exe","dll","msi","sys","com","scr","cpl" };
                foreach (var k in execExts) { if (exts.TryGetValue(k, out var c) && c > 0) aggregateInnerExecExtCounts[k] = aggregateInnerExecExtCounts.TryGetValue(k, out var existing) ? existing + c : c; }
                if (aggregateInnerExecExtCounts.Count > 0) innerExecExtCounts = new Dictionary<string,int>(aggregateInnerExecExtCounts, StringComparer.OrdinalIgnoreCase);
            } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { }
            var guess = GuessZipSubtype(za, budget, out var _, visitEntries: false);
            containerSubtype = guess;
            // Refine subtype based on cues collected
            if (containerSubtype == null)
            {
                if (hasManifestMf && hasClass) containerSubtype = "jar";
                if (hasAndroidManifest && hasDex) containerSubtype = "apk";
            }
            // Signed JAR/APK hints
            if (containerSubtype == "jar" && hasJarSig)
            {
                if (!localFindings.Contains("jar:signed")) localFindings.Add("jar:signed");
            }
            if (containerSubtype == "apk" && hasApkSig)
            {
                if (!localFindings.Contains("apk:signed")) localFindings.Add("apk:signed");
            }
            if (hasNestedArchives && containerSubtype == null) containerSubtype = "nested-archive";
            hasRemoteTemplate = ooxmlRemoteTemplate;
            hasDde = ooxmlDde;
            hasExternalLinks = ooxmlExtLinks;
            externalLinksCount = extLinksCount;
            if (innerScriptEncoded && !localFindings.Contains("archive:inner-script-encoded")) localFindings.Add("archive:inner-script-encoded");
            if (innerScriptExec && !localFindings.Contains("archive:inner-script-exec")) localFindings.Add("archive:inner-script-exec");
            if (innerScriptDownload && !localFindings.Contains("archive:inner-script-download")) localFindings.Add("archive:inner-script-download");
            if (innerExternalHosts && !localFindings.Contains("archive:inner-external-hosts")) localFindings.Add("archive:inner-external-hosts");
            if (innerUnc && !localFindings.Contains("archive:inner-unc")) localFindings.Add("archive:inner-unc");
            if (innerDisguisedScript && !localFindings.Contains("archive:inner-disguised-script")) localFindings.Add("archive:inner-disguised-script");
            if (innerSuspiciousEntries.Count > 0) localFindings.Add("archive:inner-files=" + string.Join(", ", innerSuspiciousEntries.Take(3)));
            if (innerUrlSamples.Count > 0) localFindings.Add("archive:inner-urls=" + string.Join(", ", innerUrlSamples.Take(3)));
            if (innerUncSamples.Count > 0) localFindings.Add("archive:inner-unc-samples=" + string.Join(", ", innerUncSamples.Take(2)));
            if (innerUrlSamples.Count > 0 || innerUncSamples.Count > 0)
            {
                var refs = new List<Reference>(innerUrlSamples.Count + innerUncSamples.Count);
                foreach (var url in innerUrlSamples.Take(5))
                {
                    refs.Add(new Reference { Kind = ReferenceKind.Url, Value = url, SourceTag = "archive:inner" });
                }
                foreach (var unc in innerUncSamples.Take(3))
                {
                    refs.Add(new Reference { Kind = ReferenceKind.FilePath, Value = unc, Issues = ReferenceIssue.UncPath, SourceTag = "archive:inner" });
                }
                referencesOut = refs;
            }
            // Attach OOXML external link markers
            if (ooxmlExtLinks)
            {
                if (!localFindings.Contains($"ooxml:ext-links={extLinksCount}")) localFindings.Add($"ooxml:ext-links={extLinksCount}");
                if (ooxmlAllowed > 0 && !localFindings.Contains($"ooxml:ext-allowed={ooxmlAllowed}")) localFindings.Add($"ooxml:ext-allowed={ooxmlAllowed}");
                if (ooxmlDisallowed > 0 && !localFindings.Contains($"ooxml:ext-disallowed={ooxmlDisallowed}")) localFindings.Add($"ooxml:ext-disallowed={ooxmlDisallowed}");
                if (ooxmlUnc > 0 && !localFindings.Contains($"ooxml:unc={ooxmlUnc}")) localFindings.Add($"ooxml:unc={ooxmlUnc}");
                if (ooxmlHosts.Count > 0)
                {
                    var top = ooxmlHosts.Take(3);
                    var joined = string.Join(",", top);
                    if (!localFindings.Any(x => x.StartsWith("ooxml:hosts=", StringComparison.OrdinalIgnoreCase)))
                        localFindings.Add($"ooxml:hosts={joined}");
                }
            }
            // Check encryption flags and count by scanning central directory
            int encCount = ZipEncryptedEntryCount(fs);
            if (encCount > 0) { hasEncryptedEntries = true; encryptedEntryCount = encCount; }
            // OOXML encrypted packages present these two entries at root
            isOoxmlEncrypted = sawEncryptionInfo && sawEncryptedPackage;
            if (!budget.IsComplete)
                localFindings.AddRange(budget.Issues.Where(issue => !localFindings.Contains(issue)));
            findingsOut = localFindings.Count > 0 ? localFindings : null;
            if (innerExecutablesSampled > 0)
            {
                innerPublisherCounts = innerPublishers.Count > 0 ? new Dictionary<string,int>(innerPublishers) : null;
                innerPublisherValidCounts = innerPublisherValid.Count > 0 ? new Dictionary<string,int>(innerPublisherValid) : null;
                innerPublisherSelfCounts = innerPublisherSelf.Count > 0 ? new Dictionary<string,int>(innerPublisherSelf) : null;
            }
            if (previews.Count > 0) previewOut = previews;
            // Attach inner findings via the caller's FileAnalysis when available (handled by Analyze caller)
        } catch (OutOfMemoryException) { throw; }
        catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { budget.AddIssue("archive:inspection-error"); }
        finally
        {
            inspectionComplete = budget.IsComplete;
            inspectionIssues = budget.IsComplete ? null : budget.Issues;
        }
    }

    private static bool ZipCentralDirectoryHasEncryptedEntries(Stream fs)
    {
        try {
            if (!fs.CanSeek || fs.Length < 22) return false;
            long maxScan = Math.Min(fs.Length, 1 << 16); // EOCD must be within last 64KB
            var buf = new byte[maxScan];
            fs.Seek(fs.Length - maxScan, SeekOrigin.Begin);
            int n = fs.Read(buf, 0, buf.Length);
            if (n <= 0) return false;
            int eocdSig = 0x06054b50;
            int cdSig = 0x02014b50;
            for (int i = n - 22; i >= 0; i--)
            {
                if (ReadLe32(buf, i) == eocdSig)
                {
                    int entries = ReadLe16(buf, i + 10);
                    int cdOffset = ReadLe32(buf, i + 16);
                    // Seek to central directory and scan flags per entry
                    long abs = cdOffset;
                    if (abs < 0 || abs >= fs.Length) break;
                    long remain = fs.Length - abs;
                    fs.Seek(abs, SeekOrigin.Begin);
                    var cdbuf = new byte[Math.Min(remain, 1 << 20)];
                    int m = fs.Read(cdbuf, 0, cdbuf.Length);
                    int p = 0; int scanned = 0;
                    while (p + 46 <= m && scanned < entries)
                    {
                        if (ReadLe32(cdbuf, p) != cdSig) break;
                        int flags = ReadLe16(cdbuf, p + 8);
                        if ((flags & 0x1) != 0) return true; // encrypted
                        int fnLen = ReadLe16(cdbuf, p + 28);
                        int exLen = ReadLe16(cdbuf, p + 30);
                        int cmLen = ReadLe16(cdbuf, p + 32);
                        // Extra field scan for AES (0x9901)
                        if (exLen > 4 && p + 46 + fnLen + exLen <= m)
                        {
                            int exOff = p + 46 + fnLen; int exEnd = exOff + exLen;
                            int q = exOff;
                            while (q + 4 <= exEnd)
                            {
                                int headerId = ReadLe16(cdbuf, q);
                                int dataSize = ReadLe16(cdbuf, q + 2);
                                q += 4;
                                if (headerId == 0x9901) return true; // AES extra field
                                q += dataSize;
                            }
                        }
                        p += 46 + fnLen + exLen + cmLen;
                        scanned++;
                    }
                    break;
                }
            }
        } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { }
        return false;
    }

    private static int ZipEncryptedEntryCount(Stream fs)
    {
        int count = 0;
        try {
            if (!fs.CanSeek || fs.Length < 22) return 0;
            long maxScan = Math.Min(fs.Length, 1 << 16);
            var buf = new byte[maxScan];
            fs.Seek(fs.Length - maxScan, SeekOrigin.Begin);
            int n = fs.Read(buf, 0, buf.Length);
            if (n <= 0) return 0;
            int eocdSig = 0x06054b50;
            int cdSig = 0x02014b50;
            for (int i = n - 22; i >= 0; i--)
            {
                if (ReadLe32(buf, i) == eocdSig)
                {
                    int entries = ReadLe16(buf, i + 10);
                    int cdOffset = ReadLe32(buf, i + 16);
                    long abs = cdOffset;
                    if (abs < 0 || abs >= fs.Length) break;
                    long remain = fs.Length - abs;
                    fs.Seek(abs, SeekOrigin.Begin);
                    var cdbuf = new byte[Math.Min(remain, 1 << 20)];
                    int m = fs.Read(cdbuf, 0, cdbuf.Length);
                    int p = 0; int scanned = 0;
                    while (p + 46 <= m && scanned < entries)
                    {
                        if (ReadLe32(cdbuf, p) != cdSig) break;
                        int flags = ReadLe16(cdbuf, p + 8);
                        bool encrypted = (flags & 0x1) != 0;
                        int fnLen = ReadLe16(cdbuf, p + 28);
                        int exLen = ReadLe16(cdbuf, p + 30);
                        int cmLen = ReadLe16(cdbuf, p + 32);
                        if (!encrypted && exLen > 4 && p + 46 + fnLen + exLen <= m)
                        {
                            int exOff = p + 46 + fnLen; int exEnd = exOff + exLen;
                            int q = exOff;
                            while (q + 4 <= exEnd)
                            {
                                int headerId = ReadLe16(cdbuf, q);
                                int dataSize = ReadLe16(cdbuf, q + 2);
                                q += 4;
                                if (headerId == 0x9901) { encrypted = true; break; }
                                q += dataSize;
                            }
                        }
                        if (encrypted) count++;
                        p += 46 + fnLen + exLen + cmLen;
                        scanned++;
                    }
                    break;
                }
            }
        } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { }
        return count;
    }

    private static int ReadLe16(byte[] a, int o) => a[o] | (a[o+1] << 8);
    private static int ReadLe32(byte[] a, int o) => a[o] | (a[o+1] << 8) | (a[o+2] << 16) | (a[o+3] << 24);

}
