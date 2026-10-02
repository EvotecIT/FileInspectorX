using System.IO.Compression;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace FileInspectorX;

public static partial class FileInspector
{
    private static IReadOnlyList<Reference>? MergeReferences(IReadOnlyList<Reference>? primary, IReadOnlyList<Reference>? secondary)
    {
        if ((primary?.Count ?? 0) == 0) return secondary;
        if ((secondary?.Count ?? 0) == 0) return primary;

        var merged = new List<Reference>(primary!.Count + secondary!.Count);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(IReadOnlyList<Reference> refs)
        {
            foreach (var reference in refs)
            {
                if (reference == null || string.IsNullOrWhiteSpace(reference.Value))
                {
                    continue;
                }

                var key = $"{reference.Kind}|{reference.SourceTag}|{reference.Value}|{reference.ExpandedValue}|{reference.Issues}";
                if (!seen.Add(key))
                {
                    continue;
                }

                merged.Add(reference);
            }
        }

        Add(primary);
        Add(secondary);
        return merged;
    }

    private static bool ShouldDeepAnalyzeArchiveInnerTextEntry(string name, string? declaredExtension, string? detectedExtension)
    {
        if (IsScriptName(name)) return true;

        var declared = (declaredExtension ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();
        var detected = (detectedExtension ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();

        return declared is "txt" or "log" or "xml" or "html" or "htm" or "json" or "yml" or "yaml" or "ini" or "cfg" or "config" or "ps1" or "psm1" or "psd1" or "bat" or "cmd" or "js" or "mjs" or "vbs" or "py" or "rb" or "lua"
            || detected is "txt" or "log" or "xml" or "html" or "htm" or "json" or "ps1" or "psm1" or "psd1" or "bat" or "cmd" or "js" or "mjs" or "vbs" or "py" or "rb" or "lua";
    }

    private static bool ShouldDeepAnalyzeNestedArchiveEntry(string name, string? declaredExtension, string? detectedExtension)
    {
        if (IsArchiveLikeExtension(GetExtension(name))) return true;

        var declared = (declaredExtension ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();
        var detected = (detectedExtension ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();
        return IsArchiveLikeExtension(declared) || IsArchiveLikeExtension(detected);
    }

    private static int GetNestedArchiveDeepScanBytes()
        => Math.Max(0, OperationSettings.DeepContainerMaxNestedArchiveBytes);

    private static DetectionOptions CreateInnerAnalysisOptions(DetectionOptions? source,
        NestedContainerBudgetState nestedBudget, int nestedDepth, bool includeContainer)
    {
        return new DetectionOptions
        {
            Settings = source?.Settings,
            CancellationToken = source?.CancellationToken ?? default,
            ComputeSha256 = source?.ComputeSha256 ?? false,
            MagicHeaderBytes = source?.MagicHeaderBytes ?? 0,
            DetectOnly = false,
            IncludeContainer = includeContainer && (source?.IncludeContainer ?? true),
            IncludePermissions = source?.IncludePermissions ?? true,
            IncludeAuthenticode = source?.IncludeAuthenticode ?? true,
            IncludeReferences = source?.IncludeReferences ?? true,
            IncludeInstaller = source?.IncludeInstaller ?? false,
            IncludeAssessment = source?.IncludeAssessment ?? true,
            IncludeShellProperties = source?.IncludeShellProperties ?? false,
            LearnedClassifier = source?.LearnedClassifier,
            LearnedClassificationMode = source?.LearnedClassificationMode ?? LearnedClassificationMode.Off,
            NestedContainerDepth = nestedDepth,
            NestedContainerBudget = nestedBudget
        };
    }

    private static bool CollectArchiveInnerSignals(
        string entryName,
        FileAnalysis? inner,
        HashSet<string> innerUrlSamples,
        HashSet<string> innerUncSamples,
        HashSet<string> innerSuspiciousEntries,
        ref bool innerScriptEncoded,
        ref bool innerScriptExec,
        ref bool innerScriptDownload,
        ref bool innerExternalHosts,
        ref bool innerUnc,
        ref bool innerDisguisedScript)
    {
        if (inner == null) return false;

        var detectedExt = (inner.DetectedExtension ?? inner.Detection?.Extension ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();
        bool detectedScript = IsScriptLikeExtension(detectedExt);
        bool namedScript = IsScriptName(entryName);
        bool hasPromotableUncReference = (inner.References ?? Array.Empty<Reference>()).Any(reference =>
            reference.Kind == ReferenceKind.FilePath &&
            (reference.Issues & ReferenceIssue.UncPath) != 0 &&
            !string.IsNullOrWhiteSpace(reference.Value) &&
            ShouldPromoteArchiveInnerUncReference(reference));
        bool suspicious = false;

        if (detectedScript && !namedScript)
        {
            innerDisguisedScript = true;
            suspicious = true;
        }

        foreach (var finding in inner.SecurityFindings ?? Array.Empty<string>())
        {
            switch (finding)
            {
                case "ps:encoded":
                case "archive:inner-script-encoded":
                    innerScriptEncoded = true;
                    suspicious = true;
                    break;
                case "ps:iex":
                case "ps:reflection":
                case "py:exec-b64":
                case "py:exec":
                case "rb:eval":
                case "lua:exec":
                case "archive:inner-script-exec":
                    innerScriptExec = true;
                    suspicious = true;
                    break;
                case "ps:web-dl":
                case "bat:certutil":
                case "js:mshta":
                case "js:activex":
                case "archive:inner-script-download":
                    innerScriptDownload = true;
                    suspicious = true;
                    break;
                case var n when n != null && n.StartsWith("net:hosts-ext=", StringComparison.OrdinalIgnoreCase):
                case "archive:inner-external-hosts":
                    innerExternalHosts = true;
                    suspicious = true;
                    break;
                case var n when n != null && n.StartsWith("net:unc=", StringComparison.OrdinalIgnoreCase):
                case "archive:inner-unc":
                    if (hasPromotableUncReference)
                    {
                        innerUnc = true;
                        suspicious = true;
                    }
                    break;
                case "archive:inner-disguised-script":
                    innerDisguisedScript = true;
                    suspicious = true;
                    break;
            }
        }

        foreach (var reference in inner.References ?? Array.Empty<Reference>())
        {
            if (reference.Kind == ReferenceKind.Url && !string.IsNullOrWhiteSpace(reference.Value))
            {
                innerUrlSamples.Add(reference.Value);
                suspicious = true;
            }
            else if (reference.Kind == ReferenceKind.FilePath &&
                     (reference.Issues & ReferenceIssue.UncPath) != 0 &&
                     !string.IsNullOrWhiteSpace(reference.Value) &&
                     ShouldPromoteArchiveInnerUncReference(reference))
            {
                innerUncSamples.Add(reference.Value);
                innerUnc = true;
                suspicious = true;
            }
        }

        if (suspicious)
        {
            innerSuspiciousEntries.Add(BuildArchiveInnerEntryLabel(entryName, detectedExt));
        }

        return suspicious;
    }

    private static bool ShouldPromoteArchiveInnerUncReference(Reference reference)
    {
        var sourceTag = (reference.SourceTag ?? string.Empty).Trim();
        if (string.IsNullOrEmpty(sourceTag))
        {
            return false;
        }

        return sourceTag.StartsWith("script:", StringComparison.OrdinalIgnoreCase)
            || sourceTag.StartsWith("log:", StringComparison.OrdinalIgnoreCase)
            || sourceTag.StartsWith("html:", StringComparison.OrdinalIgnoreCase)
            || sourceTag.StartsWith("task:", StringComparison.OrdinalIgnoreCase)
            || sourceTag.StartsWith("gpo:", StringComparison.OrdinalIgnoreCase)
            || sourceTag.StartsWith("lnk:", StringComparison.OrdinalIgnoreCase)
            || sourceTag.StartsWith("archive:inner", StringComparison.OrdinalIgnoreCase);
    }

    private static void MergeNestedArchiveContainerSignals(
        string entryName,
        FileAnalysis? nested,
        ref bool hasExecutables,
        ref bool hasScripts,
        ref bool hasInstallers,
        ref int innerExecutablesSampled,
        ref int innerSignedExecutables,
        ref int innerValidSignedExecutables,
        Dictionary<string,int> innerPublishers,
        Dictionary<string,int> innerPublisherValid,
        Dictionary<string,int> innerPublisherSelf,
        Dictionary<string,int> aggregateInnerExecExtCounts,
        List<InnerEntryPreview> previews)
    {
        if (nested == null)
        {
            return;
        }

        if ((nested.Flags & ContentFlags.ContainerContainsExecutables) != 0 || (nested.InnerExecutablesSampled ?? 0) > 0)
        {
            hasExecutables = true;
        }

        if ((nested.Flags & ContentFlags.ContainerContainsScripts) != 0 ||
            (nested.SecurityFindings?.Any(f =>
                string.Equals(f, "archive:inner-script-encoded", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(f, "archive:inner-script-exec", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(f, "archive:inner-script-download", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(f, "archive:inner-disguised-script", StringComparison.OrdinalIgnoreCase)) ?? false))
        {
            hasScripts = true;
        }

        if ((nested.Flags & ContentFlags.ContainerContainsInstallers) != 0)
        {
            hasInstallers = true;
        }

        innerExecutablesSampled += nested.InnerExecutablesSampled ?? 0;
        innerSignedExecutables += nested.InnerSignedExecutables ?? 0;
        innerValidSignedExecutables += nested.InnerValidSignedExecutables ?? 0;

        MergeCounts(innerPublishers, nested.InnerPublisherCounts);
        MergeCounts(innerPublisherValid, nested.InnerPublisherValidCounts);
        MergeCounts(innerPublisherSelf, nested.InnerPublisherSelfSignedCounts);
        MergeCounts(aggregateInnerExecExtCounts, nested.InnerExecutableExtCounts);

        if (nested.ArchivePreviewEntries != null)
        {
            foreach (var preview in nested.ArchivePreviewEntries)
            {
                if (preview == null || string.IsNullOrWhiteSpace(preview.Name) || previews.Count >= 10)
                {
                    continue;
                }

                var name = entryName.Replace('\\', '/') + " > " + preview.Name.Replace('\\', '/');
                if (previews.Any(existing =>
                        string.Equals(existing.Name, name, StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(existing.DetectedExtension, preview.DetectedExtension, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                previews.Add(new InnerEntryPreview
                {
                    Name = name,
                    DetectedExtension = preview.DetectedExtension
                });
            }
        }
    }

    private static void MergeCounts(Dictionary<string,int> target, IReadOnlyDictionary<string,int>? source)
    {
        if (source == null || source.Count == 0)
        {
            return;
        }

        foreach (var kv in source)
        {
            if (string.IsNullOrWhiteSpace(kv.Key) || kv.Value <= 0)
            {
                continue;
            }

            target[kv.Key] = target.TryGetValue(kv.Key, out var existing) ? existing + kv.Value : kv.Value;
        }
    }

    private static string BuildArchiveInnerEntryLabel(string entryName, string? detectedExtension)
    {
        var shortName = string.IsNullOrWhiteSpace(entryName) ? "<entry>" : entryName.Replace('\\', '/');
        var ext = (detectedExtension ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();
        return string.IsNullOrWhiteSpace(ext) ? shortName : $"{shortName} ({ext})";
    }

    private static bool IsScriptLikeExtension(string? extension)
        => MapScriptLanguageFromExtension(extension) != null;

    private static bool IsArchiveLikeExtension(string? extension)
    {
        var ext = (extension ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();
        return ext is "zip" or "7z" or "rar" or "tar" or "gz" or "bz2" or "xz" or "zst" or "iso" or "udf" or "jar" or "apk";
    }

}
