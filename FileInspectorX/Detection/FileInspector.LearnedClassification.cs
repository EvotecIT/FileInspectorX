namespace FileInspectorX;

public static partial class FileInspector
{
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<
        ILearnedContentClassifier,
        object> LearnedClassifierLocks = new();

    private static DetectionOptions WithoutLearnedClassification(DetectionOptions options)
        => new()
        {
            ComputeSha256 = options.ComputeSha256,
            MagicHeaderBytes = options.MagicHeaderBytes,
            DetectOnly = options.DetectOnly,
            IncludeContainer = options.IncludeContainer,
            IncludePermissions = options.IncludePermissions,
            IncludeAuthenticode = options.IncludeAuthenticode,
            IncludeReferences = options.IncludeReferences,
            IncludeInstaller = options.IncludeInstaller,
            IncludeAssessment = options.IncludeAssessment,
            IncludeShellProperties = options.IncludeShellProperties,
            LearnedClassificationMode = LearnedClassificationMode.Off,
            LearnedClassifier = null
        };

    private static ContentTypeDetectionResult? ApplyLearnedClassification(
        ContentTypeDetectionResult? deterministic,
        Stream content,
        DetectionOptions options)
    {
        var classifier = options.LearnedClassifier;
        return ApplyLearnedClassificationCore(
            deterministic,
            options,
            classifier,
            () => classifier!.Predict(content));
    }

    private static ContentTypeDetectionResult? ApplyLearnedClassification(
        ContentTypeDetectionResult? deterministic,
        ReadOnlyMemory<byte> content,
        DetectionOptions options)
    {
        var classifier = options.LearnedClassifier;
        return ApplyLearnedClassificationCore(
            deterministic,
            options,
            classifier,
            () => classifier!.Predict(content));
    }

    private static ContentTypeDetectionResult? ApplyLearnedClassificationFromPath(
        ContentTypeDetectionResult? deterministic,
        string path,
        DetectionOptions options)
    {
        if (options.LearnedClassificationMode == LearnedClassificationMode.Off)
            return deterministic;

        try
        {
            using var content = OpenReadShared(path);
            return ApplyLearnedClassification(deterministic, content, options);
        }
        catch (OutOfMemoryException)
        {
            throw;
        }
        catch (LearnedClassificationException ex)
        {
            if (options.LearnedClassificationMode == LearnedClassificationMode.Required)
                throw;
            return AttachLearnedFailure(deterministic, ex);
        }
        catch (Exception ex)
        {
            if (options.LearnedClassificationMode == LearnedClassificationMode.Required)
            {
                throw new LearnedClassificationException(
                    "The required learned content classifier could not read the file.", ex);
            }
            return AttachLearnedFailure(deterministic, ex);
        }
    }

    private static ContentTypeDetectionResult? ApplyLearnedClassificationCore(
        ContentTypeDetectionResult? deterministic,
        DetectionOptions options,
        ILearnedContentClassifier? classifier,
        Func<LearnedContentPrediction> predict)
    {
        if (options.LearnedClassificationMode == LearnedClassificationMode.Off)
            return deterministic;

        if (classifier is null)
        {
            var missing = new InvalidOperationException(
                "Learned classification was enabled without an ILearnedContentClassifier.");
            if (options.LearnedClassificationMode == LearnedClassificationMode.Required)
                throw new LearnedClassificationException(missing.Message, missing);
            return AttachLearnedFailure(deterministic, missing);
        }

        try
        {
            var prediction = InvokeLearnedClassifier(classifier, predict);
            return ArbitrateLearnedPrediction(deterministic, prediction);
        }
        catch (LearnedClassificationException ex)
        {
            if (options.LearnedClassificationMode == LearnedClassificationMode.Required)
                throw;
            return AttachLearnedFailure(deterministic, ex);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            if (options.LearnedClassificationMode == LearnedClassificationMode.Required)
                throw new LearnedClassificationException(
                    "The required learned content classifier failed.", ex);
            return AttachLearnedFailure(deterministic, ex);
        }
    }

    private static LearnedContentPrediction InvokeLearnedClassifier(
        ILearnedContentClassifier classifier,
        Func<LearnedContentPrediction> predict)
    {
        if (classifier is IConcurrentLearnedContentClassifier)
            return predict();

        var syncRoot = LearnedClassifierLocks.GetValue(classifier, static _ => new object());
        lock (syncRoot)
            return predict();
    }

    private static ContentTypeDetectionResult AttachLearnedFailure(
        ContentTypeDetectionResult? deterministic,
        Exception exception)
    {
        var result = deterministic ?? CreateUnknownDetection();
        result.LearnedClassification = new LearnedClassificationEvidence
        {
            Disposition = LearnedClassificationDisposition.Failed,
            DeterministicExtension = EmptyToNull(result.Extension),
            DeterministicMimeType = EmptyToNull(result.MimeType),
            DeterministicConfidence = EmptyToNull(result.Confidence),
            DeterministicReason = EmptyToNull(result.Reason),
            Message = "provider-failed:" + exception.GetType().Name
        };
        return result;
    }

    private static ContentTypeDetectionResult ArbitrateLearnedPrediction(
        ContentTypeDetectionResult? deterministic,
        LearnedContentPrediction prediction)
    {
        if (prediction is null)
            throw new InvalidOperationException("The learned classifier returned no prediction.");

        var result = deterministic ?? CreateUnknownDetection();
        var deterministicExtension = EmptyToNull(result.Extension);
        var deterministicMime = EmptyToNull(result.MimeType);
        var deterministicConfidence = EmptyToNull(result.Confidence);
        var deterministicReason = EmptyToNull(result.Reason);
        var deterministicPrimary = CreateCandidate(result);
        var deterministicCandidates = result.Candidates;
        var deterministicAlternatives = result.Alternatives;
        var learnedExtension = NormalizeExtension(prediction.Extension);
        var learnedAgreementExtensions = GetLearnedAgreementExtensions(prediction, learnedExtension);
        var agreementExtension = FindDeterministicAgreementExtension(result, learnedAgreementExtensions);
        var learnedIsGeneric = prediction.OutputLabel.Equals("unknown", StringComparison.OrdinalIgnoreCase) ||
                               prediction.OutputLabel.Equals("txt", StringComparison.OrdinalIgnoreCase);

        LearnedClassificationDisposition disposition;
        string? message = null;

        if (!string.IsNullOrWhiteSpace(agreementExtension))
        {
            disposition = LearnedClassificationDisposition.Agreed;
        }
        else if (CanLearnedPredictionFill(result) &&
                 !learnedIsGeneric &&
                 !string.IsNullOrWhiteSpace(learnedExtension))
        {
            result.Extension = learnedExtension!;
            result.MimeType = ResolveLearnedMimeType(
                prediction.MimeType,
                learnedExtension!,
                prediction.IsText ? deterministicMime : null);
            result.Confidence = LearnedConfidence(prediction.Probability);
            result.Score = null;
            result.Reason = "learned:" + prediction.Provider.ToLowerInvariant() + ":" + prediction.OutputLabel;
            result.ReasonDetails = "model:" + prediction.ModelId;
            result.IsDangerous = DangerousExtensions.IsDangerous(result.Extension);
            AlignCandidatesAfterLearnedPromotion(
                result,
                deterministicPrimary,
                deterministicCandidates,
                deterministicAlternatives);
            disposition = LearnedClassificationDisposition.Promoted;
        }
        else if (IsGenericTextDetection(result) &&
                 prediction.IsText &&
                 string.IsNullOrWhiteSpace(learnedExtension))
        {
            disposition = LearnedClassificationDisposition.Supplemental;
        }
        else if (!learnedIsGeneric && !string.IsNullOrWhiteSpace(deterministicExtension))
        {
            disposition = LearnedClassificationDisposition.Conflict;
            message = "deterministic-and-learned-disagree";
            AlignCandidatesAfterLearnedConflict(result, prediction, learnedExtension);
        }
        else
        {
            disposition = LearnedClassificationDisposition.Supplemental;
        }

        result.LearnedClassification = new LearnedClassificationEvidence
        {
            Disposition = disposition,
            Prediction = prediction,
            DeterministicExtension = deterministicExtension,
            DeterministicMimeType = deterministicMime,
            DeterministicConfidence = deterministicConfidence,
            DeterministicReason = deterministicReason,
            DeterministicAgreementExtension = agreementExtension,
            Message = message
        };
        return result;
    }

    private static ContentTypeDetectionResult ReconcileLearnedClassificationAfterAnalysis(
        ContentTypeDetectionResult result)
    {
        var evidence = result.LearnedClassification;
        if (evidence?.Prediction is null ||
            evidence.Disposition == LearnedClassificationDisposition.Failed)
        {
            return result;
        }

        if (evidence.Disposition == LearnedClassificationDisposition.Promoted)
        {
            var learnedExtension = NormalizeExtension(evidence.Prediction.Extension);
            var learnedExtensions = GetLearnedAgreementExtensions(evidence.Prediction, learnedExtension);
            if (learnedExtensions.Any(extension =>
                    ExtensionsEquivalent(result.Extension, extension)))
            {
                return result;
            }

            RestoreDeterministicMetadataAfterAnalysis(result, evidence);
            var analyzedCandidates = result.Candidates;
            var analyzedAlternatives = result.Alternatives;
            AlignCandidatesAfterLearnedPromotion(
                result,
                CreateCandidate(result),
                analyzedCandidates,
                analyzedAlternatives);
        }

        result.LearnedClassification = null;
        return ArbitrateLearnedPrediction(result, evidence.Prediction);
    }

    private static void RestoreDeterministicMetadataAfterAnalysis(
        ContentTypeDetectionResult result,
        LearnedClassificationEvidence evidence)
    {
        var analyzedCandidate = (result.Candidates ?? Array.Empty<ContentTypeDetectionCandidate>())
            .Concat(result.Alternatives ?? Array.Empty<ContentTypeDetectionCandidate>())
            .FirstOrDefault(candidate =>
                ExtensionsEquivalent(candidate.Extension, result.Extension) &&
                candidate.Reason?.StartsWith("learned:", StringComparison.OrdinalIgnoreCase) != true);
        if (analyzedCandidate is not null)
        {
            result.Confidence = analyzedCandidate.Confidence;
            result.Reason = analyzedCandidate.Reason;
            result.ReasonDetails = analyzedCandidate.ReasonDetails;
            result.Score = analyzedCandidate.Score;
            return;
        }

        var deterministicReason = string.Join(
            ";",
            (result.Reason ?? string.Empty)
                .Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Where(segment =>
                    !segment.StartsWith("learned:", StringComparison.OrdinalIgnoreCase) &&
                    !segment.StartsWith("model:", StringComparison.OrdinalIgnoreCase)));
        if (string.IsNullOrWhiteSpace(deterministicReason))
            deterministicReason = evidence.DeterministicReason ?? string.Empty;

        result.Reason = deterministicReason;
        result.ReasonDetails = null;
        result.Score = null;
        result.Confidence = deterministicReason.IndexOf("confirmed", StringComparison.OrdinalIgnoreCase) >= 0
            ? "High"
            : deterministicReason.IndexOf("structure", StringComparison.OrdinalIgnoreCase) >= 0
                ? "Medium"
                : evidence.DeterministicConfidence ?? result.Confidence;
    }

    private static bool IsGenericTextDetection(ContentTypeDetectionResult result)
        => string.Equals(
               NormalizeExtension(result.Extension),
               "txt",
               StringComparison.OrdinalIgnoreCase) ||
           string.Equals(
               EmptyToNull(result.MimeType),
               "text/plain",
               StringComparison.OrdinalIgnoreCase);

    private static string ResolveLearnedMimeType(
        string? learnedMimeType,
        string learnedExtension,
        string? deterministicMimeType)
    {
        var normalizedLearnedMime = EmptyToNull(learnedMimeType);
        if (normalizedLearnedMime != null)
            return normalizedLearnedMime;

        if (MimeMaps.Default.TryGetValue(learnedExtension, out var mappedMime) &&
            !string.IsNullOrWhiteSpace(mappedMime))
        {
            return mappedMime;
        }

        return deterministicMimeType ?? "application/octet-stream";
    }

    private static void AlignCandidatesAfterLearnedPromotion(
        ContentTypeDetectionResult result,
        ContentTypeDetectionCandidate deterministicPrimary,
        IReadOnlyList<ContentTypeDetectionCandidate>? deterministicCandidates,
        IReadOnlyList<ContentTypeDetectionCandidate>? deterministicAlternatives)
    {
        var candidates = new List<ContentTypeDetectionCandidate>
        {
            CreateCandidate(result)
        };

        void AddCandidate(ContentTypeDetectionCandidate candidate)
        {
            if (string.IsNullOrWhiteSpace(candidate.Extension))
                return;
            if (candidates.Any(existing => ExtensionsEquivalent(existing.Extension, candidate.Extension)))
                return;
            candidates.Add(candidate);
        }

        if (deterministicCandidates is { Count: > 0 })
        {
            AddCandidate(deterministicPrimary);
            foreach (var candidate in deterministicCandidates)
                AddCandidate(candidate);
        }
        else
        {
            AddCandidate(deterministicPrimary);
            if (deterministicAlternatives != null)
            {
                foreach (var candidate in deterministicAlternatives)
                    AddCandidate(candidate);
            }
        }

        result.Candidates = candidates;
        result.Alternatives = candidates.Skip(1).ToArray();
    }

    private static ContentTypeDetectionCandidate CreateCandidate(ContentTypeDetectionResult result)
        => new()
        {
            Extension = result.Extension,
            MimeType = result.MimeType,
            Confidence = result.Confidence,
            Reason = result.Reason,
            ReasonDetails = result.ReasonDetails,
            Score = result.Score ?? 0,
            IsDangerous = result.IsDangerous
        };

    private static void AlignCandidatesAfterLearnedConflict(
        ContentTypeDetectionResult result,
        LearnedContentPrediction prediction,
        string? learnedExtension)
    {
        var candidates = new List<ContentTypeDetectionCandidate>
        {
            CreateCandidate(result)
        };

        void AddCandidate(ContentTypeDetectionCandidate candidate)
        {
            if (string.IsNullOrWhiteSpace(candidate.Extension))
                return;
            if (candidates.Any(existing => ExtensionsEquivalent(existing.Extension, candidate.Extension)))
                return;
            candidates.Add(candidate);
        }

        if (result.Candidates != null)
        {
            foreach (var candidate in result.Candidates)
                AddCandidate(candidate);
        }

        if (!string.IsNullOrWhiteSpace(learnedExtension))
        {
            var concreteLearnedExtension = learnedExtension!;
            AddCandidate(new ContentTypeDetectionCandidate
            {
                Extension = concreteLearnedExtension,
                MimeType = ResolveLearnedMimeType(prediction.MimeType, concreteLearnedExtension, null),
                Confidence = LearnedConfidence(prediction.Probability),
                Reason = "learned:" + prediction.Provider.ToLowerInvariant() + ":" + prediction.OutputLabel,
                ReasonDetails = "model:" + prediction.ModelId,
                Score = 0,
                IsDangerous = DangerousExtensions.IsDangerous(concreteLearnedExtension)
            });
        }

        result.Candidates = candidates;
        result.Alternatives = candidates.Skip(1).ToArray();
    }

    internal static void RefreshDerivedAnalysisAfterLearnedPromotion(
        FileAnalysis analysis,
        string path,
        ContentTypeDetectionResult result)
    {
        if (result.LearnedClassification?.Disposition != LearnedClassificationDisposition.Promoted)
            return;

        analysis.NameIssues = AnalyzeName(path, result);
        var scriptLanguage = MapScriptLanguageFromExtension(result.Extension);
        analysis.TextSubtype = MapTextSubtypeFromExtension(result.Extension);
        if (string.IsNullOrEmpty(scriptLanguage))
        {
            analysis.ScriptLanguage = null;
            analysis.ScriptCmdlets = null;
            analysis.Flags &= ~(ContentFlags.IsScript | ContentFlags.ScriptsPotentiallyDangerous);
            if (result.LearnedClassification?.Prediction?.IsText != true)
                analysis.TextSubtype = null;
            return;
        }

        analysis.ScriptLanguage = scriptLanguage;
        analysis.TextSubtype = scriptLanguage;
        analysis.ScriptCmdlets = null;
        analysis.Flags |= ContentFlags.IsScript;
        if (scriptLanguage is "powershell" or "javascript" or "vbscript" or "shell" or "batch")
            analysis.Flags |= ContentFlags.ScriptsPotentiallyDangerous;
        if (scriptLanguage == "powershell")
        {
            var cmdlets = SecurityHeuristics.GetCmdlets(
                path,
                Math.Max(8 * 1024, Math.Min(Settings.DetectionReadBudgetBytes, 512 * 1024)));
            analysis.ScriptCmdlets = cmdlets.Count > 0 ? cmdlets : null;
        }
    }

    private static ContentKind ClassifyKindWithLearnedText(ContentTypeDetectionResult? result)
        => result?.LearnedClassification?.Disposition == LearnedClassificationDisposition.Promoted &&
           result.LearnedClassification.Prediction?.IsText == true
            ? ContentKind.Text
            : KindClassifier.Classify(result);

    private static string? FindDeterministicAgreementExtension(
        ContentTypeDetectionResult result,
        IReadOnlyList<string> learnedExtensions)
    {
        if (learnedExtensions.Count == 0)
            return null;

        var primaryExtension = NormalizeExtension(result.Extension);
        if (learnedExtensions.Any(extension => ExtensionsEquivalent(primaryExtension, extension)))
            return primaryExtension;

        var guessedExtension = NormalizeExtension(result.GuessedExtension);
        if (learnedExtensions.Any(extension => ExtensionsEquivalent(guessedExtension, extension)))
            return guessedExtension;

        foreach (var candidate in GetStrongAlternatives(result, primaryExtension))
        {
            if (candidate.Reason?.StartsWith("learned:", StringComparison.OrdinalIgnoreCase) == true)
                continue;
            var candidateExtension = NormalizeExtension(candidate.Extension);
            if (learnedExtensions.Any(extension => ExtensionsEquivalent(candidateExtension, extension)))
                return candidateExtension;
        }

        return null;
    }

    private static IReadOnlyList<string> GetLearnedAgreementExtensions(
        LearnedContentPrediction prediction,
        string? canonicalExtension)
    {
        var extensions = new List<string>();

        void Add(string? value)
        {
            var normalized = NormalizeExtension(value);
            if (string.IsNullOrWhiteSpace(normalized))
                return;
            if (!extensions.Contains(normalized!, StringComparer.OrdinalIgnoreCase))
                extensions.Add(normalized!);
        }

        Add(canonicalExtension);
        foreach (var alias in prediction.ExtensionAliases ?? Array.Empty<string>())
            Add(alias);
        Add(prediction.OutputLabel);
        return extensions;
    }

    private static bool CanLearnedPredictionFill(ContentTypeDetectionResult result)
    {
        if (string.IsNullOrWhiteSpace(result.Extension))
            return true;

        if (!result.Confidence.Equals("Low", StringComparison.OrdinalIgnoreCase))
            return false;

        return result.Extension.Equals("txt", StringComparison.OrdinalIgnoreCase) ||
               result.Extension.Equals("text", StringComparison.OrdinalIgnoreCase) ||
               result.Reason.Contains("bias:decl:", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ExtensionsEquivalent(string? left, string? right)
    {
        if (string.IsNullOrWhiteSpace(left) || string.IsNullOrWhiteSpace(right))
            return false;
        var leftValue = left!;
        var rightValue = right!;
        if (leftValue.Equals(rightValue, StringComparison.OrdinalIgnoreCase))
            return true;
        return (leftValue.Equals("jpeg", StringComparison.OrdinalIgnoreCase) &&
                rightValue.Equals("jpg", StringComparison.OrdinalIgnoreCase)) ||
               (leftValue.Equals("jpg", StringComparison.OrdinalIgnoreCase) &&
                rightValue.Equals("jpeg", StringComparison.OrdinalIgnoreCase)) ||
               (leftValue.Equals("yaml", StringComparison.OrdinalIgnoreCase) &&
                rightValue.Equals("yml", StringComparison.OrdinalIgnoreCase)) ||
               (leftValue.Equals("yml", StringComparison.OrdinalIgnoreCase) &&
                rightValue.Equals("yaml", StringComparison.OrdinalIgnoreCase)) ||
               (leftValue.Equals("tif", StringComparison.OrdinalIgnoreCase) &&
                rightValue.Equals("tiff", StringComparison.OrdinalIgnoreCase)) ||
               (leftValue.Equals("tiff", StringComparison.OrdinalIgnoreCase) &&
                rightValue.Equals("tif", StringComparison.OrdinalIgnoreCase)) ||
               (leftValue.Equals("bat", StringComparison.OrdinalIgnoreCase) &&
                rightValue.Equals("cmd", StringComparison.OrdinalIgnoreCase)) ||
               (leftValue.Equals("cmd", StringComparison.OrdinalIgnoreCase) &&
                rightValue.Equals("bat", StringComparison.OrdinalIgnoreCase));
    }

    private static string LearnedConfidence(double probability)
        => probability >= 0.90 ? "High" : probability >= 0.70 ? "Medium" : "Low";

    private static ContentTypeDetectionResult CreateUnknownDetection()
        => new()
        {
            Extension = string.Empty,
            MimeType = string.Empty,
            Confidence = "Low",
            Reason = "unknown"
        };

    private static string? EmptyToNull(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value;
}
