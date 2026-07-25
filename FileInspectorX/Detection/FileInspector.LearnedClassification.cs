namespace FileInspectorX;

public static partial class FileInspector
{
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
        return ApplyLearnedClassificationCore(
            deterministic,
            options,
            () => options.LearnedClassifier!.Predict(content));
    }

    private static ContentTypeDetectionResult? ApplyLearnedClassification(
        ContentTypeDetectionResult? deterministic,
        ReadOnlyMemory<byte> content,
        DetectionOptions options)
    {
        return ApplyLearnedClassificationCore(
            deterministic,
            options,
            () => options.LearnedClassifier!.Predict(content));
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
        Func<LearnedContentPrediction> predict)
    {
        if (options.LearnedClassificationMode == LearnedClassificationMode.Off)
            return deterministic;

        if (options.LearnedClassifier is null)
        {
            var missing = new InvalidOperationException(
                "Learned classification was enabled without an ILearnedContentClassifier.");
            if (options.LearnedClassificationMode == LearnedClassificationMode.Required)
                throw new LearnedClassificationException(missing.Message, missing);
            return AttachLearnedFailure(deterministic, missing);
        }

        try
        {
            var prediction = predict();
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
        var learnedAgreementExtension = learnedExtension ?? NormalizeExtension(prediction.OutputLabel);
        var agreementExtension = FindDeterministicAgreementExtension(result, learnedAgreementExtension);
        var learnedIsGeneric = string.IsNullOrWhiteSpace(learnedExtension) ||
                               prediction.OutputLabel.Equals("unknown", StringComparison.OrdinalIgnoreCase) ||
                               prediction.OutputLabel.Equals("txt", StringComparison.OrdinalIgnoreCase);

        LearnedClassificationDisposition disposition;
        string? message = null;

        if (!string.IsNullOrWhiteSpace(agreementExtension))
        {
            disposition = LearnedClassificationDisposition.Agreed;
        }
        else if (CanLearnedPredictionFill(result) && !learnedIsGeneric)
        {
            result.Extension = learnedExtension!;
            result.MimeType = prediction.MimeType ?? string.Empty;
            result.Confidence = LearnedConfidence(prediction.Probability);
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
        else if (!learnedIsGeneric && !string.IsNullOrWhiteSpace(deterministicExtension))
        {
            disposition = LearnedClassificationDisposition.Conflict;
            message = "deterministic-and-learned-disagree";
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

    private static void RefreshDerivedAnalysisAfterLearnedPromotion(
        FileAnalysis analysis,
        string path,
        ContentTypeDetectionResult result)
    {
        if (result.LearnedClassification?.Disposition != LearnedClassificationDisposition.Promoted)
            return;

        analysis.NameIssues = AnalyzeName(path, result);
        var scriptLanguage = MapScriptLanguageFromExtension(result.Extension);
        if (string.IsNullOrEmpty(scriptLanguage))
            return;

        analysis.ScriptLanguage = scriptLanguage;
        analysis.TextSubtype = scriptLanguage;
        analysis.Flags |= ContentFlags.IsScript;
        if (scriptLanguage is "powershell" or "javascript" or "vbscript" or "shell" or "batch")
            analysis.Flags |= ContentFlags.ScriptsPotentiallyDangerous;
    }

    private static string? FindDeterministicAgreementExtension(
        ContentTypeDetectionResult result,
        string? learnedExtension)
    {
        if (string.IsNullOrWhiteSpace(learnedExtension))
            return null;

        var primaryExtension = NormalizeExtension(result.Extension);
        if (ExtensionsEquivalent(primaryExtension, learnedExtension))
            return primaryExtension;

        var guessedExtension = NormalizeExtension(result.GuessedExtension);
        if (ExtensionsEquivalent(guessedExtension, learnedExtension))
            return guessedExtension;

        foreach (var candidate in GetStrongAlternatives(result, primaryExtension))
        {
            var candidateExtension = NormalizeExtension(candidate.Extension);
            if (ExtensionsEquivalent(candidateExtension, learnedExtension))
                return candidateExtension;
        }

        return null;
    }

    private static bool CanLearnedPredictionFill(ContentTypeDetectionResult result)
    {
        if (string.IsNullOrWhiteSpace(result.Extension))
            return true;

        if (!result.Confidence.Equals("Low", StringComparison.OrdinalIgnoreCase))
            return false;

        return result.Extension.Equals("txt", StringComparison.OrdinalIgnoreCase) ||
               result.Extension.Equals("text", StringComparison.OrdinalIgnoreCase);
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
                rightValue.Equals("tif", StringComparison.OrdinalIgnoreCase));
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
