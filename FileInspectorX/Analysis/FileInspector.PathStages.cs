namespace FileInspectorX;

public static partial class FileInspector
{
    private static bool NativeTrustRequested(FileAnalysis result, DetectionOptions options)
    {
#if NET8_0_OR_GREATER || NET472
        if (!System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows)) return false;
        if (!options.IncludeAuthenticode || !OperationSettings.VerifyAuthenticodeWithWinTrust) return false;
        var extension = result.Detection?.Extension;
        var declared = System.IO.Path.GetExtension(result.SourceFileName).TrimStart('.').ToLowerInvariant();
        return IsTrustFamily(extension) || IsTrustFamily(declared);
#else
        return false;
#endif
    }

    private static bool IsTrustFamily(string? extension)
        => extension is "exe" or "dll" or "sys" or "cpl" or "ocx" or "scr" or "com" or "pif" or "msi" or "msp" or "msix" or "appx";

    private static bool NativeEtlValidationRequested()
        => OperationSettings.EtlValidation is Settings.EtlValidationMode.TracerptOnly or Settings.EtlValidationMode.NativeThenTracerpt;

    private static void RecordUnavailablePathStages(FileAnalysis result, DetectionOptions options)
    {
        if (result.HasFileSystemSource) return;
        var issues = new List<string>();
        if (options.IncludePermissions) issues.Add("permissions:path-required");
        if (options.IncludeShellProperties) issues.Add("shell-properties:path-required");
        if (ShouldIncludeInstaller(options) && result.Detection?.Extension == "msi") issues.Add("installer:path-required");
        if (NativeTrustRequested(result, options)) issues.Add("authenticode-policy:path-required");
        if (NativeEtlValidationRequested() && result.Detection?.Extension == "etl") issues.Add("etl-validation:path-required");
        if (issues.Count == 0) return;
        result.AnalysisComplete = false;
        result.AnalysisIssues = MergeAnalysisIssues(result.AnalysisIssues, issues);
    }

    private static void AddPortablePathStageOutcomes(List<InspectionStageResult> stages, FileAnalysis result, DetectionOptions options, bool detectionOnly)
    {
        void Add(InspectionStage stage, bool requested, bool applicable, string issue)
        {
            bool missing = !detectionOnly && requested && applicable;
            stages.Add(new InspectionStageResult(stage,
                detectionOnly || !requested ? InspectionStageStatus.NotRequested :
                !applicable ? InspectionStageStatus.NotApplicable : InspectionStageStatus.Unavailable,
                missing ? new[] { issue } : Array.Empty<string>()));
        }
        Add(InspectionStage.Permissions, options.IncludePermissions, true, "permissions:path-required");
        Add(InspectionStage.ShellProperties, options.IncludeShellProperties, true, "shell-properties:path-required");
        Add(InspectionStage.Installer, ShouldIncludeInstaller(options), result.Detection?.Extension == "msi", "installer:path-required");
        Add(InspectionStage.AuthenticodePolicy, options.IncludeAuthenticode && OperationSettings.VerifyAuthenticodeWithWinTrust,
            NativeTrustRequested(result, options), "authenticode-policy:path-required");
        Add(InspectionStage.EtlValidation, NativeEtlValidationRequested(), result.Detection?.Extension == "etl", "etl-validation:path-required");
    }
}
