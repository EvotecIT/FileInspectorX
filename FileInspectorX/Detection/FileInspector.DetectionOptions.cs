namespace FileInspectorX;

public static partial class FileInspector
{
    /// <summary>
    /// Options controlling enrichment of detection output (hashes, magic header capture).
    /// </summary>
    public sealed class DetectionOptions {
        /// <summary>Immutable operation settings. Null retains the legacy global settings; use InspectionSettings.CaptureDefaults() for isolation.</summary>
        public InspectionSettings? Settings { get; set; }

        /// <summary>Cooperative cancellation checked at library computation and I/O boundaries.</summary>
        public System.Threading.CancellationToken CancellationToken { get; set; }

        internal DetectionOptions Copy() => (DetectionOptions)MemberwiseClone();

        /// <summary>When true, computes a SHA-256 hash of the full stream/file and exposes it on <see cref="ContentTypeDetectionResult.Sha256Hex"/>.</summary>
        public bool ComputeSha256 { get; set; } = false;
        /// <summary>When &gt; 0, captures the first N bytes of the header as uppercase hex into <see cref="ContentTypeDetectionResult.MagicHeaderHex"/>.</summary>
        public int MagicHeaderBytes { get; set; } = 0; // 0 = skip
        /// <summary>
        /// When true, indicates callers intend a detection-only pass. Helper APIs may honor this by running
        /// only detection and returning a minimal <see cref="FileInspectorX.FileAnalysis"/> (when used with
        /// <see cref="FileInspectorX.FileInspector.Inspect(string, FileInspectorX.FileInspector.DetectionOptions?)"/>).
        /// This does not affect <see cref="FileInspectorX.FileInspector.Detect(string)"/> which is always detection-only.
        /// </summary>
        public bool DetectOnly { get; set; } = false;

        /// <summary>Include container analysis (ZIP/TAR summaries, inner-archive hints). Default true.</summary>
        public bool IncludeContainer { get; set; } = true;
        /// <summary>Include permissions/ownership snapshot. Default true.</summary>
        public bool IncludePermissions { get; set; } = true;
        /// <summary>Include Authenticode/package signature analysis where applicable. Default true.</summary>
        public bool IncludeAuthenticode { get; set; } = true;
        /// <summary>Include references extraction from config files (Task XML, scripts.ini/xml). Default true.</summary>
        public bool IncludeReferences { get; set; } = true;
        /// <summary>Include installer/package metadata (MSIX/APPX/VSIX/MSI). Default false because native parsers require explicit trust.</summary>
        public bool IncludeInstaller { get; set; } = false;
        /// <summary>Compute Assessment (score/decision) and attach to the result. Default true.</summary>
        public bool IncludeAssessment { get; set; } = true;
        /// <summary>Include Windows shell properties (Explorer Details). Default false because shell handlers execute in-process.</summary>
        public bool IncludeShellProperties { get; set; } = false;

        /// <summary>
        /// Optional learned classifier. It is never invoked while
        /// <see cref="LearnedClassificationMode"/> is <see cref="FileInspectorX.LearnedClassificationMode.Off"/>.
        /// </summary>
        public ILearnedContentClassifier? LearnedClassifier { get; set; }

        /// <summary>Controls optional learned classification. Default is <see cref="FileInspectorX.LearnedClassificationMode.Off"/>.</summary>
        public LearnedClassificationMode LearnedClassificationMode { get; set; } = FileInspectorX.LearnedClassificationMode.Off;

        internal int NestedContainerDepth { get; set; }
        internal NestedContainerBudgetState? NestedContainerBudget { get; set; }
    }

}
