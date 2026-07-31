using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Threading;
using System.Threading.Tasks;
using FileInspectorX;
#if FILEINSPECTORX_MAGIKA
using FileInspectorX.Magika;
#endif

namespace FileInspectorX.PowerShell {
    /// <summary>
    /// <para type="synopsis">Analyzes files and returns a full FileAnalysis object by default, with optional compact views.</para>
    /// <para type="description">By default (-View Raw), returns the full FileAnalysis with detection, flags, permissions (unless excluded), signatures, installer metadata, references and assessment. Use -View to project compact views (Summary/Detection/Analysis/Permissions/Signature/References/Assessment/Installer/ShellProperties). Each view exposes Raw with the full FileAnalysis for drill-down.</para>
    /// <example>
    ///  <para>Analyze a single file</para>
    ///  <code>Get-FileInsight -Path C:\\files\\sample.docx</code>
    /// </example>
    /// <example>
    ///  <para>Detect only (no analysis)</para>
    ///  <code>Get-FileInsight -Path .\\payload.bin -DetectOnly</code>
    /// </example>
    /// <example>
    ///  <para>Detect only for all EXE files under current directory</para>
    ///  <code>Get-ChildItem -Filter *.exe -File -Recurse | Get-FileInsight -View Detection</code>
    /// </example>
    /// <example>
    ///  <para>Summarize a directory, skipping signature and installer enrichment</para>
    ///  <code>Get-ChildItem -File -Recurse | Get-FileInsight -View Summary -ExcludeSignature -ExcludeInstaller</code>
    /// </example>
    /// <example>
    ///  <para>Include SHA-256 and first 16 bytes header (hex)</para>
    ///  <code>Get-FileInsight -Path .\\app.exe -ComputeSha256 -MagicHeaderBytes 16</code>
    /// </example>
    /// <example>
    ///  <para>Use the default Magika-assisted detection while preserving deterministic validators</para>
    ///  <code>Get-FileInsight -Path .\\source.txt -View Detection</code>
    /// </example>
    /// <example>
    ///  <para>Run deterministic-only detection without Magika</para>
    ///  <code>Get-FileInsight -Path .\\source.txt -DisableMagika -View Detection</code>
    /// </example>
    /// <seealso cref="FileInspectorX.PowerShell.AsyncPSCmdlet" />
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "FileInsight", DefaultParameterSetName = "Path", SupportsShouldProcess = false)]
    [OutputType(typeof(FileInspectorX.FileAnalysis))]
    [OutputType(typeof(AnalysisView))]
    [OutputType(typeof(DetectionView))]
    [OutputType(typeof(PermissionsView))]
    [OutputType(typeof(SignatureView))]
    [OutputType(typeof(SummaryView))]
    [OutputType(typeof(AssessmentView))]
    [OutputType(typeof(PolicySummaryView))]
    [OutputType(typeof(InstallerView))]
    [OutputType(typeof(ReferencesView))]
    [OutputType(typeof(ShellPropertiesView))]
    public sealed class CmdletGetFileInsight : AsyncPSCmdlet {
        /// <summary>
        /// One or more file paths to analyze. Accepts pipeline input of strings and resolves PowerShell provider paths.
        /// </summary>
        [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true, ParameterSetName = "Path")]
        [Alias("FullName")]
        public string[] Path { get; set; } = Array.Empty<string>();

        /// <summary>Output shape to emit. Defaults to Raw (full FileAnalysis object). Other values: Summary, Detection, Analysis, Permissions, Signature, References, Assessment, Policy, Installer, ShellProperties.</summary>
        [Parameter()]
        public InsightView View { get; set; } = InsightView.Raw;

        /// <summary>Return only detection result (skip analysis). Back-compat shim for -View Detection.</summary>
        [Parameter()]
        public SwitchParameter DetectOnly { get; set; }

        /// <summary>Compute SHA-256 of the file and include in output.</summary>
        [Parameter()]
        public SwitchParameter ComputeSha256 { get; set; }

        /// <summary>Capture first N bytes of the header as uppercase hex.</summary>
        [Parameter()]
        [ValidateRange(0, 1048576)]
        public int MagicHeaderBytes { get; set; } = 0;

        /// <summary>Exclude permissions/ownership snapshot from the analysis.</summary>
        [Parameter()] public SwitchParameter ExcludePermissions { get; set; }
        /// <summary>Exclude signature/Authenticode and package signature analysis.</summary>
        [Parameter()] public SwitchParameter ExcludeSignature { get; set; }
        /// <summary>Exclude references extraction (Task XML, scripts.ini/xml).</summary>
        [Parameter()] public SwitchParameter ExcludeReferences { get; set; }
        /// <summary>Exclude installer/package metadata (MSIX/APPX/VSIX/MSI).</summary>
        [Parameter()] public SwitchParameter ExcludeInstaller { get; set; }
        /// <summary>Exclude container triage (ZIP/TAR sampling, subtype and inner hints).</summary>
        [Parameter()] public SwitchParameter ExcludeContainer { get; set; }
        /// <summary>Exclude assessment (score/decision/codes).</summary>
        [Parameter()] public SwitchParameter ExcludeAssessment { get; set; }
        /// <summary>Exclude Windows shell properties (Explorer Details).</summary>
        [Parameter()] public SwitchParameter ExcludeShellProperties { get; set; }

        /// <summary>
        /// Use the bundled Magika learned classifier. This compatibility switch is enabled by
        /// default; use DisableMagika or -UseMagika:$false for deterministic-only analysis.
        /// Deterministic magic and structural validation remain authoritative when evidence conflicts.
        /// </summary>
        [Parameter()]
        public SwitchParameter UseMagika { get; set; } = true;

        /// <summary>Disable the default Magika assistance and use deterministic analysis only.</summary>
        [Parameter()]
        public SwitchParameter DisableMagika { get; set; }

        /// <summary>Magika probability policy. Defaults to HighConfidence.</summary>
        [Parameter()]
        [ValidateSet("HighConfidence", "MediumConfidence", "BestGuess")]
        public string MagikaPredictionMode { get; set; } = "HighConfidence";

        /// <summary>
        /// Failure behavior for the optional classifier. Assist records provider failures and continues;
        /// Required reports a terminating per-file error.
        /// </summary>
        [Parameter()]
        public LearnedClassificationMode LearnedClassificationMode { get; set; } = FileInspectorX.LearnedClassificationMode.Assist;

        private InternalLogger? _logger;
        private ILearnedContentClassifier? _magikaClassifier;
        private IDisposable? _magikaDisposable;


        /// <inheritdoc />
        protected override Task BeginProcessingAsync() {
            // Bridge internal logger to PowerShell streams (optional; zero logic beyond wiring).
            _logger = new InternalLogger(false);
            _ = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            if (IsMagikaEnabled)
            {
                try
                {
                    _magikaClassifier = CreateMagikaClassifier(MagikaPredictionMode);
                    _magikaDisposable = _magikaClassifier as IDisposable;
                }
                catch (Exception ex) when (ex is not OutOfMemoryException &&
                                           LearnedClassificationMode == FileInspectorX.LearnedClassificationMode.Assist)
                {
                    WriteWarning(
                        "The optional Magika provider could not be initialized. " +
                        "Assist mode will keep deterministic results and record a learned-classification failure for each file. " +
                        "Reason: " + ex.Message);
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    ThrowTerminatingError(new ErrorRecord(
                        new LearnedClassificationException(
                            "The required Magika provider could not be initialized.",
                            ex),
                        "RequiredLearnedClassificationFailure",
                        ErrorCategory.NotSpecified,
                        targetObject: null));
                }
            }
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        protected override async Task ProcessRecordAsync() {
            try
            {
                await ProcessFilesAsync();
            }
            finally
            {
                if (CancelToken.IsCancellationRequested)
                    DisposeMagikaClassifier();
            }
        }

        private Task ProcessFilesAsync()
        {
            var options = new FileInspector.DetectionOptions {
                ComputeSha256 = ComputeSha256,
                MagicHeaderBytes = MagicHeaderBytes,
                IncludePermissions = !ExcludePermissions,
                IncludeAuthenticode = !ExcludeSignature,
                IncludeReferences = !ExcludeReferences,
                IncludeInstaller = !ExcludeInstaller,
                IncludeContainer = !ExcludeContainer,
                IncludeAssessment = !ExcludeAssessment,
                IncludeShellProperties = !ExcludeShellProperties,
                LearnedClassifier = _magikaClassifier,
                LearnedClassificationMode = IsMagikaEnabled
                    ? LearnedClassificationMode
                    : FileInspectorX.LearnedClassificationMode.Off
            };

            // Resolve each incoming path through PS provider
            foreach (var input in Path ?? Array.Empty<string>()) {
                if (string.IsNullOrWhiteSpace(input)) continue;

                try {
                    var resolved = this.GetResolvedProviderPathFromPSPath(input, out var _);
                    if (resolved is null || resolved.Count == 0) {
                        WriteError(new ErrorRecord(new ItemNotFoundException(input), "PathResolutionFailed", ErrorCategory.ObjectNotFound, input));
                        continue;
                    }
                    foreach (var p in resolved) {
                        if (!System.IO.File.Exists(p)) {
                            WriteError(new ErrorRecord(new System.IO.FileNotFoundException($"File not found: {p}", p), "FileNotFound", ErrorCategory.ObjectNotFound, p));
                            continue;
                        }

                        var view = this.View;
                        if (DetectOnly) view = InsightView.Detection;
                        switch (view) {
                            case InsightView.Raw: {
                                var a = FileInspector.Inspect(p, options);
                                WriteObject(a);
                                break; }
                            case InsightView.Detection: {
                                options.DetectOnly = true;
                                var a = FileInspector.Inspect(p, options);
                                WriteObject(a.ToDetectionView(p));
                                break; }
                            case InsightView.Permissions: {
                                var a = FileInspector.Inspect(p, options);
                                WriteObject(a.ToPermissionsView(p));
                                break; }
                            case InsightView.Signature: {
                                var a = FileInspector.Inspect(p, options);
                                WriteObject(a.ToSignatureView(p));
                                break; }
                            case InsightView.Summary: {
                                var a = FileInspector.Inspect(p, options);
                                WriteObject(a.ToSummaryView(p));
                                break; }
                            case InsightView.Assessment: {
                                var a = FileInspector.Inspect(p, options);
                                WriteObject(a.ToAssessmentView(p));
                                break; }
                            case InsightView.Policy: {
                                var a = FileInspector.Inspect(p, options);
                                WriteObject(a.ToPolicySummaryView(p));
                                break; }
                            case InsightView.Installer: {
                                var a = FileInspector.Inspect(p, options);
                                WriteObject(a.ToInstallerView(p));
                                break; }
                            case InsightView.References: {
                                var a = FileInspector.Inspect(p, options);
                                foreach (var v in a.ToReferencesView(p)) WriteObject(v);
                                break; }
                            case InsightView.ShellProperties: {
                                var a = FileInspector.Inspect(p, options);
                                foreach (var v in a.ToShellPropertiesView(p)) WriteObject(v);
                                break; }
                            default: {
                                var a = FileInspector.Inspect(p, options);
                                WriteObject(a.ToAnalysisView(p));
                                break; }
                        }
                    }
                } catch (PipelineStoppedException) { throw; }
                catch (LearnedClassificationException ex) {
                    ThrowTerminatingError(new ErrorRecord(
                        ex,
                        "RequiredLearnedClassificationFailure",
                        ErrorCategory.NotSpecified,
                        input));
                    return Task.CompletedTask;
                }
                catch (Exception ex) when (ex is not OutOfMemoryException) {
                    WriteError(new ErrorRecord(ex, "GetFileInsightFailure", ErrorCategory.NotSpecified, input));
                }
            }
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        protected override Task EndProcessingAsync()
        {
            DisposeMagikaClassifier();
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public override void Dispose()
        {
            DisposeMagikaClassifier();
            base.Dispose();
        }

        private void DisposeMagikaClassifier()
        {
            var disposable = Interlocked.Exchange(ref _magikaDisposable, null);
            _magikaClassifier = null;
            disposable?.Dispose();
        }

        private static ILearnedContentClassifier CreateMagikaClassifier(string predictionMode)
        {
#if FILEINSPECTORX_MAGIKA
            MagikaNativeRuntimeLoader.EnsureLoaded();
            if (!Enum.TryParse<MagikaPredictionMode>(predictionMode, true, out var parsedMode) ||
                !Enum.IsDefined(typeof(MagikaPredictionMode), parsedMode))
            {
                throw new ArgumentException(
                    "Expected HighConfidence, MediumConfidence, or BestGuess.",
                    nameof(predictionMode));
            }
            return new MagikaContentClassifier(new MagikaClassifierOptions
            {
                PredictionMode = parsedMode
            });
#else
            throw new InvalidOperationException(
                "Magika is optional and is not included in this PowerShell module build. " +
                "Install or publish a module built with IncludeMagika=true.");
#endif
        }

        private bool IsMagikaEnabled =>
            UseMagika &&
            !DisableMagika &&
            LearnedClassificationMode != FileInspectorX.LearnedClassificationMode.Off;
    }
}
