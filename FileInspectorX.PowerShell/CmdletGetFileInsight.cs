using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;
using FileInspectorX;

namespace FileInspectorX.PowerShell {
    /// <summary>
    /// <para type="synopsis">Analyzes files and returns content type and lightweight insights.</para>
    /// <para type="description">Thin PowerShell wrapper over FileInspectorX. Detects file type by magic bytes and heuristics and, by default, performs high-level analysis (e.g., OOXML macros, PE triage, container hints). Use -DetectOnly to return only the detection result.</para>
    /// <example>
    ///  <para>Analyze a single file</para>
    ///  <code>Get-FileInsight -Path C:\\files\\sample.docx</code>
    /// </example>
    /// <example>
    ///  <para>Detect only (no analysis)</para>
    ///  <code>Get-FileInsight -Path .\\payload.bin -DetectOnly</code>
    /// </example>
    /// <example>
    ///  <para>Include SHA-256 and first 16 bytes header (hex)</para>
    ///  <code>Get-FileInsight -Path .\\app.exe -ComputeSha256 -MagicHeaderBytes 16</code>
    /// </example>
    /// <seealso cref="FileInspectorX.PowerShell.AsyncPSCmdlet" />
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "FileInsight", DefaultParameterSetName = "Path", SupportsShouldProcess = false)]
    [OutputType(typeof(AnalysisView))]
    [OutputType(typeof(DetectionView))]
    [OutputType(typeof(PermissionsView))]
    [OutputType(typeof(SignatureView))]
    [OutputType(typeof(SummaryView))]
    public sealed class CmdletGetFileInsight : AsyncPSCmdlet {
        /// <summary>
        /// One or more file paths to analyze. Accepts pipeline input of strings and resolves PowerShell provider paths.
        /// </summary>
        [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true, ParameterSetName = "Path")]
        [Alias("FullName")]
        public string[] Path { get; set; } = Array.Empty<string>();

        /// <summary>Output shape to emit. Defaults to Summary.</summary>
        [Parameter()]
        public InsightView View { get; set; } = InsightView.Summary;

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


        private InternalLogger? _logger;


        /// <inheritdoc />
        protected override Task BeginProcessingAsync() {
            // Bridge internal logger to PowerShell streams (optional; zero logic beyond wiring).
            _logger = new InternalLogger(false);
            _ = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        protected override async Task ProcessRecordAsync() {
            var options = new FileInspector.DetectionOptions {
                ComputeSha256 = ComputeSha256,
                MagicHeaderBytes = MagicHeaderBytes
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
                            default: {
                                var a = FileInspector.Inspect(p, options);
                                WriteObject(a.ToAnalysisView(p));
                                break; }
                        }
                    }
                } catch (PipelineStoppedException) { throw; }
                catch (Exception ex) {
                    WriteError(new ErrorRecord(ex, "GetFileInsightFailure", ErrorCategory.NotSpecified, input));
                }
            }
            await Task.CompletedTask;
        }
    }
}
