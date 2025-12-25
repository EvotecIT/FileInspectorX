namespace FileInspectorX;

/// <summary>
/// Global settings for the FileInspectorX library.
/// Controls verbosity (via <see cref="InternalLogger"/>) and read budgets used during detection.
/// </summary>
/// <remarks>
/// Adjust these flags to direct diagnostic information while running detection/analysis. No thread settings are required.
/// </remarks>
public class Settings {
    /// <summary>
    /// The logger instance.
    /// </summary>
    protected static InternalLogger _logger = new InternalLogger();

    /// <summary>
    /// Gets the internal logger instance.
    /// </summary>
    public static InternalLogger Logger => _logger;

    /// <summary>
    /// Gets or sets a value indicating whether error logging is enabled.
    /// </summary>
    public bool Error {
        get => _logger.IsError;
        set => _logger.IsError = value;
    }

    /// <summary>
    /// Gets or sets a value indicating whether verbose logging is enabled.
    /// </summary>
    public bool Verbose {
        get => _logger.IsVerbose;
        set => _logger.IsVerbose = value;
    }

    /// <summary>
    /// Gets or sets a value indicating whether warning logging is enabled.
    /// </summary>
    public bool Warning {
        get => _logger.IsWarning;
        set => _logger.IsWarning = value;
    }

    /// <summary>
    /// Gets or sets a value indicating whether progress logging is enabled.
    /// </summary>
    public bool Progress {
        get => _logger.IsProgress;
        set => _logger.IsProgress = value;
    }

    /// <summary>
    /// Gets or sets a value indicating whether debug logging is enabled.
    /// </summary>
    public bool Debug {
        get => _logger.IsDebug;
        set => _logger.IsDebug = value;
    }

    /// <summary>
    /// The lock object
    /// </summary>
    protected readonly object _LockObject = new object();

    /// <summary>
    /// Maximum number of bytes that Detect and its helpers may scan when they choose to scan beyond the initial header.
    /// Used in places like ISO fallback scanning. Defaults to 1 MB.
    /// </summary>
    public static int DetectionReadBudgetBytes { get; set; } = 1_000_000;

    /// <summary>
    /// Number of bytes to read as the primary header when Detect(Stream) samples a file. Defaults to 4096.
    /// </summary>
    public static int HeaderReadBytes { get; set; } = 4096;

    /// <summary>
    /// When true, detection emits debug logs with candidate scores and alternatives.
    /// </summary>
    public static bool DetectionLogCandidates { get; set; } = false;

    /// <summary>
    /// Maximum number of alternative detection candidates to keep. Default 5.  
    /// </summary>
    public static int DetectionMaxAlternatives { get; set; } = 5;

    /// <summary>
    /// Minimum score gap required to replace the primary detection with a higher-scoring alternative.
    /// Default 6.
    /// </summary>
    public static int DetectionPrimaryScoreMargin { get; set; } = 6;

    /// <summary>
    /// Score gap within which a declared extension can act as a tie-breaker.
    /// Default 2.
    /// </summary>
    public static int DetectionDeclaredTieBreakerMargin { get; set; } = 2;

    /// <summary>
    /// Optional score adjustments for detection candidates keyed by extension or reason.
    /// Keys can be plain (e.g., "ps1") or prefixed (e.g., "ext:ps1", "reason:text:ps1").
    /// </summary>
    public static IDictionary<string, int> DetectionScoreAdjustments { get; set; } = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// When true, <see cref="FileInspector.Detect(string)"/> performs a best-effort XML well-formedness check for
    /// Group Policy ADMX/ADML files (declared or detected) using a secure XmlReader (DTD prohibited).
    /// Default true to reduce false positives and surface malformed GPO templates explicitly.
    /// </summary>
    public static bool AdmxAdmlXmlWellFormednessValidationEnabled { get; set; } = true;

    /// <summary>
    /// Maximum file size in bytes to validate when <see cref="AdmxAdmlXmlWellFormednessValidationEnabled"/> is true.
    /// Defaults to 5 MB.
    /// </summary>
    public static long AdmxAdmlXmlWellFormednessMaxBytes { get; set; } = 5_000_000;

    /// <summary>
    /// JS minified heuristic: minimum total characters to consider the heuristic.
    /// </summary>
    public static int JsMinifiedMinLength { get; set; } = 1024;

    /// <summary>
    /// JS minified heuristic: flag when average line length exceeds this many characters.
    /// </summary>
    public static int JsMinifiedAvgLineThreshold { get; set; } = 400;

    /// <summary>
    /// JS minified heuristic: ratio of non-whitespace characters to total length required to flag.
    /// </summary>
    public static double JsMinifiedDensityThreshold { get; set; } = 0.85;

    /// <summary>
    /// When true, Analyze() performs lightweight security scanning for scripts/text to produce neutral SecurityFindings.
    /// </summary>
    public static bool SecurityScanScripts { get; set; } = true;
    /// <summary>
    /// When true, scans text/script content for generic secrets (private keys, JWTs, key=... patterns). Emits neutral codes only.
    /// </summary>
    public static bool SecretsScanEnabled { get; set; } = true;

    /// <summary>
    /// When true, the References extractor will attempt to check existence for network paths (UNC/file URLs) it discovers.
    /// Defaults to false to avoid latency or network dependencies.
    /// </summary>
    public static bool CheckNetworkPathsInReferences { get; set; } = false;

    /// <summary>
    /// When true on Windows, perform WinVerifyTrust policy verification for Authenticode (catalog-aware).
    /// </summary>
    public static bool VerifyAuthenticodeWithWinTrust { get; set; } = true;

    /// <summary>
    /// When true, attempt revocation checks during WinVerifyTrust (may require network, slower).
    /// </summary>
    public static bool VerifyAuthenticodeRevocation { get; set; } = false;

    /// <summary>
    /// WinTrust/chain cache TTL in minutes. Cached policy results older than this are discarded. Default 360 minutes (6 hours).
    /// </summary>
    public static int WinTrustCacheTtlMinutes { get; set; } = 360;

    /// <summary>
    /// Maximum number of entries to keep in the WinTrust/chain cache. Oldest entries are pruned opportunistically. Default 1024.
    /// </summary>
    public static int WinTrustCacheMaxEntries { get; set; } = 1024;

    /// <summary>
    /// When false, MSI/AppX/Installer metadata enrichment is skipped even if Analyze() is asked to include installer metadata.
    /// </summary>
    public static bool IncludeInstaller { get; set; } = false;

    /// <summary>
    /// When true, MSI CustomAction summary is collected (Windows only) during installer enrichment.
    /// Default false for maximum stability.
    /// </summary>
    public static bool EnableMsiCustomActions { get; set; } = false;

    /// <summary>
    /// Enable ultra-light breadcrumb logging to a local file for crash forensics.
    /// Default false. Can be toggled by env var TIERBRIDGE_BREADCRUMBS=1.
    /// </summary>
    public static bool BreadcrumbsEnabled { get; set; } = false;

    /// <summary>
    /// Optional override for breadcrumb log file path. When null, defaults to %ProgramData%/TierBridge/FileInspectorX.Breadcrumbs.log.
    /// </summary>
    public static string? BreadcrumbsPath { get; set; } = null;

    /// <summary>
    /// Maximum breadcrumb log size in bytes before rotation. Default 5 MB.
    /// </summary>
    public static int BreadcrumbsMaxBytes { get; set; } = 5_000_000;

    /// <summary>
    /// When true, script/text heuristics attempt quick DNS resolution for discovered hostnames (UNC/URLs) to enrich findings.
    /// Default false to avoid network dependency.
    /// </summary>
    public static bool ResolveNetworkHostsInHeuristics { get; set; } = false;

    /// <summary>
    /// Maximum hosts to resolve per file when <see cref="ResolveNetworkHostsInHeuristics"/> is enabled. Default 3.
    /// </summary>
    public static int NetworkHostResolveMax { get; set; } = 3;

    /// <summary>
    /// Timeout in milliseconds for DNS/Ping checks in heuristics. Default 300ms.
    /// </summary>
    public static int NetworkHostResolveTimeoutMs { get; set; } = 300;

    /// <summary>
    /// When true, attempt a short ICMP ping in addition to DNS resolution for discovered hosts.
    /// Default false.
    /// </summary>
    public static bool PingHostsInHeuristics { get; set; } = false;

    /// <summary>
    /// Domains considered trusted/allowed for HTML external links (e.g., your own CDN/domains). Suffix match, case-insensitive.
    /// When all HTML external links are allowed, HtmlHasExternalLinks flag is suppressed.
    /// Also used by script/text heuristics to split discovered hosts into internal vs external counts (net:hosts-int/net:hosts-ext).
    /// </summary>
    public static string[] HtmlAllowedDomains { get; set; } = Array.Empty<string>();

    /// <summary>
    /// When true, ReportView exports full lists of URLs/UNCs discovered in HTML and scripts (in addition to samples).
    /// Defaults to false to keep payloads smaller.
    /// </summary>
    public static bool ReferenceFullListsEnabled { get; set; } = false;
    /// <summary>
    /// Maximum characters for any single exported full reference list. Excess is truncated.
    /// </summary>
    public static int ReferenceFullListsMaxChars { get; set; } = 4000;

    /// <summary>
    /// Assessment score threshold for Warn decision. Default 40.
    /// </summary>
    public static int AssessmentWarnThreshold { get; set; } = 40;

    /// <summary>
    /// Assessment score threshold for Block decision. Default 70.
    /// </summary>
    public static int AssessmentBlockThreshold { get; set; } = 70;

    /// <summary>
    /// Optional list of allowed vendor names (publisher/org) used for a positive hint in assessment.
    /// Matches against InstallerInfo.Publisher/PublisherDisplayName/Manufacturer and Authenticode SignerSubjectCN/O.
    /// </summary>
    public static string[] AllowedVendors { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Vendor match mode for AllowedVendors list. 'Contains' (default) matches if vendor string contains an allowed token (case-insensitive).
    /// 'Exact' requires a full case-insensitive equality.
    /// </summary>
    public static VendorMatchMode VendorMatchMode { get; set; } = VendorMatchMode.Contains;

    /// <summary>
    /// When true, zip/tar container analysis performs a deeper scan of inner entries (bounded by budgets) to detect disguised types and suspicious names.
    /// Defaults to false to keep analysis fast.
    /// </summary>
    public static bool DeepContainerScanEnabled { get; set; } = false;

    /// <summary>
    /// Maximum number of entries to scan deeply inside a container when <see cref="DeepContainerScanEnabled"/> is true. Default 64.
    /// </summary>
    public static int DeepContainerMaxEntries { get; set; } = 64;

    /// <summary>
    /// Maximum number of bytes to read from each inner entry during deep scan. Default 262144 (256 KB).
    /// </summary>
    public static int DeepContainerMaxEntryBytes { get; set; } = 262_144;

    /// <summary>
    /// Name indicators for well-known admin/security tools. Checked against inner entry names (case-insensitive) to emit neutral findings like "tool:pingcastle".
    /// </summary>
    public static string[] KnownToolNameIndicators { get; set; } = new[] { "pingcastle", "bloodhound" };

    /// <summary>
    /// Optional list of known tool SHA-256 hashes (lowercase hex). When deep container scanning computes an inner hash that matches, a finding 'toolhash:&lt;name&gt;' is emitted.
    /// </summary>
    public static IReadOnlyDictionary<string,string> KnownToolHashes { get; set; } = new Dictionary<string,string>();

    // Encoded content detection/decoding limits
    /// <summary>
    /// Minimum contiguous base64 characters to consider base64 classification.
    /// </summary>
    public static int EncodedBase64MinBlock { get; set; } = 128;
    /// <summary>
    /// Maximum number of characters to probe in the head for base64 detection.
    /// </summary>
    public static int EncodedBase64ProbeChars { get; set; } = 8192;
    /// <summary>
    /// Ratio of allowed base64 characters among non‑whitespace required to classify as base64.
    /// </summary>
    public static double EncodedBase64AllowedRatio { get; set; } = 0.92;
    /// <summary>
    /// Minimum hex characters (continuous) to classify as hex dump (80 bytes).
    /// </summary>
    public static int EncodedHexMinChars { get; set; } = 160;
    /// <summary>
    /// Number of bytes to read from file head when probing for encoded payloads during Analyze().
    /// </summary>
    public static int EncodedProbeReadBytes { get; set; } = 16 * 1024;
    /// <summary>
    /// Maximum decoded bytes to analyze from encoded payloads.
    /// </summary>
    public static int EncodedDecodeMaxBytes { get; set; } = 128 * 1024;

    // ETL validation (Windows only)
    /// <summary>
    /// ETL validation strategies.
    /// </summary>
    public enum EtlValidationMode {
        /// <summary>Do not perform ETL validation; rely on magic/extension only.</summary>
        Off,
        /// <summary>Magic/extension only (no external tools).</summary>
        MagicOnly,
        /// <summary>Use tracerpt.exe with timeout; avoids native P/Invoke.</summary>
        TracerptOnly,
        /// <summary>Attempt native ETW first, then tracerpt; UNSAFE until native struct usage is fixed.</summary>
        NativeThenTracerpt
    }
    /// <summary>
    /// ETL validation mode. Default MagicOnly for maximum stability.
    /// </summary>
    public static EtlValidationMode EtlValidation { get; set; } = EtlValidationMode.MagicOnly;
    /// <summary>Timeout in milliseconds for the tracerpt probe. Default 4000.</summary>
    public static int EtlProbeTimeoutMs { get; set; } = 4000;
    /// <summary>
    /// When &gt; 0, ETL analysis is short-circuited for files at or above this size (bytes),
    /// returning a lightweight detection-only result to avoid heavy processing on very large traces.
    /// Default 500 MB to avoid heavy processing on very large traces. Set to 0 to disable the size-based shortcut.
    /// </summary>
    public static long EtlLargeFileQuickScanBytes { get; set; } = 500_000_000;
}

/// <summary>
/// Controls how vendor names in AllowedVendors are matched.
/// </summary>
public enum VendorMatchMode
{
    /// <summary>Case-insensitive substring match (default).</summary>
    Contains = 0,
    /// <summary>Case-insensitive full equality.</summary>
    Exact = 1
}
