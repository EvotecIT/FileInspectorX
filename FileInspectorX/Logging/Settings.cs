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
    /// When true on Windows, perform WinVerifyTrust policy verification for Authenticode (catalog-aware).
    /// </summary>
    public static bool VerifyAuthenticodeWithWinTrust { get; set; } = true;

    /// <summary>
    /// When true, attempt revocation checks during WinVerifyTrust (may require network, slower).
    /// </summary>
    public static bool VerifyAuthenticodeRevocation { get; set; } = false;

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
}

/// <summary>
/// Controls how vendor names in AllowedVendors are matched.
/// </summary>
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
