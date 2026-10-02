using System.Threading;

namespace FileInspectorX;

/// <summary>Reusable immutable settings and a named choice of inspection depth.</summary>
public sealed class InspectionProfile
{
    private readonly bool _detectOnly;
    private InspectionProfile(InspectionSettings settings, bool detectOnly)
    { Settings = settings ?? throw new ArgumentNullException(nameof(settings)); _detectOnly = detectOnly; }

    /// <summary>Settings shared safely by operations created from this profile.</summary>
    public InspectionSettings Settings { get; }

    /// <summary>Creates a detection-only profile using the supplied snapshot or captured legacy defaults.</summary>
    public static InspectionProfile Quick(InspectionSettings? settings = null) => new(settings ?? InspectionSettings.CaptureDefaults(), true);

    /// <summary>Creates a full best-effort profile with the snapshot's existing read and archive limits.</summary>
    public static InspectionProfile Bounded(InspectionSettings? settings = null) => new(settings ?? InspectionSettings.CaptureDefaults(), false);

    /// <summary>Enables nested container analysis within the snapshot's existing read, entry and depth limits.</summary>
    public static InspectionProfile Deep(InspectionSettings? settings = null)
        => new((settings ?? InspectionSettings.CaptureDefaults()) with { DeepContainerScanEnabled = true }, false);

    /// <summary>Creates fresh per-call options. Native installer and shell enrichment remain explicit opt-ins.</summary>
    public FileInspector.DetectionOptions CreateOptions(CancellationToken cancellationToken = default)
        => new() { Settings = Settings, DetectOnly = _detectOnly, CancellationToken = cancellationToken };
}
