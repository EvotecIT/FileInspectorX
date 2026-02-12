namespace FileInspectorX;

public static partial class FileInspector
{
    private static void PopulateDetectionSummary(FileAnalysis res)
    {
        if (res == null) return;
        var d = res.Detection;
        if (d == null) return;

        res.DetectedExtension = string.IsNullOrWhiteSpace(d.Extension) ? null : d.Extension;
        res.DetectedMimeType = string.IsNullOrWhiteSpace(d.MimeType) ? null : d.MimeType;
        res.DetectionConfidence = string.IsNullOrWhiteSpace(d.Confidence) ? null : d.Confidence;
        res.DetectionReason = string.IsNullOrWhiteSpace(d.Reason) ? null : d.Reason;
        res.DetectionReasonDetails = string.IsNullOrWhiteSpace(d.ReasonDetails) ? null : d.ReasonDetails;
        res.DetectionValidationStatus = string.IsNullOrWhiteSpace(d.ValidationStatus) ? null : d.ValidationStatus;
        res.DetectionScore = d.Score;
        res.DetectionIsDangerous = d.IsDangerous;
    }
}
