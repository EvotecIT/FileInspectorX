---
external help file: FileInspectorX-help.xml
Module Name: FileInspectorX
online version: https://github.com/EvotecIT/FileInspectorX
schema: 2.0.0
---
# Get-FileInsight
## SYNOPSIS
Analyzes files and returns a full FileAnalysis object by default, with optional compact views.

## SYNTAX
### Path (Default)
```powershell
Get-FileInsight [-Path] <string[]> [-View <InsightView>] [-ReportReader <string>] [-DetectOnly] [-ComputeSha256] [-CollectMetrics] [-MagicHeaderBytes <int>] [-ExcludePermissions] [-ExcludeSignature] [-ExcludeReferences] [-ExcludeInstaller] [-EnableInstaller] [-ExcludeContainer] [-ExcludeAssessment] [-ExcludeShellProperties] [-EnableShellProperties] [-DisableMagika] [-MagikaPredictionMode <string>] [-LearnedClassificationMode <LearnedClassificationMode>] [<CommonParameters>]
```

### LiteralPath
```powershell
Get-FileInsight [-LiteralPath] <string[]> [-View <InsightView>] [-ReportReader <string>] [-DetectOnly] [-ComputeSha256] [-CollectMetrics] [-MagicHeaderBytes <int>] [-ExcludePermissions] [-ExcludeSignature] [-ExcludeReferences] [-ExcludeInstaller] [-EnableInstaller] [-ExcludeContainer] [-ExcludeAssessment] [-ExcludeShellProperties] [-EnableShellProperties] [-DisableMagika] [-MagikaPredictionMode <string>] [-LearnedClassificationMode <LearnedClassificationMode>] [<CommonParameters>]
```

### FileInfo
```powershell
Get-FileInsight -InputObject <FileInfo> [-View <InsightView>] [-ReportReader <string>] [-DetectOnly] [-ComputeSha256] [-CollectMetrics] [-MagicHeaderBytes <int>] [-ExcludePermissions] [-ExcludeSignature] [-ExcludeReferences] [-ExcludeInstaller] [-EnableInstaller] [-ExcludeContainer] [-ExcludeAssessment] [-ExcludeShellProperties] [-EnableShellProperties] [-DisableMagika] [-MagikaPredictionMode <string>] [-LearnedClassificationMode <LearnedClassificationMode>] [<CommonParameters>]
```

## DESCRIPTION
Supply one or more existing file paths, or pipe files from Get-ChildItem. Directories are enumerated with Get-ChildItem -File before analysis.

Path expands wildcard patterns. LiteralPath preserves wildcard characters in file names, and FileInfo pipeline input is always resolved literally.

By default (-View Raw), returns FileAnalysis with detection, flags, permissions (unless excluded), signatures, references and assessment. Use -View to select Summary, Detection, Analysis, Permissions, Signature, References, Assessment, Policy, Installer or ShellProperties; these views expose Raw for drill-down. Report returns the versioned InspectionReport contract with exact byte identity, bounded extracted content and coverage evidence.

The Report view reads a stable snapshot limited to 64 MiB per file. Larger files produce a per-file error. Content extraction retains at most 64 Ki characters and records limit issues. Report analysis is portable; requested filesystem-only stages are reported as unavailable.

Report uses the bundled OfficeIMO reader for supported documents, image metadata and passive CAB/MSI files. Use -ReportReader Builtin to select the core readers. OfficeIMO native input is limited to 32 MiB; OCR, rendering, legacy conversion and formula calculation are not performed. Native resource failures are per-file errors.

Installer metadata requires -EnableInstaller, and Windows shell properties require -EnableShellProperties. Selecting a view does not enable those parsers. MSI properties require a file path on Windows; APPX/MSIX and VSIX manifests can be read on every supported platform. Native parsers process input in the current process.

## EXAMPLES

### EXAMPLE 1
```powershell
Get-FileInsight -Path .\sample.txt
```

Analyze a single file

### EXAMPLE 2
```powershell
Get-FileInsight -Path .\payload.bin -DetectOnly
```

Detect only (no analysis)

### EXAMPLE 3
```powershell
Get-ChildItem -Filter *.exe -File -Recurse | Get-FileInsight -View Detection
```

Detect only for all EXE files under current directory

### EXAMPLE 4
```powershell
Get-ChildItem -File -Recurse | Get-FileInsight -View Summary -ExcludeSignature
```

Summarize a directory without signature enrichment

### EXAMPLE 5
```powershell
Get-FileInsight -Path .\app.exe -ComputeSha256 -MagicHeaderBytes 16
```

Include SHA-256 and first 16 bytes header (hex)

### EXAMPLE 6
```powershell
Get-FileInsight -Path .\source.txt -View Detection
```

Use the default Magika-assisted detection while preserving deterministic validators

### EXAMPLE 7
```powershell
Get-FileInsight -Path .\source.txt -DisableMagika -View Detection
```

Run deterministic-only detection without Magika

### EXAMPLE 8
```powershell
Get-FileInsight -LiteralPath '.\report[1].json' -View Detection
```

Inspect a file whose name contains brackets

### EXAMPLE 9
```powershell
Get-FileInsight -LiteralPath .\document.docx -View Report -ExcludePermissions
```

Get a versioned content report with hashes and bounded text extraction

### EXAMPLE 10
```powershell
Get-FileInsight -Path .\package.msi -View Installer -EnableInstaller
```

Read MSI product metadata on Windows without installing the package. The package can target x86, x64 or ARM64.

### EXAMPLE 11
```powershell
Get-FileInsight -Path .\package.msix -View Installer -EnableInstaller
```

Read an MSIX manifest

### EXAMPLE 12
```powershell
Get-FileInsight -Path .\source.txt -CollectMetrics
```

Collect read counters and stage timings on the full analysis

## PARAMETERS

### -CollectMetrics
Capture per-operation read, hash, archive and classifier counters and stage timings.

```yaml
Type: SwitchParameter
Parameter Sets: Path, LiteralPath, FileInfo
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ComputeSha256
Compute SHA-256 of the file and include in output.

```yaml
Type: SwitchParameter
Parameter Sets: Path, LiteralPath, FileInfo
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DetectOnly
Return only detection result (skip analysis). Back-compat shim for -View Detection.

```yaml
Type: SwitchParameter
Parameter Sets: Path, LiteralPath, FileInfo
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisableMagika
Disable the default Magika assistance and use deterministic analysis only.

```yaml
Type: SwitchParameter
Parameter Sets: Path, LiteralPath, FileInfo
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -EnableInstaller
Read MSI product properties on Windows and APPX/MSIX/VSIX manifests on all supported platforms. Pair with -View Installer to display them. Does not install or execute the package. -ExcludeInstaller takes precedence.

```yaml
Type: SwitchParameter
Parameter Sets: Path, LiteralPath, FileInfo
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -EnableShellProperties
Read Explorer Details through Windows shell property handlers. Requires Windows. Pair with -View ShellProperties to display them. -ExcludeShellProperties takes precedence.

```yaml
Type: SwitchParameter
Parameter Sets: Path, LiteralPath, FileInfo
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExcludeAssessment
Exclude assessment (score/decision/codes).

```yaml
Type: SwitchParameter
Parameter Sets: Path, LiteralPath, FileInfo
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExcludeContainer
Exclude container triage (ZIP/TAR sampling, subtype and inner hints).

```yaml
Type: SwitchParameter
Parameter Sets: Path, LiteralPath, FileInfo
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExcludeInstaller
Exclude installer/package metadata (MSIX/APPX/VSIX/MSI).

```yaml
Type: SwitchParameter
Parameter Sets: Path, LiteralPath, FileInfo
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExcludePermissions
Exclude permissions/ownership snapshot from the analysis.

```yaml
Type: SwitchParameter
Parameter Sets: Path, LiteralPath, FileInfo
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExcludeReferences
Exclude references extraction (Task XML, scripts.ini/xml).

```yaml
Type: SwitchParameter
Parameter Sets: Path, LiteralPath, FileInfo
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExcludeShellProperties
Exclude Windows shell properties (Explorer Details).

```yaml
Type: SwitchParameter
Parameter Sets: Path, LiteralPath, FileInfo
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExcludeSignature
Exclude signature/Authenticode and package signature analysis.

```yaml
Type: SwitchParameter
Parameter Sets: Path, LiteralPath, FileInfo
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -InputObject
FileInfo objects from Get-ChildItem or Get-Item. Their full names are resolved literally.

```yaml
Type: FileInfo
Parameter Sets: FileInfo
Aliases: None
Possible values:

Required: True
Position: named
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -LearnedClassificationMode
Failure behavior for the optional classifier. Assist records provider failures and continues;
Required reports a terminating per-file error.

```yaml
Type: LearnedClassificationMode
Parameter Sets: Path, LiteralPath, FileInfo
Aliases: None
Possible values: Off, Assist, Required

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LiteralPath
One or more file paths to analyze without interpreting wildcard characters. Accepts FullName or PSPath properties from pipeline objects.

```yaml
Type: String[]
Parameter Sets: LiteralPath
Aliases: FullName, PSPath, LP
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -MagicHeaderBytes
Capture first N bytes of the header as uppercase hex.

```yaml
Type: Int32
Parameter Sets: Path, LiteralPath, FileInfo
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MagikaPredictionMode
Magika probability policy. Defaults to HighConfidence.

```yaml
Type: String
Parameter Sets: Path, LiteralPath, FileInfo
Aliases: None
Possible values: HighConfidence, MediumConfidence, BestGuess

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Path
One or more existing file paths to analyze. Supports wildcard patterns and pipeline strings. FileInfo pipeline input is treated literally; use LiteralPath for names containing wildcard characters.

```yaml
Type: String[]
Parameter Sets: Path
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByValue, ByPropertyName)
Accept wildcard characters: False
```

### -ReportReader
Content reader for Report view: OfficeIMO uses the bundled native inspection adapter; Builtin uses the core readers.

```yaml
Type: String
Parameter Sets: Path, LiteralPath, FileInfo
Aliases: none
Possible values: OfficeIMO, Builtin

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -View
Output shape to emit. Defaults to Raw (full FileAnalysis object). Other values: Summary, Detection, Analysis, Permissions, Signature, References, Assessment, Policy, Installer, ShellProperties, Report. Report includes exact input identity and bounded content extraction, with a 64 MiB whole-input limit.

```yaml
Type: InsightView
Parameter Sets: Path, LiteralPath, FileInfo
Aliases: None
Possible values: Raw, Analysis, Detection, Permissions, Signature, Summary, References, Assessment, Installer, ShellProperties, Policy, Report

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

- `System.String[]`
- `System.IO.FileInfo`

## OUTPUTS

- `FileInspectorX.FileAnalysis`
- `FileInspectorX.AnalysisView`
- `FileInspectorX.DetectionView`
- `FileInspectorX.PermissionsView`
- `FileInspectorX.SignatureView`
- `FileInspectorX.SummaryView`
- `FileInspectorX.AssessmentView`
- `FileInspectorX.PolicySummaryView`
- `FileInspectorX.InstallerView`
- `FileInspectorX.ReferencesView`
- `FileInspectorX.ShellPropertiesView`
- `FileInspectorX.InspectionReport`

## RELATED LINKS

- AsyncPSCmdlet
