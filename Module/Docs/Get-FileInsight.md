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
Get-FileInsight [-Path] <string[]> [-View <InsightView>] [-DetectOnly] [-ComputeSha256] [-MagicHeaderBytes <int>] [-ExcludePermissions] [-ExcludeSignature] [-ExcludeReferences] [-ExcludeInstaller] [-ExcludeContainer] [-ExcludeAssessment] [-ExcludeShellProperties] [-DisableMagika] [-MagikaPredictionMode <string>] [-LearnedClassificationMode <LearnedClassificationMode>] [<CommonParameters>]
```

## DESCRIPTION
Analyzes files and returns a full FileAnalysis object by default, with optional compact views.

By default (-View Raw), returns the full FileAnalysis with detection, flags, permissions (unless excluded), signatures, installer metadata, references and assessment. Use -View to project compact views (Summary/Detection/Analysis/Permissions/Signature/References/Assessment/Installer/ShellProperties). Each view exposes Raw with the full FileAnalysis for drill-down.

## EXAMPLES

### EXAMPLE 1
```powershell
Get-FileInsight -Path @('C:\Path')
```


## PARAMETERS

### -ComputeSha256
Compute SHA-256 of the file and include in output.

```yaml
Type: SwitchParameter
Parameter Sets: Path
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
Parameter Sets: Path
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
Parameter Sets: Path
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
Parameter Sets: Path
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
Parameter Sets: Path
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
Parameter Sets: Path
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
Parameter Sets: Path
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
Parameter Sets: Path
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
Parameter Sets: Path
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
Parameter Sets: Path
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LearnedClassificationMode
Failure behavior for the optional classifier. Assist records provider failures and continues;
Required reports a terminating per-file error.

```yaml
Type: LearnedClassificationMode
Parameter Sets: Path
Aliases: None
Possible values: Off, Assist, Required

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MagicHeaderBytes
Capture first N bytes of the header as uppercase hex.

```yaml
Type: Int32
Parameter Sets: Path
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
Parameter Sets: Path
Aliases: None
Possible values: HighConfidence, MediumConfidence, BestGuess

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Path
One or more file paths to analyze. Accepts pipeline input of strings and resolves PowerShell provider paths.

```yaml
Type: String[]
Parameter Sets: Path
Aliases: FullName
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByValue, ByPropertyName)
Accept wildcard characters: False
```

### -View
Output shape to emit. Defaults to Raw (full FileAnalysis object). Other values: Summary, Detection, Analysis, Permissions, Signature, References, Assessment, Policy, Installer, ShellProperties.

```yaml
Type: InsightView
Parameter Sets: Path
Aliases: None
Possible values: Raw, Analysis, Detection, Permissions, Signature, Summary, References, Assessment, Installer, ShellProperties, Policy

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

## RELATED LINKS

- AsyncPSCmdlet
