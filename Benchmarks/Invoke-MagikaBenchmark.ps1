param(
    [Parameter(Mandatory)][string] $BaselineRoot,
    [Parameter(Mandatory)][string] $CandidateRoot,
    [Parameter(Mandatory)][string] $OutputRoot,
    [string] $CorpusPath = (Join-Path $PSScriptRoot '../FileInspectorX.Magika.Tests/Reference/standard_v3_3-inference_examples_by_content.json.gz'),
    [int] $Calls = 3
)
$ErrorActionPreference = 'Stop'
Import-Module PSPublishModule -MinimumVersion 3.0.153 -ErrorAction Stop
$contextPrefix = 'FileInspectorX-Magika-' + [guid]::NewGuid().ToString('N')
try {
    $result = Invoke-BenchmarkSuite -Path (Join-Path $PSScriptRoot 'magika.benchmark.ps1') -OutputRoot $OutputRoot -Variable @{
        BaselineRoot = [IO.Path]::GetFullPath($BaselineRoot)
        CandidateRoot = [IO.Path]::GetFullPath($CandidateRoot)
        CorpusPath = [IO.Path]::GetFullPath($CorpusPath)
        Calls = $Calls
        ContextPrefix = $contextPrefix
    }
    if (@($result.Samples | Where-Object Status -eq Failed).Count) { throw 'Provider benchmark validation failed.' }
    $result
} finally {
    # Native sessions must finish before their collectible dependency contexts unload.
    $cleanupErrors = [Collections.Generic.List[Exception]]::new()
    foreach ($context in [Runtime.Loader.AssemblyLoadContext]::All) {
        if ($context.Name -and $context.Name.StartsWith($contextPrefix + '-', [StringComparison]::Ordinal)) {
            try { $context.Dispose() } catch { $cleanupErrors.Add($_.Exception) }
        }
    }
    if ($cleanupErrors.Count) { throw [AggregateException]::new('Provider benchmark cleanup failed.', $cleanupErrors) }
}
