param(
    [Parameter(Mandatory)][string] $ApplicationPath,
    [string] $ScratchDirectory = (Join-Path ([IO.Path]::GetTempPath()) ('FileInspectorX-service-' + [guid]::NewGuid().ToString('N')))
)
$ErrorActionPreference = 'Stop'
$application = (Resolve-Path -LiteralPath $ApplicationPath).Path
$scratch = [IO.Path]::GetFullPath($ScratchDirectory)
if (Test-Path -LiteralPath $scratch) { throw 'Use a new scratch directory for this smoke test.' }
[IO.Directory]::CreateDirectory($scratch) | Out-Null
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = $listener.LocalEndpoint.Port
$listener.Stop()
$base = "http://127.0.0.1:$port"
$headers = @{ 'X-FileInspector-Client' = 'local'; 'X-File-Name' = 'invoices.txt' }
$process = $null
function Assert-Service([bool] $Condition, [string] $Message) { if (!$Condition) { throw $Message } }
function Wait-Report([string] $Id) {
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        $result = Invoke-RestMethod -Uri "$base/api/reports/$Id"
        if ($result.schemaVersion) { return $result }
        if ($result.state -eq 'failed') { throw $result.error }
        Start-Sleep -Milliseconds 300
    }
    throw 'Analysis did not finish within the smoke-test budget.'
}
try {
    $start = [Diagnostics.ProcessStartInfo]::new((Get-Command dotnet).Source)
    $start.UseShellExecute = $false
    $start.ArgumentList.Add($application)
    $start.ArgumentList.Add('--Port')
    $start.ArgumentList.Add([string]$port)
    $start.ArgumentList.Add('--DataDirectory')
    $start.ArgumentList.Add((Join-Path $scratch 'catalog'))
    $process = [Diagnostics.Process]::Start($start)
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        if ($process.HasExited) { throw 'Local service exited during startup.' }
        try { $null = Invoke-RestMethod -Uri "$base/api/reports"; $ready = $true; break } catch { Start-Sleep -Milliseconds 250 }
    }
    Assert-Service $ready 'Local service did not start.'
    $page = Invoke-WebRequest -Uri $base
    Assert-Service ($page.Content.Contains('Understand a file without running it.')) 'UI was not served.'
    Assert-Service (($page.Headers['Content-Security-Policy'] -join ';') -like "*script-src 'self'*") 'CSP is missing.'
    $body = [Text.Encoding]::UTF8.GetBytes('Quarterly customer invoices summarize revenue from consulting work and subscription renewals.')
    $first = Invoke-RestMethod -Uri "$base/api/uploads" -Method Post -Headers $headers -ContentType 'application/octet-stream' -Body $body
    $report = Wait-Report $first.id
    Assert-Service ($report.schemaVersion -eq 1 -and $report.file.name -eq 'invoices.txt') 'Report identity contract failed.'
    Assert-Service ($report.content.text.Contains('customer invoices')) 'Text extraction failed.'
    Assert-Service ($report.file.sha256.Length -eq 64) 'Whole-file hash is missing.'
    $lookup = @(Invoke-RestMethod -Uri "$base/api/hash/$($report.file.sha256)")
    Assert-Service ($lookup.Count -eq 1 -and $lookup[0].id -eq $first.id) 'Hash lookup failed.'
    $decoyHeaders = @{ 'X-FileInspector-Client' = 'local'; 'X-File-Name' = "$($report.file.sha256).txt" }
    $decoy = Invoke-RestMethod -Uri "$base/api/uploads" -Method Post -Headers $decoyHeaders -ContentType 'application/octet-stream' -Body ([Text.Encoding]::UTF8.GetBytes("Reference digest: $($report.file.sha256)"))
    $null = Wait-Report $decoy.id
    $lookup = @(Invoke-RestMethod -Uri "$base/api/hash/$($report.file.sha256.ToUpperInvariant())")
    Assert-Service ($lookup.Count -eq 1 -and $lookup[0].id -eq $first.id) 'Hash lookup matched a name or text instead of exact bytes.'
    $search = @(Invoke-RestMethod -Uri "$base/api/reports?q=consulting")
    Assert-Service ($search.Count -eq 1) 'Extracted-text search failed.'
    $second = Invoke-RestMethod -Uri "$base/api/uploads" -Method Post -Headers $headers -ContentType 'application/octet-stream' -Body $body
    $null = Wait-Report $second.id
    $similar = @(Invoke-RestMethod -Uri "$base/api/reports/$($first.id)/similar")
    Assert-Service ($similar.Count -eq 1 -and $similar[0].basis -eq 'exact-bytes' -and $similar[0].score -eq 1) 'Exact similarity failed.'
    $unicode = @{ 'X-FileInspector-Client' = 'local'; 'X-File-Name' = [uri]::EscapeDataString('zażółć[1].txt'); 'X-File-Name-Encoded' = 'uri' }
    $third = Invoke-RestMethod -Uri "$base/api/uploads" -Method Post -Headers $unicode -ContentType 'application/octet-stream' -Body $body
    Assert-Service ((Wait-Report $third.id).file.name -eq 'zażółć[1].txt') 'Unicode/literal upload name failed.'
    $hostileHeaders = @{ 'X-FileInspector-Client' = 'local'; 'X-File-Name' = 'hostile.txt'; 'Origin' = 'https://example.invalid' }
    $denied = Invoke-WebRequest -Uri "$base/api/uploads" -Method Post -Headers $hostileHeaders -Body $body -SkipHttpErrorCheck
    Assert-Service ($denied.StatusCode -eq 403) 'Cross-origin upload was allowed.'
    $denied = Invoke-WebRequest -Uri "$base/api/uploads" -Method Post -Body $body -SkipHttpErrorCheck
    Assert-Service ($denied.StatusCode -eq 403) 'Mutation without the client header was allowed.'
    Invoke-RestMethod -Uri "$base/api/reports/$($first.id)" -Method Delete -Headers $headers | Out-Null
    Assert-Service (!(Test-Path -LiteralPath (Join-Path $scratch "catalog/$($first.id).upload"))) 'Deleting a report retained its upload.'
    Assert-Service (!(Test-Path -LiteralPath (Join-Path $scratch "catalog/$($first.id).report.json"))) 'Deleting a report retained its extracted content.'
    Write-Output 'Local service smoke passed: upload, queue/worker, report, text search, hash lookup, similarity, Unicode names, origin protection and deletion.'
}
finally {
    if ($process -and !$process.HasExited) { $process.Kill($true); $process.WaitForExit() }
    # Keep the exact task-owned scratch path available to the invoking agent/CI for scoped cleanup.
    Write-Output "Service smoke scratch: $scratch"
}
