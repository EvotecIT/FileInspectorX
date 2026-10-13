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
        $result = Invoke-RestMethod -Uri "$base/api/reports/$Id" -Headers $authHeaders
        if ($result.schemaVersion) { return $result }
        if ($result.state -eq 'failed') { throw $result.error }
        Start-Sleep -Milliseconds 300
    }
    throw 'Analysis did not finish within the smoke-test budget.'
}
function New-WaveFixture {
    $memory = [IO.MemoryStream]::new()
    $writer = [IO.BinaryWriter]::new($memory, [Text.Encoding]::UTF8, $true)
    try {
        $writer.Write([Text.Encoding]::ASCII.GetBytes('RIFF')); $writer.Write([int]192036)
        $writer.Write([Text.Encoding]::ASCII.GetBytes('WAVEfmt ')); $writer.Write([int]16)
        $writer.Write([uint16]1); $writer.Write([uint16]2); $writer.Write([int]48000); $writer.Write([int]192000)
        $writer.Write([uint16]4); $writer.Write([uint16]16)
        $writer.Write([Text.Encoding]::ASCII.GetBytes('data')); $writer.Write([int]192000); $writer.Write([byte[]]::new(192000))
        return ,$memory.ToArray()
    } finally { $writer.Dispose(); $memory.Dispose() }
}
function New-ArchiveFixture([string] $FirstName, [string] $SecondName) {
    $memory = [IO.MemoryStream]::new()
    try {
        $zip = [IO.Compression.ZipArchive]::new($memory, [IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            foreach ($name in @($FirstName, $SecondName)) {
                $stream = $zip.CreateEntry($name, [IO.Compression.CompressionLevel]::NoCompression).Open()
                try {
                    $bytes = [Text.Encoding]::UTF8.GetBytes('Nested invoice evidence, retained as inert text.')
                    $stream.Write($bytes, 0, $bytes.Length)
                } finally { $stream.Dispose() }
            }
        } finally { $zip.Dispose() }
        return ,$memory.ToArray()
    } finally { $memory.Dispose() }
}
try {
    $start = [Diagnostics.ProcessStartInfo]::new((Get-Command dotnet).Source)
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.ArgumentList.Add($application)
    $start.ArgumentList.Add('--Port')
    $start.ArgumentList.Add([string]$port)
    $start.ArgumentList.Add('--DataDirectory')
    $start.ArgumentList.Add((Join-Path $scratch 'catalog'))
    $process = [Diagnostics.Process]::Start($start)
    $startup = $process.StandardOutput.ReadLineAsync().WaitAsync([timespan]::FromSeconds(20)).GetAwaiter().GetResult()
    Assert-Service ($startup -match '#token=([A-F0-9]{64})$') 'Private startup link was not produced.'
    $authHeaders = @{ Authorization = 'Bearer ' + $Matches[1] }
    $headers.Authorization = $authHeaders.Authorization
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        if ($process.HasExited) { throw 'Local service exited during startup.' }
        try { $null = Invoke-RestMethod -Uri "$base/api/reports" -Headers $authHeaders; $ready = $true; break } catch { Start-Sleep -Milliseconds 250 }
    }
    Assert-Service $ready 'Local service did not start.'
    $page = Invoke-WebRequest -Uri $base
    Assert-Service ($page.Content.Contains('Understand a file without running it.')) 'UI was not served.'
    Assert-Service (($page.Headers['Content-Security-Policy'] -join ';') -like "*script-src 'self'*") 'CSP is missing.'
    $body = [Text.Encoding]::UTF8.GetBytes('Quarterly customer invoices summarize revenue from consulting work and subscription renewals.')
    $first = Invoke-RestMethod -Uri "$base/api/uploads" -Method Post -Headers $headers -ContentType 'application/octet-stream' -Body $body
    $report = Wait-Report $first.id
    Assert-Service ($report.schemaVersion -eq 2 -and $report.file.name -eq 'invoices.txt') 'Report identity contract failed.'
    Assert-Service ($report.content.text.Contains('customer invoices')) 'Text extraction failed.'
    Assert-Service ($report.file.sha256.Length -eq 64) 'Whole-file hash is missing.'
    $lookup = Invoke-RestMethod -Uri "$base/api/hash/$($report.file.sha256)" -Headers $authHeaders
    Assert-Service ($lookup.Count -eq 1 -and $lookup[0].id -eq $first.id) 'Hash lookup failed.'
    $decoyHeaders = @{ Authorization = $authHeaders.Authorization; 'X-FileInspector-Client' = 'local'; 'X-File-Name' = "$($report.file.sha256).txt" }
    $decoy = Invoke-RestMethod -Uri "$base/api/uploads" -Method Post -Headers $decoyHeaders -ContentType 'application/octet-stream' -Body ([Text.Encoding]::UTF8.GetBytes("Reference digest: $($report.file.sha256)"))
    $null = Wait-Report $decoy.id
    $lookup = Invoke-RestMethod -Uri "$base/api/hash/$($report.file.sha256.ToUpperInvariant())" -Headers $authHeaders
    Assert-Service ($lookup.Count -eq 1 -and $lookup[0].id -eq $first.id) 'Hash lookup matched a name or text instead of exact bytes.'
    $search = Invoke-RestMethod -Uri "$base/api/reports?q=consulting" -Headers $authHeaders
    Assert-Service ($search.Count -eq 1 -and $search[0].id -eq $first.id) 'Extracted-text search failed.'
    $second = Invoke-RestMethod -Uri "$base/api/uploads" -Method Post -Headers $headers -ContentType 'application/octet-stream' -Body $body
    $null = Wait-Report $second.id
    $duplicateLookup = Invoke-RestMethod -Uri "$base/api/hash/$($report.file.sha256)" -Headers $authHeaders
    Assert-Service ($duplicateLookup.Count -eq 2 -and $duplicateLookup.id -contains $first.id -and $duplicateLookup.id -contains $second.id) 'Hash lookup did not return exactly both uploads with matching bytes.'
    $similar = Invoke-RestMethod -Uri "$base/api/reports/$($first.id)/similar" -Headers $authHeaders
    Assert-Service ($similar.Count -eq 1 -and $similar[0].job.id -eq $second.id -and $similar[0].basis -eq 'exact-bytes' -and $similar[0].score -eq 1) 'Exact similarity failed.'
    $unicode = @{ Authorization = $authHeaders.Authorization; 'X-FileInspector-Client' = 'local'; 'X-File-Name' = [uri]::EscapeDataString('zażółć[1].txt'); 'X-File-Name-Encoded' = 'uri' }
    $third = Invoke-RestMethod -Uri "$base/api/uploads" -Method Post -Headers $unicode -ContentType 'application/octet-stream' -Body $body
    Assert-Service ((Wait-Report $third.id).file.name -eq 'zażółć[1].txt') 'Unicode/literal upload name failed.'
    $evidenceHeaders = @{ Authorization = $authHeaders.Authorization; 'X-FileInspector-Client' = 'local'; 'X-File-Name' = 'recording.wav' }
    $audio = Invoke-RestMethod -Uri "$base/api/uploads" -Method Post -Headers $evidenceHeaders -ContentType 'application/octet-stream' -Body (New-WaveFixture)
    $audioReport = Wait-Report $audio.id
    $sampleRate = @($audioReport.content.facts | Where-Object name -eq 'Audio.SampleRate')
    Assert-Service ($audioReport.content.reader -eq 'wave-metadata' -and $sampleRate.Count -eq 1 -and $sampleRate[0].value -eq '48000' -and $sampleRate[0].origin -eq 'Embedded' -and $sampleRate[0].source.byteOffset -eq 24) 'Located media evidence was lost in worker publication.'
    Assert-Service ($audioReport.content.issues -contains 'media:payload-not-decoded' -and $audioReport.content.regions.Count -gt 0) 'Media coverage or whole-region evidence is missing.'
    $evidenceHeaders['X-File-Name'] = 'members.zip'
    $archive = Invoke-RestMethod -Uri "$base/api/uploads" -Method Post -Headers $evidenceHeaders -ContentType 'application/octet-stream' -Body (New-ArchiveFixture 'first.txt' 'second.txt')
    $archiveReport = Wait-Report $archive.id
    Assert-Service ($archiveReport.content.entries.Count -eq 2 -and $archiveReport.content.entries[0].ordinal -eq 0 -and $archiveReport.content.entries[1].ordinal -eq 1) 'Archive source identity was lost.'
    foreach ($entry in $archiveReport.content.entries) {
        Assert-Service ($entry.report.schemaVersion -eq 2 -and $entry.sha256 -eq $entry.report.file.sha256 -and $entry.report.content.text.Contains('Nested invoice evidence')) 'Nested report evidence was lost in worker publication.'
    }
    $evidenceHeaders['X-File-Name'] = 'renamed-members.zip'
    $renamed = Invoke-RestMethod -Uri "$base/api/uploads" -Method Post -Headers $evidenceHeaders -ContentType 'application/octet-stream' -Body (New-ArchiveFixture 'renamed-first.txt' 'renamed-second.txt')
    $null = Wait-Report $renamed.id
    $archiveSimilar = Invoke-RestMethod -Uri "$base/api/reports/$($archive.id)/similar" -Headers $authHeaders
    Assert-Service ($archiveSimilar.Count -eq 1 -and $archiveSimilar[0].job.id -eq $renamed.id -and $archiveSimilar[0].basis -eq 'whole-archive-members' -and $archiveSimilar[0].score -eq 1) 'Whole-member comparison did not retain the expected identity.'
    $memberEvidence = @($archiveSimilar[0].evidence | Where-Object basis -eq 'whole-archive-members')
    Assert-Service ($memberEvidence.Count -eq 1 -and $memberEvidence[0].comparedLeft -eq 2 -and $memberEvidence[0].comparedRight -eq 2 -and $memberEvidence[0].matches.Count -eq 2 -and $memberEvidence[0].matches[0].leftName -eq 'first.txt' -and $memberEvidence[0].matches[0].rightName -eq 'renamed-first.txt') 'Comparison counts or member match explanations were lost.'
    $hostileHeaders = @{ Authorization = $authHeaders.Authorization; 'X-FileInspector-Client' = 'local'; 'X-File-Name' = 'hostile.txt'; 'Origin' = 'https://example.invalid' }
    $denied = Invoke-WebRequest -Uri "$base/api/uploads" -Method Post -Headers $hostileHeaders -Body $body -SkipHttpErrorCheck
    Assert-Service ($denied.StatusCode -eq 403) 'Cross-origin upload was allowed.'
    $denied = Invoke-WebRequest -Uri "$base/api/uploads" -Method Post -Headers $authHeaders -Body $body -SkipHttpErrorCheck
    Assert-Service ($denied.StatusCode -eq 403) 'Mutation without the client header was allowed.'
    foreach ($route in @('/api/reports', "/api/reports/$($first.id)", "/api/reports/$($first.id)/similar", "/api/hash/$($report.file.sha256)")) {
        $denied = Invoke-WebRequest -Uri ($base + $route) -SkipHttpErrorCheck
        Assert-Service ($denied.StatusCode -eq 403) "Unauthenticated catalog read was allowed: $route"
    }
    $denied = Invoke-WebRequest -Uri "$base/api/reports" -Headers @{ Authorization = 'Bearer ' + ('0' * 64) } -SkipHttpErrorCheck
    Assert-Service ($denied.StatusCode -eq 403) 'Incorrect catalog credential was accepted.'
    $denied = Invoke-WebRequest -Uri "$base/api/uploads" -Method Post -Headers @{ 'X-FileInspector-Client' = 'local'; 'X-File-Name' = 'unauthorized.txt' } -Body $body -SkipHttpErrorCheck
    Assert-Service ($denied.StatusCode -eq 403) 'A constant client header bypassed upload authentication.'
    $denied = Invoke-WebRequest -Uri "$base/api/reports/$($first.id)" -Method Delete -Headers @{ 'X-FileInspector-Client' = 'local' } -SkipHttpErrorCheck
    Assert-Service ($denied.StatusCode -eq 403) 'A constant client header bypassed deletion authentication.'
    Invoke-RestMethod -Uri "$base/api/reports/$($first.id)" -Method Delete -Headers $headers | Out-Null
    Assert-Service (!(Test-Path -LiteralPath (Join-Path $scratch "catalog/$($first.id).upload"))) 'Deleting a report retained its upload.'
    Assert-Service (!(Test-Path -LiteralPath (Join-Path $scratch "catalog/$($first.id).report.json"))) 'Deleting a report retained its extracted content.'
    Write-Output 'Local service smoke passed: upload, queue/worker, report v2, located media facts, nested reports, whole-member comparisons, text search, hash lookup, similarity, Unicode names, private catalog access, origin protection and deletion.'
}
finally {
    if ($process -and !$process.HasExited) { $process.Kill($true); $process.WaitForExit() }
    # Keep the exact task-owned scratch path available to the invoking agent/CI for scoped cleanup.
    Write-Output "Service smoke scratch: $scratch"
}
