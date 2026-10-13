#Requires -Version 7.4
param(
    [Parameter(Mandatory)][string] $ApplicationPath,
    [Parameter(Mandatory)][string] $ScratchDirectory
)
$ErrorActionPreference = 'Stop'
$application = (Resolve-Path -LiteralPath $ApplicationPath).Path
$scratch = [IO.Path]::GetFullPath($ScratchDirectory)
if (Test-Path -LiteralPath $scratch) { throw 'Use a new scratch directory for catalog recovery validation.' }
[IO.Directory]::CreateDirectory($scratch) | Out-Null
# Exercise the shipped catalog directly, without adding public hooks or a test-only project dependency.
$null = [Reflection.Assembly]::LoadFrom((Join-Path ([IO.Path]::GetDirectoryName($application)) 'FileInspectorX.dll'))
$assembly = [Reflection.Assembly]::LoadFrom($application)
$catalogType = $assembly.GetType('FileInspectorX.Web.Catalog', $true)
$binding = [Reflection.BindingFlags]::Instance -bor [Reflection.BindingFlags]::Public -bor [Reflection.BindingFlags]::NonPublic
$constructor = $catalogType.GetConstructor($binding, $null, [type[]]@([string]), $null)
function Open-Catalog([string] $Path) { return $constructor.Invoke([object[]]@($Path)) }
function Invoke-Catalog($Catalog, [string] $Name, [object[]] $Arguments = @()) {
    return $catalogType.GetMethod($Name, $binding).Invoke($Catalog, $Arguments)
}
function Assert-Catalog([bool] $Condition, [string] $Message) { if (!$Condition) { throw $Message } }
function Assert-Rejected([scriptblock] $Action, [string[]] $ExceptionNames) {
    try { $null = & $Action } catch {
        $cause = $_.Exception
        while ($cause) {
            if ($cause.GetType().Name -in $ExceptionNames) { return }
            $cause = $cause.InnerException
        }
        throw
    }
    throw "Expected $($ExceptionNames -join ' or ')."
}
function Write-Upload([string] $Root, [string] $Id, [long] $Size) {
    $stream = [IO.File]::Open((Join-Path $Root "$Id.upload"), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    try { $stream.SetLength($Size) } finally { $stream.Dispose() }
}
function Write-Job([string] $Root, [string] $Id, [string] $State, [long] $Size) {
    $job = @{ id = $Id; name = 'fixture.bin'; state = $State; sizeBytes = $Size; sha256 = ('a' * 64); createdUtc = [DateTimeOffset]::UtcNow.ToString('O') }
    [IO.File]::WriteAllText((Join-Path $Root "$Id.job.json"), ($job | ConvertTo-Json -Compress))
}
function Upload-One($Catalog) {
    $stream = [IO.MemoryStream]::new([byte[]]@(42))
    try {
        $task = Invoke-Catalog $Catalog 'Upload' ([object[]]@($stream, 'fixture.bin', [Threading.CancellationToken]::None))
        return $task.GetAwaiter().GetResult()
    } finally { $stream.Dispose() }
}
function Report-Bytes($Job, [string] $Hash = $Job.Sha256) {
    return ,([Text.Encoding]::UTF8.GetBytes((@{
        schemaVersion = 1; file = @{ name = $Job.Name; sizeBytes = $Job.SizeBytes; sha256 = $Hash }
        content = @{ text = 'fixture text'; keywords = @() }; analysis = @{}
    } | ConvertTo-Json -Depth 8 -Compress)))
}
$catalog = $null
$service = $null
$connection = $null
try {
    # Interrupt the supported upload path before the declared body has finished.
    $prefix = [Text.Encoding]::ASCII.GetBytes(('U' * 16384))
    $flushOpportunities = @(200, 500, 1000)
    $established = $false
    for ($fixtureAttempt = 0; $fixtureAttempt -lt $flushOpportunities.Count; $fixtureAttempt++) {
        $crashRoot = Join-Path $scratch ("interrupted-http-upload-{0}-{1}" -f ($fixtureAttempt + 1), [guid]::NewGuid().ToString('N'))
        $partial = $null
        try {
            $portReservation = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
            $portReservation.Start(); $port = $portReservation.LocalEndpoint.Port; $portReservation.Stop()
            $start = [Diagnostics.ProcessStartInfo]::new((Get-Command dotnet).Source)
            $start.UseShellExecute = $false; $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
            foreach ($argument in @($application, '--Port', [string]$port, '--DataDirectory', $crashRoot)) { $start.ArgumentList.Add($argument) }
            $service = [Diagnostics.Process]::Start($start)
            $startup = $service.StandardOutput.ReadLineAsync().WaitAsync([TimeSpan]::FromSeconds(15)).GetAwaiter().GetResult()
            if ($startup -notmatch '#token=([0-9A-Fa-f]{64})') { throw 'Service did not provide its private startup link.' }
            $accessToken = $Matches[1]
            $connection = [Net.Sockets.TcpClient]::new()
            $connection.Connect([Net.IPAddress]::Loopback, $port)
            $header = "POST /api/uploads HTTP/1.1`r`nHost: 127.0.0.1:$port`r`nAuthorization: Bearer $accessToken`r`nX-FileInspector-Client: local`r`nX-File-Name: interrupted.bin`r`nContent-Type: application/octet-stream`r`nContent-Length: 67108864`r`n`r`n"
            $network = $connection.GetStream()
            $network.Write([Text.Encoding]::ASCII.GetBytes($header))
            $network.Write($prefix); $network.Flush()
            for ($poll = 0; $poll -lt 100; $poll++) {
                # NTFS enumeration can report a stale live size. Observe only the path;
                # the authoritative byte check runs after the exclusive writer closes.
                $uploads = @(Get-ChildItem -LiteralPath $crashRoot -Filter '*.upload' -File -ErrorAction SilentlyContinue)
                Assert-Catalog ($uploads.Count -le 1) 'The interrupted request created unexpected upload artifacts.'
                if ($uploads.Count -eq 1) { $partial = $uploads[0]; break }
                if ($service.HasExited) { throw 'Service exited before the interrupted upload was retained.' }
                Start-Sleep -Milliseconds 100
            }
            Assert-Catalog ($null -ne $partial) 'The partial upload did not reach catalog storage.'
            Assert-Catalog ($partial.Name -cmatch '^[a-f0-9]{32}\.upload$') 'The interrupted request created an unexpected upload filename.'
            # Creation precedes the first write. Give the already-sent body a bounded
            # opportunity to persist, without treating elapsed time as byte evidence.
            Start-Sleep -Milliseconds $flushOpportunities[$fixtureAttempt]
            Assert-Catalog (!$service.HasExited) 'Service exited before controlled upload interruption.'
            Assert-Catalog (@(Get-ChildItem -LiteralPath $crashRoot -Filter '*.job.json').Count -eq 0) 'The interrupted fixture already had a committed job.'
            $service.Kill($true); $service.WaitForExit(); $service.Dispose(); $service = $null
            $connection.Dispose(); $connection = $null
            $partialBytes = [IO.File]::ReadAllBytes($partial.FullName)
            Assert-Catalog ($partialBytes.Length -le $prefix.Length) 'Termination retained more bytes than the interrupted HTTP body.'
            Assert-Catalog ($partialBytes.Where({ $_ -ne [byte][char]'U' }).Count -eq 0) 'Retained upload bytes did not match the interrupted HTTP body.'
            Assert-Catalog (@(Get-ChildItem -LiteralPath $crashRoot -Filter '*.job.json').Count -eq 0) 'Termination retained committed metadata for the interrupted body.'
            $established = $partialBytes.Length -ge 8192
        }
        finally {
            if ($connection) { $connection.Dispose(); $connection = $null }
            if ($service) { if (!$service.HasExited) { $service.Kill($true); $service.WaitForExit() }; $service.Dispose(); $service = $null }
            if (Test-Path -LiteralPath $crashRoot) {
                $catalog = Open-Catalog $crashRoot
                try {
                    Assert-Catalog (@(Get-ChildItem -LiteralPath $crashRoot -Force | Where-Object Name -ne 'catalog.lock').Count -eq 0) 'Restart retained generated artifacts from the interrupted HTTP attempt.'
                }
                finally { $catalog.Dispose(); $catalog = $null }
            }
        }
        if ($established) {
            Write-Output "Interrupted HTTP upload retained $($partialBytes.Length) verified body bytes without committed metadata (attempt $($fixtureAttempt + 1))."
            break
        }
        Write-Output "Interrupted HTTP fixture attempt $($fixtureAttempt + 1) retained only $($partialBytes.Length) matching body bytes; recovery cleaned its generated artifacts."
    }
    Assert-Catalog $established 'Could not establish an 8-16 KiB interrupted HTTP upload after three controlled attempts.'

    # A child produces JSON over its pipe and has no file destination to recreate after parent death.
    $childInput = Join-Path $scratch 'child-input.txt'
    [IO.File]::WriteAllText($childInput, 'Bounded child publication fixture.')
    $start = [Diagnostics.ProcessStartInfo]::new((Get-Command dotnet).Source)
    $start.UseShellExecute = $false; $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    foreach ($argument in @($application, '--worker', $childInput, 'child-input.txt')) { $start.ArgumentList.Add($argument) }
    $service = [Diagnostics.Process]::Start($start)
    $childJson = $service.StandardOutput.ReadToEndAsync().WaitAsync([TimeSpan]::FromSeconds(30)).GetAwaiter().GetResult()
    Assert-Catalog ($service.WaitForExit(5000) -and $service.ExitCode -eq 0) 'The standalone child did not complete.'
    $childReport = $childJson | ConvertFrom-Json
    Assert-Catalog ($childReport.schemaVersion -eq 2 -and $childReport.file.name -eq 'child-input.txt') 'Child stdout did not contain its report.'
    Assert-Catalog (@(Get-ChildItem -LiteralPath $scratch -Filter '*.report.json*').Count -eq 0) 'The child wrote report files without a catalog owner.'
    $service.Dispose(); $service = $null

    $recovery = Join-Path $scratch 'recovery'
    [IO.Directory]::CreateDirectory($recovery) | Out-Null
    $orphanIds = @(1..9 | ForEach-Object { [guid]::NewGuid().ToString('N') })
    foreach ($id in $orphanIds) { Write-Upload $recovery $id (64MB) }
    # Exact state of a process terminated while receiving uploads: generated blobs without published metadata.
    [IO.File]::WriteAllText((Join-Path $recovery "$($orphanIds[0]).job.json.tmp"), '{unfinished')
    [IO.File]::WriteAllText((Join-Path $recovery "$($orphanIds[1]).report.json"), 'orphan extracted content')
    [IO.File]::WriteAllText((Join-Path $recovery "$($orphanIds[1]).report.json.tmp"), 'unfinished content')
    $interrupted = [guid]::NewGuid().ToString('N')
    Write-Upload $recovery $interrupted 8
    Write-Job $recovery $interrupted 'running' 8
    [IO.File]::WriteAllText((Join-Path $recovery "$interrupted.report.json"), 'uncommitted report')
    [IO.File]::WriteAllText((Join-Path $recovery "$interrupted.report.json.tmp"), 'unfinished report')
    $unrelated = @('notes.upload', ($orphanIds[0] + '.upload.backup'), ('ABCDEF' + $orphanIds[0].Substring(6) + '.upload'))
    foreach ($name in $unrelated) { [IO.File]::WriteAllText((Join-Path $recovery $name), 'preserve unrelated file') }
    $nested = Join-Path $recovery 'unrelated-directory'
    [IO.Directory]::CreateDirectory($nested) | Out-Null
    [IO.File]::WriteAllText((Join-Path $nested "$($orphanIds[0]).upload"), 'preserve nested file')
    $catalog = Open-Catalog $recovery
    Assert-Catalog (@(Invoke-Catalog $catalog 'List' ([object[]]@($null))).Count -eq 1) 'Recovery imported orphan uploads as jobs.'
    foreach ($id in $orphanIds) {
        foreach ($suffix in @('.upload', '.job.json.tmp', '.report.json', '.report.json.tmp')) {
            Assert-Catalog (!(Test-Path -LiteralPath (Join-Path $recovery ($id + $suffix)))) 'Recovery retained orphan or temporary generated content.'
        }
    }
    foreach ($name in $unrelated) { Assert-Catalog ([IO.File]::ReadAllText((Join-Path $recovery $name)) -eq 'preserve unrelated file') 'Recovery modified an unrelated filename.' }
    Assert-Catalog ([IO.File]::ReadAllText((Join-Path $nested "$($orphanIds[0]).upload")) -eq 'preserve nested file') 'Recovery traversed a subdirectory.'
    $failed = Invoke-Catalog $catalog 'Find' ([object[]]@($interrupted))
    Assert-Catalog ($failed.State -eq 'failed') 'An interrupted job was not made deletable.'
    Assert-Catalog (!(Test-Path -LiteralPath (Join-Path $recovery "$interrupted.report.json"))) 'Recovery retained an interrupted report.'
    # A report left by an older surviving worker remains ineligible for content search and similarity.
    [IO.File]::WriteAllText((Join-Path $recovery "$interrupted.report.json"), '{"schemaVersion":1,"content":{"text":"late-worker-sentinel"}}')
    Assert-Catalog (@(Invoke-Catalog $catalog 'List' ([object[]]@('late-worker-sentinel'))).Count -eq 0) 'Search exposed a non-completed report.'
    Assert-Catalog ((Invoke-Catalog $catalog 'Similar' ([object[]]@($interrupted))).Status -eq 404) 'Similarity exposed a non-completed report.'
    Assert-Catalog ((Invoke-Catalog $catalog 'Delete' ([object[]]@($interrupted))).Status -eq 204) 'Interrupted job deletion failed.'
    Assert-Catalog (!(Test-Path -LiteralPath (Join-Path $recovery "$interrupted.upload"))) 'Deletion retained interrupted input.'
    Assert-Catalog (!(Test-Path -LiteralPath (Join-Path $recovery "$interrupted.report.json"))) 'Deletion retained late report content.'

    $job = Upload-One $catalog
    Invoke-Catalog $catalog 'Update' ([object[]]@($job.Id, 'running', $null)) | Out-Null
    $valid = Report-Bytes $job
    Assert-Rejected { Invoke-Catalog $catalog 'PublishReport' ([object[]]@($job.Id, (Report-Bytes $job ('b' * 64)))) } 'InvalidDataException'
    Assert-Catalog (!(Test-Path -LiteralPath (Join-Path $recovery "$($job.Id).report.json"))) 'Mismatched identity was published.'
    # A real filesystem failure after report publication must roll back the exposed state/content.
    $blocked = Join-Path $recovery "$($job.Id).job.json.tmp"
    [IO.Directory]::CreateDirectory($blocked) | Out-Null
    Assert-Rejected { Invoke-Catalog $catalog 'PublishReport' ([object[]]@($job.Id, $valid)) } @('UnauthorizedAccessException', 'IOException')
    Assert-Catalog ((Invoke-Catalog $catalog 'Find' ([object[]]@($job.Id))).State -eq 'running') 'Metadata failure exposed completed state.'
    Assert-Catalog (!(Test-Path -LiteralPath (Join-Path $recovery "$($job.Id).report.json"))) 'Metadata failure retained published content.'
    [IO.Directory]::Delete($blocked)
    Invoke-Catalog $catalog 'PublishReport' ([object[]]@($job.Id, $valid)) | Out-Null
    Assert-Catalog ((Invoke-Catalog $catalog 'Find' ([object[]]@($job.Id))).State -eq 'completed') 'Valid publication did not complete the job.'
    Assert-Rejected { Invoke-Catalog $catalog 'PublishReport' ([object[]]@($job.Id, $valid)) } 'InvalidDataException'
    $oldOwner = $catalog
    $catalog.Dispose(); $catalog = $null
    $catalog = Open-Catalog $recovery
    Assert-Catalog ((Invoke-Catalog $catalog 'Find' ([object[]]@($job.Id))).State -eq 'completed') 'Completed publication did not survive restart.'
    Assert-Rejected { Invoke-Catalog $oldOwner 'PublishReport' ([object[]]@($job.Id, $valid)) } 'ObjectDisposedException'
    $catalog.Dispose(); $catalog = $null

    $quota = Join-Path $scratch 'quota'
    [IO.Directory]::CreateDirectory($quota) | Out-Null
    foreach ($index in 1..8) {
        $id = [guid]::NewGuid().ToString('N')
        Write-Upload $quota $id (64MB)
        Write-Job $quota $id 'failed' 1
    }
    $catalog = Open-Catalog $quota
    Assert-Rejected { Upload-One $catalog } 'CatalogFullException'
    Assert-Catalog (@(Get-ChildItem -LiteralPath $quota -Filter '*.upload').Count -eq 8) 'Failed quota admission retained another upload.'
    $catalog.Dispose(); $catalog = $null
    Write-Output 'Catalog recovery passed: real interrupted HTTP upload recovered, child pipe publication checked, 576 MiB of orphan uploads removed, temps/interrupted reports repaired, unrelated files preserved, retained-byte quota and atomic owner publication checked.'
}
finally {
    if ($connection) { $connection.Dispose() }
    if ($service) { if (!$service.HasExited) { $service.Kill($true); $service.WaitForExit() }; $service.Dispose() }
    if ($catalog) { $catalog.Dispose() }
    Write-Output "Catalog recovery scratch: $scratch (quota fixtures are sparse generated uploads)."
}
