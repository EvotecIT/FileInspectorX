#Requires -Version 7.4
param(
    [Parameter(Mandatory)][string] $ApplicationPath,
    [Parameter(Mandatory)][string] $ScratchDirectory
)
$ErrorActionPreference = 'Stop'
$application = (Resolve-Path -LiteralPath $ApplicationPath).Path
$scratch = [IO.Path]::GetFullPath($ScratchDirectory)
if (Test-Path -LiteralPath $scratch) { throw 'Use a new scratch directory for deadline validation.' }
[IO.Directory]::CreateDirectory($scratch) | Out-Null
$connections = [Collections.Generic.List[Net.Sockets.TcpClient]]::new()
$service = $null
$shutdownService = $null
$receipt = @{ result = 'running'; observations = @() }
function Assert-Deadline([bool] $Condition, [string] $Message) { if (!$Condition) { throw $Message } }
function Reserve-Port {
    $reservation = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try { $reservation.Start(); return $reservation.LocalEndpoint.Port } finally { $reservation.Stop() }
}
function Start-Service([string] $Executable, [string[]] $Arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new($Executable)
    $start.UseShellExecute = $false; $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::Start($start)
    try {
        $startup = $process.StandardOutput.ReadLineAsync().WaitAsync([TimeSpan]::FromSeconds(20)).GetAwaiter().GetResult()
        Assert-Deadline ($startup -match '#token=([0-9A-Fa-f]{64})$') 'The private startup link was not produced.'
        return @{ process = $process; token = $Matches[1]; errors = $process.StandardError.ReadToEndAsync() }
    } catch {
        if (!$process.HasExited) { $process.Kill($true); $process.WaitForExit() }
        $process.Dispose(); throw
    }
}
function Start-IncompleteUpload([int] $Port, [string] $Token, [string] $Name = 'incomplete.bin', [long] $DeclaredLength = 67108864, [bool] $KeepAlive = $false) {
    $client = [Net.Sockets.TcpClient]::new()
    $connections.Add($client)
    $client.Connect([Net.IPAddress]::Loopback, $Port)
    $network = $client.GetStream()
    $connectionHeader = if ($KeepAlive) { '' } else { "Connection: close`r`n" }
    $header = "POST /api/uploads HTTP/1.1`r`nHost: 127.0.0.1:$Port`r`nAuthorization: Bearer $Token`r`nX-FileInspector-Client: local`r`nX-File-Name: $Name`r`nContent-Type: application/octet-stream`r`nContent-Length: $DeclaredLength`r`n$connectionHeader`r`n"
    $network.Write([Text.Encoding]::ASCII.GetBytes($header))
    $network.Write([byte[]]::new(16384)); $network.Flush()
    return $client
}
function Assert-ConnectionClosed([Net.Sockets.TcpClient] $Client, [Diagnostics.Stopwatch] $Clock, [double] $LimitSeconds, [IO.Stream] $Network = $null, [switch] $RequireConnectionClose) {
    $buffer = [byte[]]::new(1024)
    $received = [IO.MemoryStream]::new()
    if (!$Network) { $Network = $Client.GetStream() }
    try {
        while ($true) {
            $remaining = $LimitSeconds - $Clock.Elapsed.TotalSeconds
            if ($remaining -le 0) { throw 'The incomplete request remained connected beyond its deadline.' }
            try {
                $read = $Network.ReadAsync($buffer, 0, $buffer.Length).WaitAsync([TimeSpan]::FromSeconds($remaining)).GetAwaiter().GetResult()
            } catch {
                $cause = $_.Exception
                $closed = $false; $expired = $false
                while ($cause) {
                    if ($cause.GetType().Name -in @('IOException', 'SocketException')) { $closed = $true }
                    if ($cause -is [TimeoutException]) { $expired = $true }
                    $cause = $cause.InnerException
                }
                if ($closed) { break }
                if ($expired) { throw 'The incomplete request remained connected beyond its deadline.' }
                throw
            }
            if ($read -eq 0) { break }
            $received.Write($buffer, 0, $read)
            Assert-Deadline ($received.Length -le 8192) 'An incomplete upload produced an unexpectedly large response.'
        }
        $reply = [Text.Encoding]::ASCII.GetString($received.ToArray())
        Assert-Deadline ($reply -notmatch '^HTTP/1\.[01] 2[0-9][0-9]') 'An incomplete upload was accepted after cancellation.'
        if ($RequireConnectionClose) {
            Assert-Deadline ($reply -match '(?im)^Connection:[^\r\n]*\bclose\b') 'A rejected request body did not receive Connection: close.'
        }
        if ($reply -match '^HTTP/1\.[01] ([0-9]{3})') { return [int]$Matches[1] }
        return 0
    } finally { $received.Dispose() }
}
function Get-UploadArtifacts([string] $CatalogRoot) {
    @(Get-ChildItem -LiteralPath $CatalogRoot -File | Where-Object { $_.Name -match '\.(upload|job\.json(?:\.tmp)?|report\.json(?:\.tmp)?)$' } | ForEach-Object {
        @{ name = $_.Name; bytes = $_.Length }
    })
}
function Assert-UploadDiscarded([string] $CatalogRoot, [Diagnostics.Stopwatch] $Clock, [double] $LimitSeconds, [Diagnostics.Process] $Process = $null) {
    # A transport close can precede the pending read's IO completion and rollback.
    # Observe owner cleanup within the same deadline; publication always fails immediately.
    $observation = @{ check = $receipt.activeCheck; transportClosedSeconds = [Math]::Round($Clock.Elapsed.TotalSeconds, 3); limitSeconds = $LimitSeconds; artifactsAtClose = @(Get-UploadArtifacts $CatalogRoot) }
    $receipt.observations += $observation
    while ($true) {
        $artifacts = @(Get-UploadArtifacts $CatalogRoot)
        $observation.remainingArtifacts = $artifacts
        Assert-Deadline (@($artifacts | Where-Object { $_.name -notlike '*.upload' }).Count -eq 0) 'Incomplete input published job metadata or a report.'
        if ($Process) {
            $observation.serviceExited = $Process.HasExited
            if ($Process.HasExited) { $observation.serviceExitCode = $Process.ExitCode }
            Assert-Deadline (!$Process.HasExited) 'The service exited before interrupted upload cleanup completed.'
        }
        Assert-Deadline ($Clock.Elapsed.TotalSeconds -lt $LimitSeconds) 'Incomplete input retained partial upload bytes beyond its cleanup deadline.'
        if ($artifacts.Count -eq 0) {
            $observation.cleanupCompletedSeconds = [Math]::Round($Clock.Elapsed.TotalSeconds, 3)
            return
        }
        Start-Sleep -Milliseconds 25
    }
}
function Stop-Service($Owner) {
    if (!$Owner) { return }
    if (!$Owner.process.HasExited) { $Owner.process.Kill($true); $Owner.process.WaitForExit() }
    $errors = $Owner.errors.GetAwaiter().GetResult()
    $Owner.process.Dispose()
    return $errors
}
try {
    $port = Reserve-Port
    $catalog = Join-Path $scratch 'catalog'
    $service = Start-Service (Get-Command dotnet).Source @($application, '--Port', [string]$port, '--DataDirectory', $catalog)
    $auth = @{ Authorization = 'Bearer ' + $service.token }
    $base = "http://127.0.0.1:$port"
    $null = Invoke-RestMethod -Uri "$base/api/reports" -Headers $auth -TimeoutSec 5
    foreach ($rejection in @(
        @{ check = 'unauthorized-unread-body'; token = ('0' * 64); name = 'fixture.bin'; length = 67108864; status = 403 },
        @{ check = 'bad-name-unread-body'; token = $service.token; name = ''; length = 67108864; status = 400 },
        @{ check = 'oversize-unread-body'; token = $service.token; name = 'fixture.bin'; length = 67108865; status = 413 }
    )) {
        $receipt.activeCheck = $rejection.check
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $client = Start-IncompleteUpload $port $rejection.token $rejection.name $rejection.length $true
        $status = Assert-ConnectionClosed $client $clock 5 -RequireConnectionClose
        Assert-Deadline ($status -eq $rejection.status) 'A rejected unread body did not produce its expected response.'
        $receipt.observations += @{ check = $rejection.check; seconds = [Math]::Round($clock.Elapsed.TotalSeconds, 2); status = $status }
        $client.Dispose(); $connections.Clear()
    }
    Assert-Deadline (@(Get-ChildItem -LiteralPath $catalog -Filter '*.upload').Count -eq 0) 'Early rejection retained upload bytes.'
    Assert-Deadline (@(Get-ChildItem -LiteralPath $catalog -Filter '*.job.json').Count -eq 0) 'Early rejection created upload metadata.'
    $null = Invoke-RestMethod -Uri "$base/api/reports" -Headers $auth -TimeoutSec 5
    # Closing the sending side before Content-Length is satisfied must not commit a prefix.
    $receipt.activeCheck = 'premature-body-eof'
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $client = Start-IncompleteUpload $port $service.token
    $network = $client.GetStream()
    do {
        $eofUpload = Get-ChildItem -LiteralPath $catalog -Filter '*.upload' | Select-Object -First 1
        if (!$eofUpload) {
            Assert-Deadline ($clock.Elapsed.TotalSeconds -lt 5) 'The EOF request never entered upload storage.'
            Start-Sleep -Milliseconds 25
        }
    } while (!$eofUpload)
    $eofId = [IO.Path]::GetFileNameWithoutExtension($eofUpload.Name)
    $receipt.eofUploadId = $eofId
    $client.Client.Shutdown([Net.Sockets.SocketShutdown]::Send)
    $null = Assert-ConnectionClosed $client $clock 5 $network
    Assert-UploadDiscarded $catalog $clock 5 $service.process
    $client.Dispose(); $connections.Clear()
    $receipt.observations += @{ check = 'premature-body-eof'; result = 'no uploaded prefix or job committed' }
    $clock = [Diagnostics.Stopwatch]::StartNew()
    # Fill all handler slots: one stalled body owns the upload gate; fifteen requests wait for it.
    $receipt.activeCheck = 'body-and-upload-gate-deadline'
    foreach ($index in 1..16) { $null = Start-IncompleteUpload $port $service.token }
    $partial = $null
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        $partial = Get-ChildItem -LiteralPath $catalog -Filter '*.upload' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($partial) { break }
        Start-Sleep -Milliseconds 50
    }
    Assert-Deadline ($null -ne $partial) 'The incomplete request never entered catalog upload storage.'
    foreach ($client in $connections) { $null = Assert-ConnectionClosed $client $clock 38 }
    $receipt.observations += @{ check = 'body-and-upload-gate-deadline'; seconds = [Math]::Round($clock.Elapsed.TotalSeconds, 2); connections = 16 }
    Assert-UploadDiscarded $catalog $clock 38 $service.process
    $null = Invoke-RestMethod -Uri "$base/api/reports" -Headers $auth -TimeoutSec 5
    $receipt.activeCheck = 'valid-next-upload-and-report'
    $headers = @{ Authorization = $auth.Authorization; 'X-FileInspector-Client' = 'local'; 'X-File-Name' = 'after-deadline.txt' }
    $body = [Text.Encoding]::UTF8.GetBytes('A valid upload succeeds after stalled requests expire.')
    $job = Invoke-RestMethod -Uri "$base/api/uploads" -Method Post -Headers $headers -ContentType 'application/octet-stream' -Body $body -TimeoutSec 5
    Assert-Deadline ($job.sizeBytes -eq $body.Length) 'The upload gate did not accept the next valid request.'
    $report = $null
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        $report = Invoke-RestMethod -Uri "$base/api/reports/$($job.id)" -Headers $auth -TimeoutSec 5
        if ($report.schemaVersion) { break }
        Assert-Deadline ($report.state -ne 'failed') 'The valid request failed after deadline cleanup.'
        Start-Sleep -Milliseconds 100
    }
    Assert-Deadline ($report.schemaVersion -eq 2 -and $report.content.text.Contains('valid upload succeeds')) 'The valid next upload did not produce its report.'
    Assert-Deadline (!(Test-Path -LiteralPath (Join-Path $catalog ($eofId + '.upload')))) 'The earlier EOF upload reappeared after the upload gate was released.'
    $listed = Invoke-RestMethod -Uri "$base/api/reports" -Headers $auth -TimeoutSec 5
    Assert-Deadline ($listed.Count -eq 1 -and $listed[0].id -eq $job.id) 'Incomplete input appeared in the catalog after the next valid upload.'
    $receipt.observations += @{ check = 'handler-and-upload-gates-released'; result = 'GET, valid upload and report succeeded' }
    $serviceErrors = Stop-Service $service; $service = $null
    [IO.File]::WriteAllText((Join-Path $scratch 'service-errors.txt'), $serviceErrors)
    foreach ($client in $connections) { $client.Dispose() }; $connections.Clear()

    # Model the backend contract where cancellation occurs with a successful EOF read.
    # The catalog must check cancellation before it durably publishes that input.
    $receipt.activeCheck = 'cancellation-at-final-eof'
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
public sealed class CancelAtEofStream : MemoryStream {
    private readonly CancellationTokenSource cancellation;
    public CancelAtEofStream(CancellationTokenSource cancellation) : base(new byte[] { 42 }) { this.cancellation = cancellation; }
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default) {
        int count = base.ReadAsync(buffer, token).GetAwaiter().GetResult();
        if (count == 0) cancellation.Cancel();
        return new ValueTask<int>(count);
    }
}
'@
    $null = [Reflection.Assembly]::LoadFrom((Join-Path ([IO.Path]::GetDirectoryName($application)) 'FileInspectorX.dll'))
    $assembly = [Reflection.Assembly]::LoadFrom($application)
    $binding = [Reflection.BindingFlags]::Public -bor [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Instance
    $catalogType = $assembly.GetType('FileInspectorX.Web.Catalog', $true)
    $constructor = $catalogType.GetConstructor($binding, $null, [type[]]@([string]), $null)
    $canceledRoot = [string](Join-Path $scratch 'canceled-eof-catalog')
    $owner = $constructor.Invoke([object[]]@($canceledRoot))
    $cancellation = [Threading.CancellationTokenSource]::new()
    $stream = [CancelAtEofStream]::new($cancellation)
    try {
        $task = $catalogType.GetMethod('Upload', $binding).Invoke($owner, [object[]]@($stream, 'canceled.bin', $cancellation.Token))
        $rejected = $false
        try { $null = $task.GetAwaiter().GetResult() } catch {
            $cause = $_.Exception
            while ($cause -and $cause -isnot [OperationCanceledException]) { $cause = $cause.InnerException }
            if (!$cause) { throw }; $rejected = $true
        }
        Assert-Deadline $rejected 'Cancellation at the final EOF read published an upload.'
        Assert-Deadline (@(Get-ChildItem -LiteralPath $canceledRoot -Filter '*.upload').Count -eq 0) 'Canceled EOF retained upload bytes.'
        Assert-Deadline (@(Get-ChildItem -LiteralPath $canceledRoot -Filter '*.job.json').Count -eq 0) 'Canceled EOF published metadata.'
        $receipt.observations += @{ check = 'cancellation-at-final-eof'; result = 'no bytes or metadata committed' }
    } finally { $stream.Dispose(); $cancellation.Dispose(); $owner.Dispose() }

    # Run the same production listener in a separate host with its real shutdown token.
    # This avoids platform-specific console-signal APIs and adds no production test hooks.
    $receipt.activeCheck = 'shutdown-pending-body'
    $shutdownHost = Join-Path $scratch 'shutdown-host.ps1'
    [IO.File]::WriteAllText($shutdownHost, @'
param([string] $Application, [int] $Port, [string] $CatalogRoot)
$ErrorActionPreference = 'Stop'
$null = [Reflection.Assembly]::LoadFrom((Join-Path ([IO.Path]::GetDirectoryName($Application)) 'FileInspectorX.dll'))
$assembly = [Reflection.Assembly]::LoadFrom($Application)
$binding = [Reflection.BindingFlags]::Public -bor [Reflection.BindingFlags]::NonPublic
$catalogType = $assembly.GetType('FileInspectorX.Web.Catalog', $true)
$constructor = $catalogType.GetConstructor(($binding -bor [Reflection.BindingFlags]::Instance), $null, [type[]]@([string]), $null)
$catalog = $constructor.Invoke([object[]]@($CatalogRoot))
$shutdown = [Threading.CancellationTokenSource]::new()
try {
    $shutdown.CancelAfter([TimeSpan]::FromSeconds(8))
    $method = $assembly.GetType('FileInspectorX.Web.LocalServer', $true).GetMethod('Run', ($binding -bor [Reflection.BindingFlags]::Static))
    $task = $method.Invoke($null, [object[]]@($Port, $catalog, $shutdown.Token))
    $task.GetAwaiter().GetResult()
} finally { $shutdown.Dispose(); $catalog.Dispose() }
'@)
    $port = Reserve-Port
    $shutdownCatalog = Join-Path $scratch 'shutdown-catalog'
    $pwshExecutable = (Get-Process -Id $PID).Path
    $shutdownService = Start-Service $pwshExecutable @('-NoProfile', '-File', $shutdownHost, '-Application', $application, '-Port', [string]$port, '-CatalogRoot', $shutdownCatalog)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $client = Start-IncompleteUpload $port $shutdownService.token
    $null = Assert-ConnectionClosed $client $clock 15
    Assert-Deadline ($shutdownService.process.WaitForExit(5000) -and $shutdownService.process.ExitCode -eq 0) 'Shutdown did not drain the canceled listener handler.'
    Assert-UploadDiscarded $shutdownCatalog $clock 15
    $receipt.observations += @{ check = 'shutdown-pending-body'; seconds = [Math]::Round($clock.Elapsed.TotalSeconds, 2); result = 'process exited cleanly; partial bytes removed' }
    $shutdownErrors = Stop-Service $shutdownService; $shutdownService = $null
    [IO.File]::WriteAllText((Join-Path $scratch 'shutdown-errors.txt'), $shutdownErrors)
    $receipt.result = 'passed'
    $receipt.Remove('activeCheck')
    Write-Output 'Local service deadlines passed: 16 stalled/serialized uploads expired, partial input was removed, valid GET/upload/report succeeded, and shutdown drained a pending body.'
} catch {
    $receipt.result = 'failed'; $receipt.failure = $_.Exception.Message
    throw "Deadline validation failed during '$($receipt.activeCheck)': $($_.Exception.Message)"
} finally {
    if ($service) { [IO.File]::WriteAllText((Join-Path $scratch 'service-errors.txt'), (Stop-Service $service)) }
    if ($shutdownService) { [IO.File]::WriteAllText((Join-Path $scratch 'shutdown-errors.txt'), (Stop-Service $shutdownService)) }
    foreach ($client in $connections) { $client.Dispose() }
    [IO.File]::WriteAllText((Join-Path $scratch 'deadline-receipt.json'), ($receipt | ConvertTo-Json -Depth 6))
    if ($receipt.result -eq 'failed') {
        # Keep timing/state evidence in CI logs even when artifact upload is skipped.
        Write-Output ('Deadline failure receipt: ' + ($receipt | ConvertTo-Json -Depth 6 -Compress))
        foreach ($log in @('service-errors.txt', 'shutdown-errors.txt')) {
            $path = Join-Path $scratch $log
            if (Test-Path -LiteralPath $path) {
                $errors = [IO.File]::ReadAllText($path)
                Write-Output ($log + ': ' + $errors.Substring(0, [Math]::Min(2048, $errors.Length)))
            }
        }
    }
    Write-Output "Deadline validation scratch: $scratch"
}
