# File reports and local analysis

`FileInspector.AnalyzeReport` answers what a file contains using the existing
detector, bounded readers and plain language observations linked to evidence.
It never executes scripts, opens documents in Office or sends content to a service.

## Report contract

Schema version 1 contains `File`, `Analysis`, `Content` and `Observations`.
`File` records the display name, exact byte length and whole-input SHA-256.
`Analysis` retains detection, validation, learned-classifier evidence when requested,
signatures and typed stage outcomes. `Content` records the reader, text, metadata,
archive inventory and explicit issues. Each observation points to a supporting field.

The producer version and UTC creation time accompany every report. Consumers should
check `SchemaVersion` before interpreting a saved report. `Outcome` is partial when
either existing analysis or the content reader is limited. A detected type is not
structural validation, and successful completion is not a safety verdict.

On .NET 8, the inbox `System.Text.Json` reflection serializer can save and read
`InspectionReport` while preserving immutable stage outcomes and optional metrics.
The local application's JSON uses camel-case properties and string enums. Use
`JsonSerializerDefaults.Web` with `JsonStringEnumConverter` when reading those
exports. Other target frameworks expose the same report data; serializer integration
on those targets is consumer-owned and is not qualified by this implementation.

```csharp
var options = new InspectionReportOptions {
    MaxInputBytes = 64 * 1024 * 1024,
    MaxTextCharacters = 64 * 1024,
    Detection = new FileInspector.DetectionOptions { IncludePermissions = false }
};
using var input = File.OpenRead("report.xlsx");
var report = FileInspector.AnalyzeReport(input, "report.xlsx", options);
Console.WriteLine(report.Content.Metadata["SheetNames"]);
Console.WriteLine(report.Outcome);
```

The reader buffers a bounded snapshot so identity and extraction refer to the same
bytes. Seekable input is read from zero and restored to its original position;
forward-only input consumes the remaining content. The caller's stream stays open.
The default input limit is 64 MiB. The text limit is 64 Ki characters, ZIP/TAR inventory
limit 256 entries, expanded member limit 1 MiB, and total expanded read limit 16 MiB.
Existing archive-directory, compression-ratio and XML depth/DTD safeguards apply.
Oversized input throws `InvalidDataException`; cancellation propagates.

Reports force certificate chain checks offline, including signers inside archives.
On .NET 8, issuer downloads are disabled and trust depends on locally available
certificates. On older targets, offline chain trust remains unknown and the report
records `cert:offline-chain-validation-unavailable`. Envelope signature verification
and certificate metadata remain available; neither establishes package integrity.

| Reader | Available content | Boundary |
| --- | --- | --- |
| UTF text | Text sample, encoding, sampled lines, frequent words | Invalid encodings and truncation are explicit |
| Word OOXML | Main-document paragraphs and table count | No revisions, headers, drawings or layout |
| Excel OOXML | Sheet names, stored values, shared/inline strings, formulas | No formula execution, formatting or calculation |
| PowerPoint OOXML | Stored slide text, sampled slides | No notes, embedded objects or rendering; part order is lexical |
| ZIP/TAR | Bounded member inventory and whole-member SHA-256 where available | No filesystem extraction; larger/unread members have no hash |
| PNG/GIF/JPEG | Header format and dimensions where present | Header claims only; pixels, OCR and metadata are uninspected |
| PDF | Existing direct lexical inspection signals | No text extraction, page-tree traversal or compressed-object interpretation |
| Other formats | Existing detection/analysis | Content reader explicitly unavailable |

The OOXML readers accept Transitional and Strict namespaces. Unsupported package
XML namespaces are reported explicitly.

`ReportSimilarity.Compare` returns 1 for exact-byte equality. Otherwise it estimates
overlap of three-word shingles in extracted text using a deterministic 128-hash
sample. It returns null when text is insufficient. Scores describe extracted samples,
which may be truncated or omit parts; they do not prove semantic equivalence or
binary similarity. Frequent words are word frequencies rather than inferred purpose.

## Batch diagnostics

`AnalyzeReports(paths)` yields one `ReportBatchItem` for every supplied path. Read and
size failures keep their source and stable issue code. `AnalyzeDirectoryReports`
also reports enumeration failures and skipped directory/file links. Its sources are
relative to the scan root. The older analysis APIs retain compatibility behavior;
`FileAnalysis.SourceName` exposes a basename for result correlation.

## Local application

```bash
dotnet run --project FileInspectorX.Web -- --Port 5088 --DataDirectory ./local-catalog
```

Open the private link printed at startup. Its fragment contains a random access
token for this running instance; keep the link private. The browser clears the
fragment and retains access in its tab session. Restarting the host invalidates
the old link. The application uses only the .NET 8 runtime and existing
core references, with no ASP.NET shared framework or new packages. It accepts raw
uploads, queues work, and exposes searchable reports. Names and file-derived text
are rendered as text; they cannot introduce markup into the page.

On Windows, `HttpListener` uses HTTP.sys URL permissions. If startup reports access
denied, an administrator can reserve the exact loopback prefix for the account that
will run the application, then run the application under that ordinary account:

```powershell
netsh http add urlacl url=http://127.0.0.1:5088/ user="DOMAIN\User" listen=yes delegate=no
```

Use the actual account and selected port; inspect existing reservations before
changing them. The application does not change URL permissions automatically.
See [Microsoft's URL reservation documentation](https://learn.microsoft.com/en-us/windows/win32/http/add-urlacl).

Accepted requests have a 30-second deadline. The host closes stalled connections
and removes unfinished uploads so later uploads can proceed. Error responses to
requests with a body close the connection. Uploads canceled before publication
are discarded. If an upload response fails after publication, check the report
list before uploading again; its job may already be queued or running.

Each queued analysis runs in a separate child process. The host stops workers after
30 seconds or when an observed working set exceeds 512 MiB. That memory check is
sampled rather than a hard OS limit. Workers retain the user's OS permissions.
Worker output is limited to 16 MiB and travels through a pipe; only the live host
publishes report files. A surviving worker cannot recreate a deleted catalog report.
The host accepts up to 16 queued jobs and 200 retained jobs, with a conservative
512 MiB uploaded-content budget. Failed/interrupted jobs remain visible; queued and
running jobs become failed on restart and can be uploaded again. The catalog has a
single-process ownership lock.
On startup, generated uploads and reports without job metadata, interrupted report
output and stale temporary writes are removed before new uploads are admitted.

The default catalog is under the user's local application-data folder in
`FileInspectorX/local-reports`. Use a protected directory for a custom catalog.
On Unix the catalog directory is restricted to its owner; Windows uses the chosen
folder's ACL inheritance. Uploads, names and extracted content are sensitive data.
The application retains them until the user chooses **Delete file and report**.
Deletion removes both the upload and report. There is no public sharing endpoint.

The host binds `127.0.0.1`, validates the host header and requires the instance's
secret bearer token for every API read and mutation. Mutations also require a
custom client header and reject cross-origin writes. CSP restricts scripts/assets to the
local application. These controls do not make it suitable for untrusted public
uploads or protect against another process running as the same user. Network
deployment needs authentication, authorization, tenant separation, retention policy,
strong OS resource isolation and a reviewed hosting boundary.

## HTTP API

| Request | Result |
| --- | --- |
| `POST /api/uploads` | Raw bytes with `X-File-Name`; returns queued job with ID |
| `GET /api/reports?q=...` | Jobs matching name, exact hash, extracted text, type or keywords |
| `GET /api/reports/{id}` | Current job state or completed schema-v1 JSON |
| `GET /api/hash/{sha256}` | Matching local uploads; names may differ for identical bytes |
| `GET /api/reports/{id}/similar` | Exact-byte/text-sample matches, with basis and score |
| `DELETE /api/reports/{id}` | Removes completed/failed job, upload and report; active jobs reject deletion |

All API requests require `Authorization: Bearer <token>`, using the token from the
private startup link. Mutation requests also require `X-FileInspector-Client: local`. Browser uploads encode
Unicode names as percent-encoded UTF-8 and set `X-File-Name-Encoded: uri`; ASCII
clients can send the name directly. Names are display data; the storage path always
uses a generated ID. Reports do not expose the catalog's physical paths.

```powershell
$token = Read-Host 'Token from the private startup link'
$headers = @{ Authorization = "Bearer $token"; 'X-FileInspector-Client' = 'local'; 'X-File-Name' = 'sample.txt' }
$job = Invoke-RestMethod -Uri 'http://127.0.0.1:5088/api/uploads' -Method Post `
    -Headers $headers -ContentType 'application/octet-stream' -InFile './sample.txt'
Invoke-RestMethod -Uri "http://127.0.0.1:5088/api/reports/$($job.id)" -Headers $headers
```

For validation, `Build/Test-LocalService.ps1` exercises the live upload/worker/report,
search, exact similarity, name encoding, origin controls and deletion contracts.
`Build/Test-CatalogRecovery.ps1` checks interrupted uploads and stored report
publication; `Build/Test-LocalServiceDeadlines.ps1` checks stalled request cleanup
and service cancellation. CI runs these checks on Windows, Linux and macOS.
Deeper engine options and the evidence needed before adoption are in the
[dependency assessment](dependency-assessment.md).
