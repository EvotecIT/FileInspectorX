# File reports and local analysis

`FileInspector.AnalyzeReport` answers what a file contains using the existing
detector, bounded readers and plain language observations linked to evidence.
It never executes scripts, opens documents in Office or sends content to a service.

## Report contract

Schema version 3 contains `File`, `Analysis`, `Content` and `Observations`.
`File` records the display name, exact byte length and whole-input SHA-256.
`Analysis` retains detection, validation, learned-classifier evidence when requested,
signatures and typed stage outcomes. `Content` records the reader, text, metadata,
archive inventory, typed facts, binary regions, extraction provenance, logical document
units, diagnostics and omissions. Each observation
points to a supporting field.

`InspectionReport.CurrentSchemaVersion` identifies the producer contract.
`InspectionReport.SupportsSchema(version)` accepts versions 1, 2 and 3; other versions
must be rejected. Saved version-1 reports retain their original evidence and can be
read by the local catalog or compared through either comparison API. Missing version-2
collections are empty, so a version-1 report does not acquire facts, regions or nested
reports merely by being loaded. Reports saved without an extraction descriptor retain
unknown provenance; a reader name alone does not establish text compatibility.

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

### Facts and source locations

Each `Content.Facts` record has a field `Name`, a `Kind` and an invariant string
`Value`. Media names include their format or field family, such as `Wave.Encoding`
or `Audio.Channels`; legacy metadata retains its existing field names.
The kind distinguishes text, integer, decimal, Boolean, timestamp,
URI and SHA-256 representations. `Origin` distinguishes embedded claims from derived
values; the contract also has default and inferred categories. Current media readers
emit embedded declarations and explicitly derived durations or counts. Legacy metadata
is projected as derived facts when a reader has no native fact records.

An optional `Source` identifies a container part or record and a zero-based byte offset
and length. `ByteSpace` distinguishes original `SnapshotBytes`, decoded `PartBytes`,
native `ProfileBytes` and `Unknown` coordinates. Snapshot offsets in a nested report
refer to that member's bytes. `LogicalSource` separately records document pages,
slides, sheets, cell ranges, stories and block or character coordinates. A logical
character position is never a snapshot byte offset. Some derived facts have no physical byte range. Locations
never contain the host's filesystem path. Duplicate tags can remain separate facts,
even when the compatibility `Metadata` dictionary cannot retain every occurrence.
Text prefixes set `Truncated`; numeric values that cannot fit are omitted rather than
shortened. Embedded dates, camera details, codec names and dimensions are file claims,
not proof of authenticity.

Native metadata object IDs are retained in `Source.Record`. When the native reader
provides no byte range, `ByteSpace` is `Unknown` and the offsets remain absent.
An object descriptor can have an empty `Value` while retaining its name, identity
and attributes, such as creator-only XMP or a tagged PDF structure element without
alternate text. These attributes remain source claims and do not become primary text.

```csharp
var report = FileInspector.AnalyzeReport("recording.wav");
foreach (var fact in report.Content.Facts)
    Console.WriteLine($"{fact.Name}: {fact.Value} ({fact.Kind}, {fact.Origin}) " +
        $"at byte {fact.Source?.ByteOffset}");
```

### Captured input and limits

The reader captures the input once and computes its SHA-256 during capture, so identity
and extraction refer to the same bytes. Seekable input is read from zero and restored
to its original position; forward-only input consumes the remaining content. The
caller's stream stays open.

The snapshot stays in memory up to `MaxMemorySnapshotBytes`. Beyond that threshold,
the .NET 8 build creates an exclusive temporary file with owner-only permissions
on Unix; Windows uses the selected directory's inherited ACL. The file is deleted on close,
including cancellation or failed capture. `SnapshotDirectory` must already exist;
null uses the host's temporary directory. The .NET Standard and .NET Framework
builds reject a spill on a non-Windows host with `PlatformNotSupportedException`,
even if that host has a newer runtime. Keep the captured input within the memory
threshold on those builds. This threshold bounds snapshot storage, not all parser
allocations or process memory.

| Option | Default | Scope |
| --- | --- | --- |
| `MaxInputBytes` | 64 MiB | Complete root input |
| `MaxMemorySnapshotBytes` | 64 MiB | Captured bytes before disk spill |
| `MaxTextCharacters` | 64 Ki characters | Text retained by each reader |
| `MaxArchiveEntries` | 256 | Inventory entries visited per archive |
| `MaxEntryBytes` | 1 MiB | Expanded bytes of one member |
| `MaxExpandedBytes` | 16 MiB | Content-reader expansion across root and descendants |
| `MaxMetadataBytes` | 1 MiB | Bytes probed by each media metadata reader |
| `MaxFacts` | 256 | Facts retained by each content reader |
| `MaxFactCharacters` | 4 Ki characters | One retained fact value |
| `MaxTotalContentCharacters` | 256 Ki characters | Retained reader text, identifiers, metadata, logical locations, diagnostics and omissions across root and descendants |
| `MaxEntryNameCharacters` | 1,024 | Retained decoded member name |
| `MaxIdentifierCharacters` | 1,024 | Complete member IDs, field names and location keys; oversized identifiers are omitted |
| `MaxRegions` | 32 | Binary regions emitted per input |
| `MaxRegionBytes` | 2 MiB | One complete region to hash |
| `MaxRegionHashBytes` | 16 MiB | Region bytes hashed per input |
| `MaxNestedReports` | 32 | Descendant reports across one root |
| `MaxNestedDepth` | 2 | Descendant depth; root is zero |
| `MaxDocumentUnits` | 256 | Logical units retained per input |
| `MaxDiagnostics` | 256 | Diagnostics and omissions retained per input |
| `MaxNativeExpandedBytes` | 64 MiB | Native model expansion reserved per optional invocation |
| `MaxTotalNativeExpandedBytes` | 256 MiB | Native model expansion across root and descendants |
| `MaxNativeReadBytes` | 256 MiB | Actual optional-reader source and payload reads across the root |
| `MaxDecompressionWorkBytes` | 256 MiB | Native decompression work across the root |

Output budgets must be positive. Zero nesting limits disable nested analysis;
zero native allowances refuse mandatory native work. Existing archive-directory, compression-ratio and XML
depth/DTD safeguards also apply. These limits govern report content extraction;
the existing `Analysis` section retains its own detection and analyzer settings.
Oversized input throws `InspectionInputSizeLimitException`; cancellation propagates. Bounded
omissions appear in content or region issues and make coverage partial.

For a larger local input on .NET 8, configure the input and snapshot budgets explicitly:

```csharp
var report = FileInspector.AnalyzeReport("video.mp4", new InspectionReportOptions {
    MaxInputBytes = 512 * 1024 * 1024,
    MaxMemorySnapshotBytes = 8 * 1024 * 1024,
    MaxMetadataBytes = 1024 * 1024
});
```

The whole input is still captured and hashed. Media readers seek over payloads within
that captured stream. Raising a library budget does not raise the local application's
64 MiB upload limit.

Reports force certificate chain checks offline, including signers inside archives.
On .NET 8, issuer downloads are disabled and trust depends on locally available
certificates. On older targets, offline chain trust remains unknown and the report
records `cert:offline-chain-validation-unavailable`. Envelope signature verification
and certificate metadata remain available; neither establishes package integrity.

The base library provides the following readers when no optional adapter is selected.

| Reader | Available content | Boundary |
| --- | --- | --- |
| UTF text | Text sample, encoding, sampled lines, frequent words | Invalid encodings and truncation are explicit |
| Word OOXML | Main-document paragraphs and table count | No revisions, headers, drawings or layout |
| Excel OOXML | Sheet names, stored values, shared/inline strings, formulas | No formula execution, formatting or calculation |
| PowerPoint OOXML | Stored slide text, sampled slides | No notes, embedded objects or rendering; part order is lexical |
| ZIP/TAR | Bounded member inventory, whole-member SHA-256 and optional nested reports | No filesystem extraction; larger/unread members have no hash |
| PNG/GIF/JPEG | Header format and dimensions where present | Header claims only; pixels, OCR and metadata are uninspected |
| WAV | Format, channels, sample rate, sample width and data size; duration for a consistent PCM/float declaration | No waveform decoding; compressed or inconsistent declarations have no derived duration |
| FLAC | STREAMINFO sample declarations and Vorbis comments | No audio-frame decoding or stored audio-MD5 verification |
| ID3 | Version-2.2/2.3/2.4 text frames with source frame identity | No MP3-frame/bitrate analysis; unsupported transforms and non-text frames are reported |
| ISO-BMFF | Brands, sampled tracks, handler/codec identifiers, declared dimensions and media timing | No sample decoding; track transforms, edit lists and fragmented timing remain uninspected |
| PDF | Existing direct lexical inspection signals | No text extraction, page-tree traversal or compressed-object interpretation |
| Other formats | Existing detection/analysis | Content reader explicitly unavailable |

The OOXML readers accept Transitional and Strict namespaces. Unsupported package
XML namespaces are reported explicitly.

### Optional native document inspection

`FileInspectorX.OfficeIMO` maps selected OfficeIMO owners into the same report contract.
The base library does not reference OfficeIMO. Compose the adapter explicitly in C#:

```csharp
using FileInspectorX.OfficeIMO;

var reader = new OfficeImoContentReader();
var report = FileInspector.AnalyzeReport("report.pdf", new InspectionReportOptions {
    ContentReader = reader
});
foreach (var unit in report.Content.DocumentUnits)
    Console.WriteLine($"{unit.Kind}: {unit.Status}");
```

The finite profile covers modern XML Word, Excel and PowerPoint, native PDF text,
selected OpenDocument formats, RTF, image metadata and passive CAB/MSI inventory.
The default native input ceiling is 32 MiB. Each input loads one native owner model;
the canonical Reader projects its text and metadata while that owner is alive.
Image inspection does not decode pixels. PDF page failures, warnings, metadata and
repair descriptions remain separate from searchable primary text.

`Content.Extraction` records reader versions, the profile, text basis and text-changing
settings. Saved Excel formula values remain uncomputed cache evidence; a formula is
never silently replaced by a calculated result. Embedded author names, dates, Exif,
XMP and ICC declarations remain file claims. Unsupported legacy/encrypted profiles
produce a claimed refusal, and malformed native input retains a failed result. These
outcomes do not enable a different text reader. Genuine unsupported formats use the
core readers.

`InspectionContentLimitException` preserves typed native resource/admission limits,
including fractional measurements and the original exception. It remains terminal.
Native model expansion without a complete measured counter consumes the entire finite
reservation conservatively. Selected complete payloads consume one bridge copy and
one core copy; archive decode work can exceed the retained selected bytes. No prefix
member becomes a child report. The core owns hashing and descendant dispatch, using
exact member ID and ordinal rather than display names.

The enhanced PowerShell module selects this profile for `-View Report`; use
`-ReportReader Builtin` for the core readers. Builds can set `IncludeOfficeIMO=false`
to exclude the adapter. The local application selects OfficeIMO inside its child
worker and accepts `--ContentReader Builtin` as an explicit alternative.

Media readers report declarations and provenance without validating playback. They
always retain `media:payload-not-decoded`. ISO-BMFF inspection accepts an `ftyp`
container; an image-oriented brand with no movie tracks does not become a video
description. Unrecognized formats still retain core detection and analysis.

### Nested members and binary regions

A plain ZIP or TAR member receives `ReportArchiveEntry.Report` when its complete bytes
were read and the shared nesting budgets allow it. OOXML internal parts use the existing
document subset reader rather than becoming independent document reports. Child
reports share expanded-byte and retained-content budgets with their root. A partial
child makes root content partial. Set either nesting option to zero for inventory
and hashes without descendant analysis.

Member names remain display data. `Kind` retains the source file, directory or other
record type independently of any truncated name. `Ordinal` preserves zero-based identity when names
repeat. `InventorySource` distinguishes native content-reader, raw ZIP and raw TAR
inventories. Correlation uses that scope together with `MemberId` and `Ordinal`;
equal ordinals or names in two inventories do not identify the same member.
A long display name retains a prefix, sets `NameTruncated` and records its full decoded
`SourceNameCharacters`. Complete native IDs retain their separate identifier allowance. A missing
whole-member hash or nested report is an omission, not an empty member or successful
read.
Comparison recovers schema-1 member ordinals from saved inventory order because that
version did not store ordinals or member kinds.

`Content.Regions` records whole PE raw sections where their ranges and hash budgets
permit them. Invalid, overlapping or over-budget sections retain an explicit status
and have no hash. Other non-text, non-archive inputs can retain leading 64 KiB fixed
blocks within the region budgets. The final shorter block is hashed in full. Each
record includes offset, declared length, actually hashed bytes and coverage issues;
a prefix hash is never presented as a whole-region hash.

### Comparing reports

```csharp
var first = FileInspector.AnalyzeReport("first.zip");
var second = FileInspector.AnalyzeReport("second.zip");
foreach (var evidence in ReportComparison.Compare(first, second))
    Console.WriteLine($"{evidence.Basis}: {evidence.Score:P0}; " +
        $"compared {evidence.ComparedLeft}/{evidence.ComparedRight}, partial={evidence.Partial}");
```

`ReportComparison.Compare` returns each available basis, including a zero-overlap
result. An empty collection means there is no comparable evidence. Exact identity
replaces the text estimate for that pair; available member and region evidence
can still accompany it.

| Basis | Meaning |
| --- | --- |
| `exact-bytes` | Equal whole-input SHA-256; score 1 |
| `extracted-text-shingles` | Overlap of three-word shingles using a deterministic 128-hash sample, only for compatible declared extraction profiles |
| `whole-archive-members` | Multiset overlap of complete member SHA-256 and byte lengths |
| `whole-pe-sections` | Multiset overlap of complete raw-section SHA-256 and byte lengths |
| `sampled-fixed-blocks` | Multiset overlap of inspected complete fixed blocks |

Multiset scores count matching items divided by the union count; they are not weighted
by byte size. Duplicate members count separately and renamed members can match. Evidence
includes the algorithm/version, compared and observed-uncompared counts, compared byte
totals where meaningful, partial coverage, and matches with names, ordinals and offsets.
Unvisited content remains outside the score. A score of 1 for sampled blocks can occur
even when the whole files differ.

`ReportSimilarity.Compare` remains the simpler exact-byte/text API and returns null
when there is insufficient text and the whole hashes differ. Neither API establishes
semantic equivalence, runtime behavior, provenance or safety. Frequent words remain
word frequencies rather than an inferred purpose.

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
the old link. The application uses the .NET 8 runtime and includes the selected
OfficeIMO adapter and its native owners; it needs no ASP.NET shared framework. It accepts raw
uploads, queues work, and exposes searchable reports. Names and file-derived text
are rendered as text; they cannot introduce markup into the page.
The report view shows fact origins/source locations, nested member reports and binary
regions. Related files show each available comparison basis and inspected coverage.

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
| `GET /api/reports/{id}` | Current job state or saved report JSON; new reports use schema 3 |
| `GET /api/hash/{sha256}` | Matching local uploads; names may differ for identical bytes |
| `GET /api/reports/{id}/similar` | Up to 20 positive-overlap matches, with best basis/score and all comparison evidence |
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
