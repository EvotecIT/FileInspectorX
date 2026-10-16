# File understanding and dependency boundaries

The base `FileInspectorX` package owns file identity, detection, bounded report
policy, comparison and descendant orchestration. `FileInspectorX.OfficeIMO` is an
optional adapter over selected [OfficeIMO](https://github.com/EvotecIT/OfficeIMO)
format owners. OfficeIMO does not reference FileInspectorX. Applications choose
whether to ship the adapter; the enhanced Web application and PowerShell module
compose it explicitly.

## Selected native owners

| Capability | Canonical owner | Adapter boundary |
| --- | --- | --- |
| Modern XML Word, Excel and PowerPoint | Native document models and their selected Reader adapters | One native load followed by canonical text and metadata projection; legacy conversion is disabled |
| PDF | `OfficeIMO.Pdf` and `OfficeIMO.Reader.Pdf` | Native text, source structure, page outcomes, repairs and decoding evidence; no rendering or OCR |
| OpenDocument and RTF | Native format models and selected Reader adapters | Deferred binary payloads, explicit story/note policy and original parser diagnostics |
| Image metadata | `OfficeIMO.Core` | Header facts, Exif, timestamps/GPS, XMP, ICC structure and authored-resolution evidence; no pixel decode |
| CAB/MSI | `OfficeIMO.Archives` | Passive inventory and grouped selected-member reads; no installation, external cabinet fetch or filesystem extraction |

The selected closure contains Core, Archives, the six native document owners,
Reader.Core and the six matching Reader adapters. Public consumer references use
OfficeIMO 3.5.1 or later. Reader.All, Reader.Zip, OCR, AI and rendering packages are
outside this adapter. The base FileInspectorX and optional Magika packages retain
their independent capability boundaries.

The adapter maps native results into FileInspectorX DTOs. It does not parse document
XML, PDF text, RTF, embedded containers or archive compression itself. Native
payload identities and ordinals link selected complete bytes to inventory records;
display names never establish identity. FileInspectorX hashes and dispatches each
admitted child after the native owner and invocation lease have ended.

## Evidence and limits

Schema 3 records extraction profiles, logical document locations, diagnostics,
recovery and omissions. Old reports without a profile retain unknown provenance.
Exact SHA-256 identity remains comparable across profiles; text overlap requires
compatible declared reader versions, text basis and settings.

Embedded author names, timestamps, hidden-state declarations and image metadata
remain claims. Formula expressions and saved values remain uncomputed evidence.
Authored image density stays separate from a display default. ICC structural
validity stays separate from supported transform availability. PDF page failures
and diagnostic messages never become searchable primary text.

The core supplies immutable snapshots and remaining output, native-read, expansion,
member and work allowances. The adapter applies finite native admission before
projection and never turns zero into an unlimited native default. Unknown full-model
expansion consumes the entire finite reservation conservatively. Actual source
reads, payload reads, selected bytes and decompression work remain separate charges.
Malformed/refused native inputs keep their claimed result; only genuine
NotApplicable allows the core readers. Native resource and admission failures are
terminal and preserve their structured measurements and original exceptions.

These limits do not prove peak RSS or streaming behavior for every native model.
The local child worker retains its 30-second deadline, observed 512 MiB working-set
threshold, 16 MiB output bound and parent-owned atomic publication. A child process
has the user's OS permissions; public hosting needs a separate authentication,
tenant and OS-isolation design.

## Qualification boundaries

Native and package tests establish the selected workflows, finite limits, payload
lifetime and report mapping. Synthetic files do not establish every producer's
interoperability or visual fidelity. Physical Office acceptance, unsupported fonts,
platform behavior, package publication and installed user versions remain separate
evidence. Qualify .NET Framework, PowerShell, .NET 8 and any trimming/AOT or native
host separately.

Local source and private candidate packages are distinct from public availability.
Use an isolated feed/cache for local candidates; keep normal consumer pins clean.
Publication lag does not justify runtime reflection, a second production parser,
private build versions or downstream compatibility shims. New production engines,
external tools, OCR models and services require their own approved role and
qualification.
