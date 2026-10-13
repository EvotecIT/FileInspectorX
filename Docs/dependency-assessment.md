# Deeper file understanding and dependency boundaries

Assessed 13 October 2026. FileInspectorX and OfficeIMO develop their managed
inspection capabilities independently. FileInspectorX has no OfficeIMO dependency,
and OfficeIMO has no FileInspectorX dependency. A provider, package split or shared
transport has not been selected. New production dependencies and their roles need
approval before integration.

The [report guide](file-reports.md) describes the implemented FileInspectorX contract
and its limits. This assessment identifies the remaining capabilities and the
decisions needed to connect them without duplicating format engines.

## What FileInspectorX owns

FileInspectorX owns file identity, detection and analysis, portable reports,
comparison evidence and the local upload/search workflow. Its managed report
readers use existing platform capabilities and repository code; this upgrade adds
no production package or external executable.

| Capability | Available evidence | Remaining boundary |
| --- | --- | --- |
| UTF text and selected OOXML | Bounded text, stored values/formulas, counts and package inventory | Fuller document stories, review, relationships and layout need document owners |
| ZIP/TAR | Whole-member hashes, ordinals and bounded nested reports | Unread or oversized members remain explicit omissions; no filesystem extraction |
| WAV, FLAC, ID3, ISO-BMFF | Source-located declarations, tags, track/codec identifiers and supported derived timing | No sample decoding, playback validation, transcription or scene understanding |
| PE and other binary inputs | Whole raw-section hashes or sampled complete fixed blocks | Overlap describes inspected bytes, not program behavior or semantic similarity |
| PNG/GIF/JPEG | Header format/dimensions | Embedded metadata, pixel decoding and OCR are separate capabilities |
| PDF | Existing direct lexical inspection signals | Text, page/object models and rendering are not integrated |

Schema-v2 facts distinguish embedded claims from derived values. Regions and
comparison evidence keep their inspected coverage visible. The report accepts saved
schema-v1 evidence without inventing the new fields. Larger configured inputs can
use a captured disk snapshot on supported runtimes, but extraction and output still
have finite budgets.

These limits do not make every analysis stage a streaming parser or establish a
hard process-memory bound. The [local worker](../FileInspectorX.Web/Worker.cs) has a
30-second deadline and an observed 512 MiB working-set threshold. The threshold is
sampled, and the worker has the user's OS permissions. Public hosting needs a
separate authorization, tenant and OS-isolation design.

## What the document and image owners provide

[OfficeIMO](https://github.com/EvotecIT/OfficeIMO) owns reusable document, image,
PDF and archive-format behavior. Improving those APIs is useful to OfficeIMO
consumers even before FileInspectorX consumes any package.

| Owner | Inspection capability | Evidence that a later integration must preserve |
| --- | --- | --- |
| `OfficeIMO.Pdf` | Managed PDF loading, object/page reading and `ReadForInspection` outcomes | Recovery/repair evidence, selected-page outcomes, text mapping/fallback evidence, permission refusal and terminal resource/cancellation failures |
| `OfficeIMO.Reader.Core` and format adapters | Structured document output with opt-in `ReaderInspectionOptions` evidence | Source identities, review/formula/visibility/safety/payload categories, shared record/text budgets and existing versioned Reader serialization |
| Word, Excel and PowerPoint owners | Document models and opt-in original-package security capture | Stored formulas/cache declarations, review records, hidden content and source-package findings; no macro execution or formula calculation by inspection |
| `OfficeIMO.Core` and `OfficeIMO.Reader.Image` | Managed image metadata inspection and bounded Reader projection | Raw Exif identity/offsets, duplicate fields, timestamp/GPS interpretation, XMP collections, ICC structure and authored-resolution status |
| `OfficeIMO.Archives` | Managed CAB/MSI format ownership | Whole-member bytes and names, compression/support boundaries, finite expansion and lifetime ownership |

OfficeIMO's Reader evidence uses its existing metadata contract. FileInspectorX
facts are a separate portable representation. Neither contract currently imports
the other's types. Similar field names do not establish that the schemas or
serialization policies are interchangeable.

Image metadata coverage remains a defined profile: private or additional Exif
directories, camera MakerNotes and arbitrary structured RDF can be omitted.
ICC structural evidence does not establish that every profile can be used as a
supported color transform. A missing authored resolution must stay distinct from
a display default. Generic image inspection must not imply decoding support for
every container handled by a dedicated metadata API.

PDF inspection must retain per-page failures and text-decoding evidence. Readable
text does not establish visual reading order, complete font coverage, rendering
fidelity or OCR quality. Recovering a damaged file must not erase the fact that it
was recovered. Document security findings and embedded metadata remain evidence,
not a trustworthy statement about the author's identity or a safety verdict.

OfficeIMO has its own dependency and target-framework graph. First-party source
ownership does not mean a chosen OfficeIMO package has no transitive dependencies,
native assets or compatibility work. Those properties must be checked for the
specific packages and hosts proposed for integration.

## Integration and package choices remain open

The code in each repository stays independently useful while these questions are
resolved. An integration decision should name the exact capability and caller,
rather than adding the whole OfficeIMO repository to core.

| Decision | Options to assess | Practical consequence |
| --- | --- | --- |
| Receiving boundary | Core reference or optional reader integration | Determines whether all FileInspectorX installations carry document-engine requirements |
| Package selection | Individual format owners and Reader adapters already serving the chosen formats | Determines transitive dependencies, target frameworks and deployment size |
| Mapping owner | Thin integration code that maps native results into report facts/text/issues | Keeps parsing in its canonical format owner and report policy in FileInspectorX |
| Execution | In-process library use or the local host's child worker | Determines cancellation, lifetime, memory and failure boundaries; a child process is not an OS sandbox |
| Contract | Preserve both versioned models or explicitly map a supported subset | Determines where source locations, unknown values, recovery and partial coverage can be lost |

No package name, reference direction or compatibility bridge is prescribed here.
Before choosing, run a representative file through each public owner API and
compare the resulting evidence and omissions. Check the actual public package
availability separately from local source. Qualify a local candidate through
source references or an isolated package feed; do not hide publication lag with
runtime reflection, fallback parsers or private build versions in normal pins.

A later adapter should receive the same captured bytes used for identity and
extraction. It should apply content policy once, preserve native source identities,
and map unknown, skipped, recovered and failed states explicitly. It must not
silently replace stored text with OCR, a formula with a calculated result, or an
embedded declaration with a verified fact. Finite source, expansion, page, metadata
and output limits must survive the mapping.

## Remaining gaps and external alternatives

Independent managed upgrades do not complete every file-understanding workflow.
These choices remain conditional on an actual need; none is a recommendation to
install another production dependency now.

| Need | Route to assess | Boundary |
| --- | --- | --- |
| Broader embedded metadata | Extend the image owner where its profile is insufficient; use [MetadataExtractor](https://github.com/drewnoakes/metadata-extractor-dotnet) as a separately qualified alternative or test comparison | Additional tag coverage does not verify claims or decode pixels |
| Unsupported PDF reading cases | Improve `OfficeIMO.Pdf`; use [PdfPig](https://github.com/UglyToad/PdfPig) only as a comparison or an explicitly approved alternative | Do not introduce a second production PDF reader merely to avoid fixing the owner |
| Fuller OOXML markup | Extend the document owners and their existing Open XML support | Preserve review, hidden-content and relationship policy; no parallel document engine in FileInspectorX |
| Interoperable fuzzy byte digests | Assess [TLSH](https://github.com/trendmicro/tlsh) or an existing-index requirement separately | Current exact-region overlap is not a TLSH/ssdeep digest or a behavioral comparison |
| Additional media formats and decoded stream proof | Extend bounded managed profiles where practical; assess [ffprobe](https://ffmpeg.org/ffprobe.html) for a selected native-tool role | Native build provenance, protocols, accessible paths and process/output budgets need separate qualification |
| Scanned text | Use the existing `OfficeIMO.Ocr.IOcrEngine` ownership route and assess the selected engine, rasterizer and language models | OCR, page rasterization and decoded-pixel budgets are distinct from stored text extraction |
| Purpose or scene descriptions | A separately designed synthesis workflow over retained evidence | Requires source citations, privacy policy and uncertainty handling; metadata alone is insufficient |

Test-only comparison engines must stay outside shipped artifacts, normal installation
and public APIs. A future production engine needs an explicit role, license/transitive
inventory, update owner and target-host qualification. Native tools and OCR models
have their own distribution and resource requirements even when the caller is managed.

## Evidence required before connecting the repositories

Exercise malformed and truncated inputs, duplicates, conflicting metadata, damaged
PDFs, unusual fonts, encrypted/permission-restricted inputs, hidden/review content,
stored formulas and cached results, and nested expansion limits. Include independently
produced files with known expected content; synthetic fixtures alone do not prove
producer interoperability or extraction fidelity.

Measure the selected packages' installed size, startup and peak memory on each
intended host. Validate .NET Framework/PowerShell, .NET 8, trimming/AOT and any native
targets separately. Test cancellation, stream ownership, temporary-file cleanup,
worker failure and saved-report compatibility at the actual integration boundary.
Record engine versions and extraction policy so a changed result can be diagnosed.
