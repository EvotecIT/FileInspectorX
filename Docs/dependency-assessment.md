# Dependencies for deeper file understanding

Assessed 13 October 2026. This is a proposal: none of these engines is installed,
referenced or invoked by FileInspectorX. Each production dependency and its role
needs approval before implementation. Published package information below is a
research snapshot, not a version pin or a compatibility test.

The most useful next additions are embedded image metadata and readable PDF text.
Keep detection and the portable report contract in FileInspectorX; make deeper
readers optional. The same report should explain which engine ran, what it read,
what it skipped and which facts support its observations.

## Current coverage and remaining work

The current [report reader](../FileInspectorX/Reporting/ReportContentReader.cs)
extracts bounded UTF text, selected Office XML content, archive inventories and
whole-member hashes within the expansion budget. It reads PNG/GIF/JPEG header
dimensions. PDF content remains direct lexical signals. Text similarity compares
extracted samples; it does not compare binary structure or infer meaning.

The [report options](../FileInspectorX/Reporting/InspectionReport.cs) default to
64 MiB input, 64 Ki characters, 256 archive entries, 1 MiB per expanded member and
16 MiB expanded bytes overall. The [local Web host](../FileInspectorX.Web/Worker.cs)
uses a separate worker, with a 30-second deadline and an observed 512 MiB working
set threshold. That threshold is sampled, and the worker has the user's OS
permissions; it is not an OS sandbox or a hard memory limit.

| Remaining question | Suitable capability | What still needs separate work |
| --- | --- | --- |
| Who created this photo; when and where? | Embedded metadata reader | Values are file claims; authenticity and location consent |
| What does this PDF say? | PDF text and object reader | Reading order, scanned pages, rendering, tables and quality evidence |
| What is in Office headers, notes and relationships? | OOXML package/object reader | Explicit content policy, formatting, revisions, calculation and layout |
| Which binaries resemble this file? | Fuzzy byte digest | Corpus thresholds, unavailable digests and indexing |
| What streams and codecs are in this video/audio? | Media probe | Transcription, scene understanding, thumbnails and decoding proof |
| What does this scanned page or screenshot say? | OCR | Rasterization, language policy, quality assessment and pixel budgets |

## Options, from smaller deployment changes to larger ones

This ordering considers native assets, models and maintenance as well as download
size. It is an assessment, not a measured installation benchmark. Package archives
contain multiple framework builds; their compressed size is not the added size of
a published application. Native tool size depends on the chosen build and target.

| Order | Candidate and narrow role | Deployment and ownership fit |
| --- | --- | --- |
| 1 | MetadataExtractor: embedded media metadata | Managed optional reader; useful without pixel decoding or models |
| 2 | PdfPig: PDF text, pages and document facts | Managed optional reader; largest immediate content gap |
| 3 | Open XML SDK: fuller OOXML structure and validation | Conditional replacement for the bounded XML subset, if scope justifies it |
| 4 | TLSH: binary similarity | Optional native utility/library; distinct report field and comparison basis |
| 5 | ffprobe: audio/video stream inventory | Optional installed native worker with a controlled build |
| 6 | Tesseract: OCR for images | Native worker plus selected language models; PDF rasterization adds another engine |

### 1. MetadataExtractor

Use it to expose Exif, IPTC, XMP and ICC fields, camera details, embedded timestamps,
orientation and location tags. Its supported formats include common images,
camera raw files and some movie/audio containers. It is a metadata reader; scene
descriptions and OCR remain separate capabilities. [Upstream scope](https://github.com/drewnoakes/metadata-extractor-dotnet#features).

The published 2.9.3 package has `net8.0`, `netstandard2.0` and `netstandard2.1`
assets. Upstream advertises NativeAOT for its .NET 8 target. The archive is about
1 MB, before dependencies. Its runtime graph includes XmpCore; older targets also
bring compatibility/encoding packages. [Package frameworks and dependencies](https://www.nuget.org/packages/MetadataExtractor/),
[AOT declaration](https://github.com/drewnoakes/metadata-extractor-dotnet/blob/main/MetadataExtractor/MetadataExtractor.csproj).

MetadataExtractor is Apache-2.0; upstream identifies XmpCore as BSD licensed.
Keep both license sets in the distributable. [License and third-party terms](https://github.com/drewnoakes/metadata-extractor-dotnet/blob/main/LICENSE).

Qualify it with independent camera/phone files, conflicting Exif/XMP values,
malformed/truncated metadata and large tags. Retain source directory/tag identifiers,
raw values and parse errors. Show timestamps and GPS as embedded claims. Exercise
XMP and camera notes in the actual trimmed/AOT executable, and validate Windows
PowerShell's .NET Framework path separately before claiming that host is supported.

### 2. PdfPig

Use it for page counts and dimensions, text with page locations, document metadata,
links, forms and attachment inventory. This addresses PDFs whose text lives in
compressed content streams. A readable extraction also enables existing keyword
and text similarity features. [Document APIs](https://github.com/UglyToad/PdfPig#usage).

PdfPig is Apache-2.0 and has additional attribution notices. Its published 0.1.16
package supplies .NET Standard 2.0/2.1, .NET Framework 4.6.2/4.7.1 and .NET 6/8/9
assets; the archive is about 16 MB. It is managed, with bundled resources and
compatibility dependencies on older targets. Verify the selected package graph,
rather than inferring a release from the development branch. [Published package](https://www.nuget.org/packages/PdfPig/0.1.16),
[license](https://github.com/UglyToad/PdfPig/blob/master/LICENSE),
[notices](https://github.com/UglyToad/PdfPig/blob/master/NOTICES.txt).

Upstream warns that text content order often differs from reading order and that
pre-1.0 minor versions can change the API. Select and report an extraction policy;
do not present `Page.Text` as a faithful reading sequence. [Reading guidance](https://github.com/UglyToad/PdfPig#reading-text-from-a-pdf).

PDF rasterization, scanned-page OCR and reliable table reconstruction are separate
work. Image filters also have limitations. [Image extraction limits](https://github.com/UglyToad/PdfPig/wiki/FAQ).
Upstream has renewed trimming/AOT analysis; that is useful evidence, not proof of
our chosen extraction path. [Release notes](https://github.com/UglyToad/PdfPig/releases/tag/v0.1.16).

Qualify compressed/object-stream PDFs, custom fonts and CJK, multicolumn pages,
encrypted inputs, incremental updates, scans and damaged cross-references. Compare
text against known producer output and human reading order. Report password-required,
recovered and skipped content separately. Cap pages, decoded bytes, attachments and
output; retain the worker deadline because an input byte limit does not bound all
parser allocations. No rendering or full PDF conformance claim follows from parsing.

### 3. Open XML SDK and fuller document engines

The SDK offers typed OPC parts and ISO 29500 markup, including validation APIs.
It is appropriate when relationship-aware extraction, Strict/Transitional documents,
headers, notes, comments and markup compatibility exceed the current XML subset.
It is a low-level format API; FileInspectorX still needs an explicit policy for
which content belongs in a report. [SDK scope](https://github.com/dotnet/Open-XML-SDK),
[validation example](https://learn.microsoft.com/en-us/office/open-xml/word/how-to-validate-a-word-processing-document).

The published 3.5.1 package is MIT licensed and includes `netstandard2.0`, `net8.0`
and .NET Framework assets. Its archive is about 15 MB, plus the Framework package
and packaging dependencies. No native Office installation is needed for XML access.
Validate the actual package/transitive graph and AOT path; framework compatibility
alone proves neither trimming safety nor bounded memory. [Package](https://www.nuget.org/packages/DocumentFormat.OpenXml/3.5.1),
[Framework package](https://www.nuget.org/packages/DocumentFormat.OpenXml.Framework/3.5.1),
[MIT license](https://github.com/dotnet/Open-XML-SDK/blob/main/LICENSE).

The SDK documents ZIP working-set growth on modern .NET. Preserve expansion limits
before handing a package to it and test large/damaged parts. [Known issues](https://github.com/dotnet/Open-XML-SDK#known-issues).
Treat stored formulas and cached results as separate evidence; the cached value
reflects a prior calculation and can be absent or stale. [SpreadsheetML formulas](https://learn.microsoft.com/en-us/office/open-xml/spreadsheet/working-with-formulas).

Full document engines become relevant for layout, rendering, calculated values and
higher-level interpretation. OfficeIMO is excluded from this implementation.
The nearby source already has document readers and an `OfficeIMO.Ocr.IOcrEngine`
contract; any later reuse needs a separate ownership and public-package assessment.
Do not create another document layout or OCR orchestration engine in this project.

### 4. TLSH, with ssdeep as an interoperability alternative

TLSH compares byte streams through fuzzy digests. It needs at least 50 bytes with
enough variation; short or repetitive inputs may produce no digest. The upstream
implementation builds a native library and executable, and does not certify its
listed third-party ports as equivalent. [Algorithm and deployment](https://github.com/trendmicro/tlsh).
It permits a choice of Apache-2.0 or BSD terms. [License](https://github.com/trendmicro/tlsh/blob/master/LICENSE).

Prefer an optional adapter to an approved upstream build if binary resemblance is
needed. Record algorithm/version, digest availability and byte coverage. Verify
known vectors, cross-platform parity, short/uniform files and edited/compressed
copies. Calibrate distance thresholds by file family; a distance is not a semantic
similarity percentage. An AOT host can launch a tool, but still needs that target's
executable and bounded process/output handling.

ssdeep is useful when consuming existing ssdeep indexes. Its CTPH program and
libfuzzy use GPL-2.0-or-later, so its distribution/integration needs a specific
license decision. The official page's release/platform information is old; it
does not establish current target qualification. It adds no immediate value to
the existing text comparison workflow. [Official scope and license](https://ssdeep-project.github.io/ssdeep/).

### 5. ffprobe

Use JSON output for container and stream facts: codecs, dimensions, duration,
sample rate, channels, stream tags and subtitles/attachments inventory where
supported. Select specific fields; avoid packet/frame dumps as the default report.
Transcription and visual scene understanding remain separate. [ffprobe options](https://ffmpeg.org/ffprobe.html).

This is a native executable, without a .NET target framework. Prefer a configured
installed tool in an isolated worker over shipping every codec in core. A NativeAOT
host does not remove native deployment requirements. Build size and supported
formats depend on enabled components; measure each approved OS/architecture build.

FFmpeg's base terms are LGPL-2.1-or-later; enabling GPL components changes the build's
terms, and nonfree configurations need separate scrutiny. Record binary provenance,
configure flags and corresponding source/licenses before redistribution. [Official licensing guidance](https://ffmpeg.org/legal.html).
Restrict protocols and local file access: network protocols are available by
default. A protocol allowlist still does not constrain all accessible local paths.
[Protocol controls](https://ffmpeg.org/ffmpeg-protocols.html#Protocol-Options).
Test truncated media, misleading tags, unusual stream counts, playlists, external
references, missing codecs, oversized output and process termination.

### 6. Tesseract OCR

Use it to produce OCR text, word boxes and recognition evidence for supported
images. It supplies a native CLI and C/C++ APIs; no upstream .NET framework or
managed-wrapper compatibility should be inferred. Quality depends on the image
and preprocessing. [Engine and output formats](https://github.com/tesseract-ocr/tesseract).

Tesseract and the official fast language models are Apache-2.0; Leptonica uses
BSD-2-Clause, and native image codecs have their own terms. Models and native
libraries must be inventoried separately. [Engine license](https://github.com/tesseract-ocr/tesseract/blob/main/LICENSE),
[model license](https://github.com/tesseract-ocr/tessdata_fast/blob/main/LICENSE),
[Leptonica license](https://github.com/DanBloomberg/leptonica/blob/master/leptonica-license.txt).

Start with explicitly selected languages and compare `tessdata_fast` against
`tessdata_best` on the real corpus. Upstream describes a speed/accuracy tradeoff;
shipping every language increases model storage and operational scope. [Model choices](https://tesseract-ocr.github.io/tessdoc/Data-Files.html).
Tesseract cannot read PDF input: scanned PDFs require a separately approved
rasterizer, fonts/assets and page/pixel budgets. [Input limitations](https://tesseract-ocr.github.io/tessdoc/InputFormats.html).

Use a shared OCR owner if this later proceeds. Keep recognized text distinct from
stored text and include language/model/version and page/image origin. Qualify
rotated pages, low resolution, tables, handwriting and mixed languages against
ground truth; engine confidence is not calibrated factual certainty. Validate
timeouts, cancellation, temporary-file cleanup, process concurrency and maximum
decoded pixels on each shipped target.

## Decision and acceptance requirements

Propose MetadataExtractor and PdfPig first, as independently optional readers.
Choose Open XML SDK only when fuller Office structure is required. Defer native
similarity, media probing and OCR until the corresponding user workflow is chosen.
Keep UI, PowerShell and the Web host as consumers of one report owner.

Assign an owner for engine updates, advisories, licenses, native build provenance
and regression fixtures. Record engine versions in reports so changed extraction
can be diagnosed. Requalify affected fixtures after updates, especially PdfPig's
pre-1.0 API changes and native codec/model changes.

Before approval, resolve exact package/tool versions, transitive licenses, ownership
and target hosts. Before shipping, measure installed/published size, startup and
peak memory; run meaningful malformed-input and independent-producer fixtures;
verify the intended .NET Framework, trimmed/AOT and native targets separately.
Report unavailable engines, partial reads and resource-limit failures explicitly.
None of these candidates supplies trustworthy semantic summaries by itself:
any later model-based explanation needs its own evidence, privacy and review policy.
