using Xunit;

namespace FileInspectorX.Tests;

public class FixtureCorpusTests
{
    [Fact]
    public void Fixture_WrappedBase64_MzPayload_Detects_InnerExecutable()
    {
        var path = TestHelpers.GetFixturePath("encoded", "wrapped-base64-mz.txt");

        var analysis = FileInspector.Analyze(path);

        Assert.NotNull(analysis);
        Assert.Equal("b64", analysis.Detection!.Extension);
        Assert.Equal("base64", analysis.EncodedKind);
        Assert.NotNull(analysis.EncodedInnerDetection);
        Assert.Equal("exe", analysis.EncodedInnerDetection!.Extension);
        Assert.True(analysis.Flags.HasFlag(ContentFlags.EncodedBase64));
    }

    [Fact]
    public void Fixture_QuotedPrintable_MzPayload_Detects_InnerExecutable()
    {
        var path = TestHelpers.GetFixturePath("encoded", "quoted-printable-mz.txt");

        var analysis = FileInspector.Analyze(path);

        Assert.NotNull(analysis);
        Assert.Equal("qp", analysis.Detection!.Extension);
        Assert.Equal("quoted-printable", analysis.EncodedKind);
        Assert.NotNull(analysis.EncodedInnerDetection);
        Assert.Equal("exe", analysis.EncodedInnerDetection!.Extension);
        Assert.Contains("enc:qp", analysis.SecurityFindings ?? Array.Empty<string>());
    }

    [Fact]
    public void Fixture_Markdown_BlankLine_Javascript_StaysMarkdown()
    {
        var path = TestHelpers.GetFixturePath("text", "markdown-heading-js.txt");

        var detection = FileInspector.Detect(path);

        Assert.NotNull(detection);
        Assert.Equal("md", detection!.Extension);
        Assert.Equal("text/markdown", detection.MimeType);
        Assert.NotNull(detection.Alternatives);
        Assert.Contains(detection.Alternatives!, a => string.Equals(a.Extension, "js", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Fixture_Markdown_Fenced_Pem_Block_StaysMarkdown()
    {
        var path = TestHelpers.GetFixturePath("text", "markdown-fenced-pem.md");

        var detection = FileInspector.Detect(path);

        Assert.NotNull(detection);
        Assert.Equal("md", detection!.Extension);
        Assert.Equal("text/markdown", detection.MimeType);
    }

    [Fact]
    public void Fixture_Markdown_Indented_Pem_Block_StaysMarkdown()
    {
        var path = TestHelpers.GetFixturePath("text", "markdown-indented-pem.md");

        var detection = FileInspector.Detect(path);

        Assert.NotNull(detection);
        Assert.Equal("md", detection!.Extension);
        Assert.Equal("text/markdown", detection.MimeType);
    }

    [Fact]
    public void Fixture_Indented_Pem_PrivateKey_Detects_Key()
    {
        var path = TestHelpers.GetFixturePath("text", "indented-pem-private-key.txt");

        var detection = FileInspector.Detect(path);

        Assert.NotNull(detection);
        Assert.Equal("key", detection!.Extension);
        Assert.Equal("application/x-pem-key", detection.MimeType);
        Assert.StartsWith("text:pem-key", detection.Reason);
    }

    [Fact]
    public void Fixture_Html_InlineDataUri_Produces_DataUri_Summaries()
    {
        var path = TestHelpers.GetFixturePath("references", "html-inline-data-uri.html");

        var analysis = FileInspector.Analyze(path);
        var refs = analysis.References ?? Array.Empty<Reference>();

        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "html:data-uri=1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "html:data-exts=js:1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(analysis.SecurityFindings ?? Array.Empty<string>(), f => string.Equals(f, "html:data-uri=1", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Fixture_Script_InlineDataUri_Produces_DataUri_Summaries()
    {
        var path = TestHelpers.GetFixturePath("references", "script-inline-data-uri.js");

        var analysis = FileInspector.Analyze(path);
        var refs = analysis.References ?? Array.Empty<Reference>();

        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-exts=ps1:1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(analysis.SecurityFindings ?? Array.Empty<string>(), f => string.Equals(f, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Fixture_Html_Css_WrappedDataUri_Produces_DataUri_Summaries()
    {
        var path = TestHelpers.GetFixturePath("references", "html-css-wrapped-data-uri.html");

        var analysis = FileInspector.Analyze(path);
        var refs = analysis.References ?? Array.Empty<Reference>();

        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "html:data-uri=1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "html:data-exts=css:1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(analysis.SecurityFindings ?? Array.Empty<string>(), f => string.Equals(f, "html:data-uri=1", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Fixture_Script_ChunkedDataUri_Produces_DataUri_Summaries()
    {
        var path = TestHelpers.GetFixturePath("references", "script-inline-data-uri-chunked.js");

        var analysis = FileInspector.Analyze(path);
        var refs = analysis.References ?? Array.Empty<Reference>();

        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-exts=ps1:1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(analysis.SecurityFindings ?? Array.Empty<string>(), f => string.Equals(f, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Fixture_Script_MixedQuote_ChunkedDataUri_Produces_DataUri_Summaries()
    {
        var path = TestHelpers.GetFixturePath("references", "script-inline-data-uri-mixed-quote.js");

        var analysis = FileInspector.Analyze(path);
        var refs = analysis.References ?? Array.Empty<Reference>();

        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-exts=ps1:1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(analysis.SecurityFindings ?? Array.Empty<string>(), f => string.Equals(f, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Fixture_Script_Parenthesized_ChunkedDataUri_Produces_DataUri_Summaries()
    {
        var path = TestHelpers.GetFixturePath("references", "script-inline-data-uri-parenthesized.js");

        var analysis = FileInspector.Analyze(path);
        var refs = analysis.References ?? Array.Empty<Reference>();

        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-exts=ps1:1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(analysis.SecurityFindings ?? Array.Empty<string>(), f => string.Equals(f, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Fixture_Script_TemplateLiteral_DataUri_Produces_DataUri_Summaries()
    {
        var path = TestHelpers.GetFixturePath("references", "script-inline-data-uri-template-literal.js");

        var analysis = FileInspector.Analyze(path);
        var refs = analysis.References ?? Array.Empty<Reference>();

        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-exts=ps1:1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(analysis.SecurityFindings ?? Array.Empty<string>(), f => string.Equals(f, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Fixture_Script_TemplateLiteral_Concat_DataUri_Produces_DataUri_Summaries()
    {
        var path = TestHelpers.GetFixturePath("references", "script-inline-data-uri-template-literal-concat.js");

        var analysis = FileInspector.Analyze(path);
        var refs = analysis.References ?? Array.Empty<Reference>();

        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-exts=ps1:1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(analysis.SecurityFindings ?? Array.Empty<string>(), f => string.Equals(f, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Fixture_Script_ArrayJoin_DataUri_Produces_DataUri_Summaries()
    {
        var path = TestHelpers.GetFixturePath("references", "script-inline-data-uri-array-join.js");

        var analysis = FileInspector.Analyze(path);
        var refs = analysis.References ?? Array.Empty<Reference>();

        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-exts=ps1:1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(analysis.SecurityFindings ?? Array.Empty<string>(), f => string.Equals(f, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Fixture_Script_TemplateLiteral_ArrayJoin_DataUri_Produces_DataUri_Summaries()
    {
        var path = TestHelpers.GetFixturePath("references", "script-inline-data-uri-template-literal-join.js");

        var analysis = FileInspector.Analyze(path);
        var refs = analysis.References ?? Array.Empty<Reference>();

        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-exts=ps1:1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(analysis.SecurityFindings ?? Array.Empty<string>(), f => string.Equals(f, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Fixture_Script_Parenthesized_ArrayJoin_DataUri_Produces_DataUri_Summaries()
    {
        var path = TestHelpers.GetFixturePath("references", "script-inline-data-uri-parenthesized-array-join.js");

        var analysis = FileInspector.Analyze(path);
        var refs = analysis.References ?? Array.Empty<Reference>();

        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-exts=ps1:1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(analysis.SecurityFindings ?? Array.Empty<string>(), f => string.Equals(f, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Fixture_Script_TemplateLiteral_Parenthesized_ArrayJoin_DataUri_Produces_DataUri_Summaries()
    {
        var path = TestHelpers.GetFixturePath("references", "script-inline-data-uri-template-literal-parenthesized-join.js");

        var analysis = FileInspector.Analyze(path);
        var refs = analysis.References ?? Array.Empty<Reference>();

        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-exts=ps1:1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(analysis.SecurityFindings ?? Array.Empty<string>(), f => string.Equals(f, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Fixture_Script_ArrayJoin_Concat_DataUri_Produces_DataUri_Summaries()
    {
        var path = TestHelpers.GetFixturePath("references", "script-inline-data-uri-array-join-concat.js");

        var analysis = FileInspector.Analyze(path);
        var refs = analysis.References ?? Array.Empty<Reference>();

        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-exts=ps1:1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(analysis.SecurityFindings ?? Array.Empty<string>(), f => string.Equals(f, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Fixture_Script_TemplateLiteral_ArrayJoin_Concat_DataUri_Produces_DataUri_Summaries()
    {
        var path = TestHelpers.GetFixturePath("references", "script-inline-data-uri-template-literal-join-concat.js");

        var analysis = FileInspector.Analyze(path);
        var refs = analysis.References ?? Array.Empty<Reference>();

        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-exts=ps1:1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(analysis.SecurityFindings ?? Array.Empty<string>(), f => string.Equals(f, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Fixture_Script_Concat_DataUri_Produces_DataUri_Summaries()
    {
        var path = TestHelpers.GetFixturePath("references", "script-inline-data-uri-concat.js");

        var analysis = FileInspector.Analyze(path);
        var refs = analysis.References ?? Array.Empty<Reference>();

        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-exts=ps1:1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(analysis.SecurityFindings ?? Array.Empty<string>(), f => string.Equals(f, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Fixture_PowerShell_With_Base64_Blob_Remains_Powershell()
    {
        var path = TestHelpers.GetFixturePath("near-miss", "powershell-base64-blob.ps1");

        var detection = FileInspector.Detect(path);
        var analysis = FileInspector.Analyze(path);

        Assert.NotNull(detection);
        Assert.Equal("ps1", detection!.Extension);
        Assert.Null(analysis.EncodedKind);
    }

    [Fact]
    public void Fixture_Script_ArrayJoin_With_NonEmpty_Separator_Does_Not_Create_DataUri_Summary()
    {
        var path = TestHelpers.GetFixturePath("near-miss", "script-inline-data-uri-array-join-separator.js");

        var analysis = FileInspector.Analyze(path);
        var refs = analysis.References ?? Array.Empty<Reference>();

        Assert.DoesNotContain(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(analysis.SecurityFindings ?? Array.Empty<string>(), f => string.Equals(f, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Fixture_Script_ArrayJoin_With_StringCall_Does_Not_Create_DataUri_Summary()
    {
        var path = TestHelpers.GetFixturePath("near-miss", "script-inline-data-uri-array-join-string-call.js");

        var analysis = FileInspector.Analyze(path);
        var refs = analysis.References ?? Array.Empty<Reference>();

        Assert.DoesNotContain(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(analysis.SecurityFindings ?? Array.Empty<string>(), f => string.Equals(f, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Fixture_Script_Comment_DataUri_Text_Does_Not_Create_DataUri_Summary()
    {
        var path = TestHelpers.GetFixturePath("near-miss", "script-comment-data-uri.js");

        var analysis = FileInspector.Analyze(path);
        var refs = analysis.References ?? Array.Empty<Reference>();

        Assert.DoesNotContain(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(analysis.SecurityFindings ?? Array.Empty<string>(), f => string.Equals(f, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Fixture_Script_Doc_String_DataUri_Text_Does_Not_Create_DataUri_Summary()
    {
        var path = TestHelpers.GetFixturePath("near-miss", "script-doc-string-data-uri.js");

        var analysis = FileInspector.Analyze(path);
        var refs = analysis.References ?? Array.Empty<Reference>();

        Assert.DoesNotContain(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(analysis.SecurityFindings ?? Array.Empty<string>(), f => string.Equals(f, "script:data-uri=1", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Fixture_Html_DataUriLooking_Text_Does_Not_Create_DataUri_Summary()
    {
        var path = TestHelpers.GetFixturePath("near-miss", "html-data-uri-looking-text.html");

        var analysis = FileInspector.Analyze(path);
        var refs = analysis.References ?? Array.Empty<Reference>();

        Assert.DoesNotContain(refs, r => r.Kind == ReferenceKind.Command && string.Equals(r.Value, "html:data-uri=1", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(analysis.SecurityFindings ?? Array.Empty<string>(), f => string.Equals(f, "html:data-uri=1", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Fixture_Log_With_Long_Base64Looking_Token_Stays_Log_And_Not_Encoded()
    {
        var path = TestHelpers.GetFixturePath("near-miss", "log-base64-looking-token.log");

        var detection = FileInspector.Detect(path);
        var analysis = FileInspector.Analyze(path);

        Assert.NotNull(detection);
        Assert.Equal("log", detection!.Extension);
        Assert.Null(analysis.EncodedKind);
    }

    [Fact]
    public void Fixture_Changelog_Inline_Certificate_Markers_Are_Not_Pem()
    {
        var path = TestHelpers.GetFixturePath("near-miss", "changelog-inline-certificate.txt");

        var detection = FileInspector.Detect(path);

        Assert.NotNull(detection);
        Assert.NotEqual("crt", detection!.Extension);
        Assert.NotEqual("key", detection.Extension);
    }

    [Fact]
    public void Fixture_Markdown_Blockquote_Pem_Block_StaysMarkdown()
    {
        var path = TestHelpers.GetFixturePath("text", "markdown-blockquote-pem.md");

        var detection = FileInspector.Detect(path);

        Assert.NotNull(detection);
        Assert.Equal("md", detection!.Extension);
        Assert.Equal("text/markdown", detection.MimeType);
    }

    [Fact]
    public void Fixture_Semicolon_Path_List_Is_Not_Csv()
    {
        var path = TestHelpers.GetFixturePath("near-miss", "semicolon-path-list.txt");

        var detection = FileInspector.Detect(path);

        Assert.NotNull(detection);
        Assert.NotEqual("csv", detection!.Extension);
    }

    [Fact]
    public void Fixture_Ini_With_Dotted_Keys_Is_Not_Toml()
    {
        var path = TestHelpers.GetFixturePath("near-miss", "ini-dotted-keys.txt");

        var detection = FileInspector.Detect(path);

        Assert.NotNull(detection);
        Assert.Equal("ini", detection!.Extension);
    }

    [Fact]
    public void Fixture_Timestamped_Service_Log_Stays_Log()
    {
        var path = TestHelpers.GetFixturePath("near-miss", "timestamped-service.log");

        var detection = FileInspector.Detect(path);

        Assert.NotNull(detection);
        Assert.Equal("log", detection!.Extension);
        Assert.Equal("Medium", detection.Confidence);
        Assert.StartsWith("text:log-levels", detection.Reason);
    }
}
