#if NET8_0_OR_GREATER
using System.Text.Json;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class InspectionReportSchema3Tests
{
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void ActualLegacyJsonRetainsUnknownExtractionAndByteSpace(int schema)
    {
        var json = "{\"SchemaVersion\":" + schema + ",\"Content\":{\"Reader\":\"utf-text\",\"Text\":\"saved text\",\"Facts\":[{\"Name\":\"value\",\"Source\":{\"ByteOffset\":9,\"ByteLength\":2}}],\"Entries\":[{\"Name\":\"member.bin\",\"SizeBytes\":2}]}}";
        var saved = JsonSerializer.Deserialize<InspectionReport>(json)!;
        Assert.True(InspectionReport.SupportsSchema(saved.SchemaVersion));
        Assert.Null(saved.Content.Extraction);
        Assert.Empty(saved.Content.DocumentUnits);
        Assert.Empty(saved.Content.Diagnostics);
        Assert.Empty(saved.Content.Omissions);
        var fact = Assert.Single(saved.Content.Facts);
        Assert.Null(fact.LogicalSource);
        Assert.Equal(ReportByteSpace.Unknown, fact.Source!.ByteSpace);
        Assert.Equal(9, fact.Source.ByteOffset);
        Assert.Equal(ReportArchiveInventorySource.Unknown, Assert.Single(saved.Content.Entries).InventorySource);
    }

    [Fact]
    public void Schema3RoundtripKeepsProvenanceLogicalSpansRecoveryAndMemberIdentity()
    {
        var report = new InspectionReport
        {
            Content = new ContentProfile
            {
                Reader = "canonical-reader",
                Text = "page text",
                Extraction = new ReportExtractionDescriptor
                {
                    ReaderId = "canonical-reader", ReaderVersion = "3.4.6", ProfileId = "document/v1",
                    TextBasis = ReportTextBasis.CanonicalDocumentText,
                    Settings = new Dictionary<string, string> { ["page-order"] = "2,1,2", ["formulas"] = "cached-values" }
                },
                DocumentUnits = new[] { new ReportDocumentUnit
                {
                    Id = "page:2:occurrence:0", Kind = "page", Ordinal = 0, Status = InspectionStageStatus.Partial,
                    Location = new ReportLogicalLocation { Page = 2, SourceCharacterOffset = 100, SourceCharacterLength = 9 },
                    TextStart = 0, TextLength = 9
                } },
                Diagnostics = new[] { new ReportDiagnostic
                {
                    Severity = ReportDiagnosticSeverity.Warning, Category = "reader", Code = "native:repaired", Message = "Source repaired",
                    Source = new ReportSourceLocation { Part = "document.xml", ByteSpace = ReportByteSpace.PartBytes, ByteOffset = 5 },
                    LogicalSource = new ReportLogicalLocation { Story = "body", BlockAnchor = "block:1" },
                    IsRecoverable = true, Recovery = ReportRecoveryKind.Repaired,
                    Attributes = new Dictionary<string, string> { ["repair"] = "structure" }
                } },
                Facts = new[] { new ReportFact { Name = "cell", Value = "42", LogicalSource = new ReportLogicalLocation { Sheet = "Budget", A1Range = "A1" }, Attributes = new Dictionary<string, string> { ["formula-state"] = "cached" } } },
                Omissions = new[] { new ReportContentOmission { Code = "native:skipped", Scope = "notes", Count = null } },
                Entries = new[] { new ReportArchiveEntry { Name = "member", Ordinal = 2, InventorySource = ReportArchiveInventorySource.ContentReader, MemberId = "part:2", DeclaredSizeBytes = null } }
            }
        };
        var saved = JsonSerializer.Deserialize<InspectionReport>(JsonSerializer.Serialize(report))!;
        Assert.Equal(3, saved.SchemaVersion);
        Assert.Equal(ReportTextBasis.CanonicalDocumentText, saved.Content.Extraction!.TextBasis);
        Assert.Equal("2,1,2", saved.Content.Extraction.Settings["page-order"]);
        var unit = Assert.Single(saved.Content.DocumentUnits);
        Assert.Equal("page:2:occurrence:0", unit.Id);
        Assert.Equal((int?)9, unit.TextLength);
        Assert.Equal((long?)100, unit.Location!.SourceCharacterOffset);
        var diagnostic = Assert.Single(saved.Content.Diagnostics);
        Assert.True(diagnostic.IsRecoverable);
        Assert.Equal(ReportRecoveryKind.Repaired, diagnostic.Recovery);
        Assert.Equal(ReportByteSpace.PartBytes, diagnostic.Source!.ByteSpace);
        Assert.Equal("block:1", diagnostic.LogicalSource!.BlockAnchor);
        Assert.Equal("structure", diagnostic.Attributes["repair"]);
        Assert.Equal("A1", Assert.Single(saved.Content.Facts).LogicalSource!.A1Range);
        Assert.Equal("cached", Assert.Single(saved.Content.Facts).Attributes["formula-state"]);
        Assert.Null(Assert.Single(saved.Content.Omissions).Count);
        Assert.Equal("part:2", Assert.Single(saved.Content.Entries).MemberId);
        Assert.Equal(ReportArchiveInventorySource.ContentReader, Assert.Single(saved.Content.Entries).InventorySource);
        Assert.Null(Assert.Single(saved.Content.Entries).DeclaredSizeBytes);
        Assert.False(InspectionReport.SupportsSchema(0));
        Assert.False(InspectionReport.SupportsSchema(4));
    }
}
#endif
