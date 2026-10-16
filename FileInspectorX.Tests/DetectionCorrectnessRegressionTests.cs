using System.Text;
using FileInspectorX;
using Xunit;

namespace FileInspectorX.Tests;

public class DetectionCorrectnessRegressionTests
{
    [Theory]
    [InlineData("{}")]
    [InlineData("[]")]
    [InlineData("[1]")]
    [InlineData("[\"value\"]")]
    public void CompleteJsonWithoutName_IsRecognizedAcrossInputs(string json)
    {
        AssertAcrossInputs(Encoding.UTF8.GetBytes(json), detection =>
        {
            Assert.Equal("json", detection.Extension);
            Assert.Equal("passed", detection.ValidationStatus);
        });
    }

    [Fact]
    public void MalformedJson_HasTheSameFailedValidationAcrossInputs()
    {
        AssertAcrossInputs(Encoding.UTF8.GetBytes("{\"a\":1,}"), detection =>
        {
            Assert.Equal("json", detection.Extension);
            Assert.Equal("Low", detection.Confidence);
            Assert.Equal("failed", detection.ValidationStatus);
            Assert.Contains("json:validation-error", detection.Reason);
        });
    }

    [Theory]
    [InlineData("{\"asset\":\"unrelated\",\"version\":1,\"nodes\":[]}")]
    [InlineData("{\"metadata\":{\"asset\":{\"version\":\"2.0\"},\"nodes\":[]}}")]
    [InlineData("{\"asset\":{\"version\":\"7.0\"},\"nodes\":[]}")]
    public void GenericJsonWithGltfWords_RemainsJson(string json)
    {
        AssertAcrossInputs(Encoding.UTF8.GetBytes(json), detection =>
        {
            Assert.Equal("json", detection.Extension);
            Assert.Equal("passed", detection.ValidationStatus);
        });
    }

    [Fact]
    public void GltfAssetVersion_IsRecognizedAcrossInputs()
    {
        AssertAcrossInputs(Encoding.UTF8.GetBytes("{\"asset\":{\"version\":\"2.0\"},\"nodes\":[]}"), detection =>
        {
            Assert.Equal("gltf", detection.Extension);
            Assert.Equal("model/gltf+json", detection.MimeType);
            Assert.Equal("passed", detection.ValidationStatus);
            Assert.Contains("schema-not-validated", detection.ReasonDetails ?? string.Empty);
        });
    }

    [Fact]
    public void CompleteForwardOnlyJson_ReceivesStructuralValidation()
    {
        using var stream = new ForwardOnlyStream(Encoding.UTF8.GetBytes("{\"asset\":{\"version\":\"2.0\"},\"nodes\":[],}"));
        var detection = FileInspector.Detect(stream);
        Assert.NotNull(detection);
        Assert.Equal("json", detection!.Extension);
        Assert.Equal("failed", detection.ValidationStatus);
    }

    [Fact]
    public void MalformedJsonWithGltfWords_DoesNotBypassValidation()
    {
        AssertAcrossInputs(Encoding.UTF8.GetBytes("{\"asset\":{\"version\":\"2.0\"},\"nodes\":[],}"), detection =>
        {
            Assert.Equal("json", detection.Extension);
            Assert.Equal("failed", detection.ValidationStatus);
        });
    }

    [Theory]
    [InlineData("Please order dim sum tomorrow.")]
    [InlineData("This document describes VBScript and the MsgBox command.")]
    [InlineData("The API path is /service:endpoint and the option is setlocal.")]
    [InlineData("For more information, use Get-Help in PowerShell.")]
    public void OrdinaryProse_DoesNotBecomeScript(string prose)
    {
        AssertAcrossInputs(Encoding.UTF8.GetBytes(prose), detection =>
        {
            Assert.Equal("txt", detection.Extension);
            Assert.False(detection.IsDangerous);
            Assert.DoesNotContain(detection.Candidates ?? Array.Empty<ContentTypeDetectionCandidate>(),
                candidate => candidate.Extension is "vbs" or "bat" or "ps1");
        });
    }

    [Theory]
    [InlineData("Dim x\nSet o = CreateObject(\"WScript.Shell\")\n", "vbs")]
    [InlineData("' Comment mentioning a program\nWScript.Echo \"hello\"\n", "vbs")]
    [InlineData("@echo off\nsetlocal\necho hello\nendlocal\n", "bat")]
    [InlineData("Get-Process | Where-Object { $_.Id -gt 4 }\n", "ps1")]
    public void ActualScripts_RetainRecognition(string script, string extension)
    {
        AssertAcrossInputs(Encoding.UTF8.GetBytes(script), detection =>
            Assert.Equal(extension, detection.Extension));
    }

    [Fact]
    public void OleWorkbookDirectory_OverridesWordMarkerInPayload()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            DetectorTests.WriteSyntheticOleDirectoryFile(path, "Workbook");
            using (var file = File.OpenWrite(path))
            {
                file.Position = 1024;
                var marker = Encoding.ASCII.GetBytes("WordDocument");
                file.Write(marker, 0, marker.Length);
            }
            AssertAcrossInputs(File.ReadAllBytes(path), detection =>
            {
                Assert.Equal("xls", detection.Extension);
                Assert.Contains("cfbf", detection.Reason);
            });
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void OlePayloadMarkersWithoutSubtypeDirectory_RemainGeneric()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            DetectorTests.WriteSyntheticOleDirectoryFile(path, "Unrelated");
            using (var file = File.OpenWrite(path))
            {
                file.Position = 1024;
                var marker = Encoding.ASCII.GetBytes("WordDocument Workbook PowerPoint Document SummaryInformation Property Directory");
                file.Write(marker, 0, marker.Length);
            }
            AssertAcrossInputs(File.ReadAllBytes(path), detection => Assert.Equal("ole2", detection.Extension));
        }
        finally { File.Delete(path); }
    }

    private static void AssertAcrossInputs(byte[] data, Action<ContentTypeDetectionResult> assert)
    {
        var memory = FileInspector.Detect(data.AsMemory());
        Assert.NotNull(memory);
        assert(memory!);
        var bytes = FileInspector.Detect(data);
        Assert.NotNull(bytes);
        assert(bytes!);
        var span = FileInspector.Detect(data.AsSpan());
        Assert.NotNull(span);
        assert(span!);
        using var stream = new MemoryStream(data);
        var streamed = FileInspector.Detect(stream);
        Assert.NotNull(streamed);
        assert(streamed!);
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            File.WriteAllBytes(path, data);
            var file = FileInspector.Detect(path);
            Assert.NotNull(file);
            assert(file!);
        }
        finally { File.Delete(path); }
    }

    private sealed class ForwardOnlyStream : MemoryStream
    {
        internal ForwardOnlyStream(byte[] data) : base(data, writable: false) { }
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    }
}
