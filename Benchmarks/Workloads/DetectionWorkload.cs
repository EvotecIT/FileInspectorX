using System.IO.Compression;
using System.Text;

namespace FileInspectorX.Benchmarks;

/// <summary>Product workloads and integrity proof; PowerForge owns measurement policy.</summary>
public sealed class DetectionWorkload
{
    private readonly byte[] _bytes;
    private readonly string _expected;
    private readonly string _shape;
    private readonly bool _hash;
    private readonly bool _analyze;
    private readonly int _calls;
    private readonly string? _expectedHash;

    public DetectionWorkload(string scenario, string shape, int calls)
    {
        _shape = shape;
        _calls = calls;
        _hash = scenario is "Hash1MiB" or "Hash16MiB";
        _analyze = scenario == "AnalyzeDocx";
        if (scenario is "ZipDocx" or "AnalyzeDocx")
        {
            using var output = new MemoryStream();
            using (var zip = new ZipArchive(output, ZipArchiveMode.Create, true))
            {
                zip.CreateEntry("[Content_Types].xml");
                zip.CreateEntry("word/document.xml");
                for (int i = 0; i < (_analyze ? 2048 : 100); i++) zip.CreateEntry($"word/media/{i}.bin");
            }
            _bytes = output.ToArray();
            _expected = "docx";
        }
        else
        {
            int length = scenario == "Hash16MiB" ? 16 * 1024 * 1024 : scenario is "Json1MiB" or "Hash1MiB" ? 1024 * 1024 : 4096;
            _bytes = Encoding.UTF8.GetBytes("{\"name\":\"FileInspectorX\",\"count\":123,\"enabled\":true}" + new string(' ', length));
            _expected = "json";
        }
        _expectedHash = _hash ? Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(_bytes)).ToLowerInvariant() : null;
    }

    /// <summary>Runs the same complete-input work in every engine and returns integrity and allocation evidence.</summary>
    public WorkloadResult Run()
    {
        long before = GC.GetAllocatedBytesForCurrentThread();
        var options = new FileInspector.DetectionOptions { ComputeSha256 = _hash, CollectMetrics = _analyze };
        ContentTypeDetectionResult? result = null;
        int matched = 0;
        bool hashesMatch = true;
        long readOperations = 0;
        for (int i = 0; i < _calls; i++)
        {
            if (_analyze)
            {
                FileAnalysis analysis;
                if (_shape == "Stream")
                {
                    using var stream = new MemoryStream(_bytes, writable: false);
                    analysis = FileInspector.Analyze(stream, options);
                    if (stream.Position != 0) throw new InvalidOperationException("Analysis moved the caller's stream.");
                }
                else if (_shape == "Span") analysis = FileInspector.Analyze(_bytes.AsSpan(), options);
                else analysis = FileInspector.Analyze(_bytes, options);
                if (analysis.ContainerEntryCount != 2050) throw new InvalidOperationException("Analysis lost ZIP entries.");
                result = analysis.Detection;
                readOperations += analysis.Metrics?.ReadOperations ?? throw new InvalidOperationException("Analysis lost requested metrics.");
            }
            else if (_shape == "Stream")
            {
                using var stream = new MemoryStream(_bytes, writable: false);
                result = FileInspector.Detect(stream, options);
                if (stream.Position != 0) throw new InvalidOperationException("Detection moved the caller's stream.");
            }
            else if (_shape == "Span") result = FileInspector.Detect(_bytes.AsSpan(), options);
            else result = FileInspector.Detect(_bytes, options);
            if (result?.Extension == _expected) matched++;
            if (_hash && result?.Sha256Hex != _expectedHash) hashesMatch = false;
        }
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        return new WorkloadResult(_calls, matched, allocated, hashesMatch, readOperations);
    }
}

/// <summary>Observable workload proof and allocation count for one batch.</summary>
public sealed record WorkloadResult(int Calls, int Matches, long AllocatedBytes, bool HashMatches, long ReadOperations);
