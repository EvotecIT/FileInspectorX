using System.Security.Cryptography;

namespace FileInspectorX.Benchmarks;

/// <summary>Compares full directory scans over the same prebuilt filesystem corpus.</summary>
public sealed class DirectoryWorkload
{
    private readonly string _root;
    private readonly string[] _paths;
    private readonly Dictionary<string, int> _hashes;
    private readonly string _mode;
    private readonly FileInspector.DetectionOptions _options = new()
    {
        ComputeSha256 = true, CollectMetrics = true, IncludeAuthenticode = false,
        IncludePermissions = false, IncludeReferences = false, IncludeInstaller = false,
        IncludeAssessment = false, IncludeContainer = false
    };

    /// <summary>Captures expected hashes before timing and retains identical scan options.</summary>
    public DirectoryWorkload(string root, string mode)
    {
        _root = Path.GetFullPath(root);
        _mode = mode;
        _paths = Directory.GetFiles(_root).OrderBy(path => path, StringComparer.Ordinal).ToArray();
        if (_paths.Length == 0) throw new ArgumentException("The corpus contains no files.", nameof(root));
        _hashes = _paths.Select(path => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant())
            .GroupBy(hash => hash, StringComparer.Ordinal).ToDictionary(group => group.Key, group => group.Count(), StringComparer.Ordinal);
    }

    /// <summary>Runs a sequential or asynchronous scan, verifying every complete hash and result.</summary>
    public WorkloadResult Run()
    {
        // Async workers allocate on other threads. Process totals include all of
        // them; run this suite in a dedicated host and retain background outliers.
        long before = GC.GetTotalAllocatedBytes(precise: true);
        int count = 0, matches = 0;
        bool hashesMatch = true;
        var remainingHashes = new Dictionary<string, int>(_hashes, StringComparer.Ordinal);
        long reads = 0;
        void Inspect(FileAnalysis result)
        {
            count++;
            if (result.Detection?.Extension == "json" && result.AnalysisComplete) matches++;
            var hash = result.Detection?.Sha256Hex;
            if (hash != null && remainingHashes.TryGetValue(hash, out var remaining) && remaining > 0)
                remainingHashes[hash] = remaining - 1;
            else hashesMatch = false;
            reads += result.Metrics?.ReadOperations ?? throw new InvalidOperationException("Scan lost operation metrics.");
        }
        if (_mode == "Sequential")
            foreach (var result in FileInspector.AnalyzeDirectory(_root, options: _options)) Inspect(result);
        else ConsumeAsync().GetAwaiter().GetResult();
        if (count != _paths.Length) throw new InvalidOperationException("Directory scan lost or duplicated a file.");
        hashesMatch &= remainingHashes.Values.All(count => count == 0);
        return new WorkloadResult(count, matches, GC.GetTotalAllocatedBytes(precise: true) - before, hashesMatch, reads);

        async Task ConsumeAsync()
        {
            var results = _mode == "AsyncSequential" ? FileInspector.AnalyzeFilesAsync(_paths, _options)
                : _mode == "Parallel4" ? FileInspector.AnalyzeDirectoryAsync(_root, options: _options, maxDegreeOfParallelism: 4)
                : throw new ArgumentException("Use Sequential, AsyncSequential or Parallel4.");
            await foreach (var result in results) Inspect(result);
        }
    }
}
