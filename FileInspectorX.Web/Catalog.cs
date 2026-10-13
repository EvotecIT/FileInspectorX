using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Channels;

namespace FileInspectorX.Web;

internal sealed class Catalog : IDisposable
{
    internal const int MaxUploadBytes = 64 * 1024 * 1024;
    internal const int MaxReportBytes = 16 * 1024 * 1024;
    private const int MaxJobs = 200;
    private const long MaxStoredBytes = 512L * 1024 * 1024;
    private readonly string _root;
    private readonly Dictionary<string, Job> _jobs = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private readonly SemaphoreSlim _uploads = new(1);
    private readonly FileStream _ownership;
    private bool _disposed;
    internal Channel<string> Queue { get; } = Channel.CreateBounded<string>(16);

    internal Catalog(string root)
    {
        _root = Path.GetFullPath(root);
        Directory.CreateDirectory(_root);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(_root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        _ownership = new FileStream(Path.Combine(_root, "catalog.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        try { Recover(); }
        catch { _ownership.Dispose(); _uploads.Dispose(); throw; }
    }

    // Recovery owns the catalog before inspecting generated names. Unmatched files and
    // subdirectories are outside its namespace and are never removed.
    private void Recover()
    {
        foreach (var file in Directory.EnumerateFiles(_root))
        {
            if (!TryArtifact(file, out _, out _)) continue;
            if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("A generated catalog artifact cannot be a link.");
        }
        foreach (var file in Directory.EnumerateFiles(_root, "*.job.json"))
        {
            if (!TryArtifact(file, out var id, out var suffix) || suffix != ".job.json") continue;
            if (_jobs.Count >= MaxJobs) throw new InvalidDataException("The catalog exceeds its job limit.");
            var job = JsonSerializer.Deserialize<Job>(File.ReadAllText(file), ReportJson.Options) ?? throw new InvalidDataException("Invalid job metadata.");
            if (job.Id != id || !ValidId(job.Id) || job.SizeBytes < 0 || job.SizeBytes > MaxUploadBytes ||
                job.State is not ("queued" or "running" or "completed" or "failed"))
                throw new InvalidDataException("Invalid catalog identity or metadata.");
            _jobs.Add(job.Id, job);
        }
        foreach (var job in _jobs.Values)
        {
            bool interrupted = job.State is "queued" or "running";
            bool uploadValid = File.Exists(Blob(job.Id)) && new FileInfo(Blob(job.Id)).Length == job.SizeBytes;
            if (interrupted || !uploadValid || job.State == "completed" && !File.Exists(ReportPath(job.Id)))
            {
                job.State = "failed";
                job.Error = interrupted ? "Analysis was interrupted. Upload the file again to retry." : "Stored analysis files are missing or inconsistent. Upload the file again to retry.";
                Save(job);
            }
        }
        foreach (var file in Directory.EnumerateFiles(_root))
        {
            if (!TryArtifact(file, out var id, out var suffix)) continue;
            if (suffix.EndsWith(".tmp", StringComparison.Ordinal) || !_jobs.TryGetValue(id, out var job) ||
                suffix == ".report.json" && job.State != "completed")
                File.Delete(file);
        }
    }

    private static bool TryArtifact(string path, out string id, out string suffix)
    {
        var name = Path.GetFileName(path);
        id = name.Length >= 32 ? name.Substring(0, 32) : string.Empty;
        suffix = name.Length >= 32 ? name.Substring(32) : string.Empty;
        return ValidId(id) && suffix is ".upload" or ".job.json" or ".job.json.tmp" or ".report.json" or ".report.json.tmp";
    }

    internal string Blob(string id) => Path.Combine(_root, id + ".upload");
    internal string ReportPath(string id) => Path.Combine(_root, id + ".report.json");
    private void Save(Job job) => ReportJson.WriteAtomic(Path.Combine(_root, job.Id + ".job.json"), job);
    private static bool ValidId(string? id) => id is { Length: 32 } && id.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
    internal Job? Find(string id) { lock (_gate) return _jobs.TryGetValue(id, out var job) ? Clone(job) : null; }
    private static Job Clone(Job job) => new() { Id = job.Id, Name = job.Name, State = job.State, Sha256 = job.Sha256, SizeBytes = job.SizeBytes, CreatedUtc = job.CreatedUtc, Error = job.Error };

    internal Job[] List(string? query)
    {
        lock (_gate) return _jobs.Values.Where(j => string.IsNullOrEmpty(query) || j.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            j.Sha256?.Equals(query, StringComparison.OrdinalIgnoreCase) == true || MatchesContent(j.Id, query!))
            .OrderByDescending(j => j.CreatedUtc).Select(Clone).ToArray();
    }
    internal Job[] ListByHash(string hash)
    {
        lock (_gate) return _jobs.Values.Where(j => j.Sha256?.Equals(hash, StringComparison.OrdinalIgnoreCase) == true)
            .OrderByDescending(j => j.CreatedUtc).Select(Clone).ToArray();
    }
    private bool MatchesContent(string id, string query)
    {
        var report = Read(id);
        return report != null && (report.Content.Text.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            report.Analysis.DetectedExtension?.Contains(query, StringComparison.OrdinalIgnoreCase) == true ||
            report.Content.Keywords.Any(word => word.Contains(query, StringComparison.OrdinalIgnoreCase)));
    }
    private InspectionReport? Read(string id)
    {
        if (!ValidId(id) || !_jobs.TryGetValue(id, out var job) || job.State != "completed" || !File.Exists(ReportPath(id))) return null;
        var report = JsonSerializer.Deserialize<InspectionReport>(File.ReadAllText(ReportPath(id)), ReportJson.Options);
        return report?.SchemaVersion == 1 ? report : null;
    }
    internal WebResponse ReportResponse(string id)
    {
        lock (_gate)
        {
            if (!_jobs.TryGetValue(id, out var job)) return WebResponse.Json(404, new { error = "Report not found." });
            if (job.State != "completed" || !File.Exists(ReportPath(id))) return WebResponse.Json(200, Clone(job));
            // Capture the response while holding the catalog lock, before a concurrent deletion can remove it.
            using var document = JsonDocument.Parse(File.ReadAllText(ReportPath(id)));
            return WebResponse.Json(200, document.RootElement.Clone());
        }
    }
    internal WebResponse Similar(string id)
    {
        lock (_gate)
        {
            var source = Read(id);
            if (source == null) return WebResponse.Json(404, new { error = "Report not found." });
            var matches = _jobs.Values.Where(j => j.Id != id && j.State == "completed").Select(j =>
            {
                var other = Read(j.Id);
                return new { job = Clone(j), score = other == null ? null : ReportSimilarity.Compare(source, other), basis = other?.File.Sha256 == source.File.Sha256 ? "exact-bytes" : "extracted-text-shingles" };
            }).Where(m => m.score > 0).OrderByDescending(m => m.score).Take(20).ToArray();
            return WebResponse.Json(200, matches);
        }
    }
    internal async Task<Job> Upload(Stream body, string name, CancellationToken token)
    {
        name = name.Replace('\\', '/').Split('/').Last();
        if (string.IsNullOrWhiteSpace(name) || name.Length > 255 || name.Any(char.IsControl)) throw new InvalidDataException("The display name must be 1–255 characters without control characters.");
        await _uploads.WaitAsync(token);
        var job = new Job { Name = name };
        try
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                // Retained bytes, rather than stale metadata, determine admission after recovery.
                if (_jobs.Count >= MaxJobs || _jobs.Values.Sum(j => File.Exists(Blob(j.Id)) ? new FileInfo(Blob(j.Id)).Length : 0) > MaxStoredBytes - MaxUploadBytes)
                    throw new CatalogFullException();
            }
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            await using (var output = new FileStream(Blob(job.Id), FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                var buffer = new byte[8192];
                while (true)
                {
                    var read = await body.ReadAsync(buffer, token);
                    if (read == 0) break;
                    job.SizeBytes += read;
                    if (job.SizeBytes > MaxUploadBytes) throw new InvalidDataException("The upload exceeds 64 MiB.");
                    hash.AppendData(buffer, 0, read);
                    await output.WriteAsync(buffer.AsMemory(0, read), token);
                }
            }
            job.Sha256 = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                token.ThrowIfCancellationRequested();
                // Publish metadata before waking the worker. Roll back if the bounded queue cannot accept it.
                Save(job); _jobs.Add(job.Id, job);
                if (!Queue.Writer.TryWrite(job.Id)) { _jobs.Remove(job.Id); throw new CatalogFullException(); }
            }
            return Clone(job);
        }
        catch
        {
            foreach (var suffix in new[] { ".upload", ".job.json", ".job.json.tmp" }) File.Delete(Path.Combine(_root, job.Id + suffix));
            throw;
        }
        finally { _uploads.Release(); }
    }
    internal void Update(string id, string state, string? error = null)
    {
        lock (_gate) { ObjectDisposedException.ThrowIf(_disposed, this); var job = _jobs[id]; job.State = state; job.Error = error; Save(job); }
    }

    // A child has no catalog destination. Only the current owner publishes its bounded
    // output, and only while the job is still running in this process.
    internal void PublishReport(string id, byte[] json)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!ValidId(id) || !_jobs.TryGetValue(id, out var job) || job.State != "running" || json.Length > MaxReportBytes)
                throw new InvalidDataException("The report cannot be published for this job.");
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = ReportJson.Options.MaxDepth });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("schemaVersion", out var schema) || !schema.TryGetInt32(out var version) || version != 1 ||
                !root.TryGetProperty("file", out var file) || file.ValueKind != JsonValueKind.Object ||
                !file.TryGetProperty("name", out var name) || name.ValueKind != JsonValueKind.String || name.GetString() != job.Name ||
                !file.TryGetProperty("sizeBytes", out var size) || !size.TryGetInt64(out var length) || length != job.SizeBytes ||
                !file.TryGetProperty("sha256", out var hash) || hash.ValueKind != JsonValueKind.String || hash.GetString() != job.Sha256)
                throw new InvalidDataException("The report does not identify the uploaded bytes.");
            var previousError = job.Error;
            try
            {
                ReportJson.WriteAtomic(ReportPath(id), root);
                job.State = "completed"; job.Error = null;
                Save(job);
            }
            catch
            {
                job.State = "running"; job.Error = previousError;
                File.Delete(ReportPath(id)); File.Delete(ReportPath(id) + ".tmp");
                throw;
            }
        }
    }
    internal WebResponse Delete(string id)
    {
        lock (_gate)
        {
            if (!_jobs.TryGetValue(id, out var job)) return WebResponse.Json(404, new { error = "Report not found." });
            if (job.State is "queued" or "running") return WebResponse.Json(409, new { error = "Wait for this analysis to finish before deleting it." });
            foreach (var suffix in new[] { ".upload", ".report.json", ".report.json.tmp", ".job.json", ".job.json.tmp" }) File.Delete(Path.Combine(_root, id + suffix));
            _jobs.Remove(id);
            return WebResponse.Json(204, null);
        }
    }
    public void Dispose() { lock (_gate) { if (_disposed) return; _disposed = true; _ownership.Dispose(); _uploads.Dispose(); } }
}
