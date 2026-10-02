using System.IO.Compression;

namespace FileInspectorX;

/// <summary>Owns one bounded ZIP reader for the content stages of a single analysis.</summary>
internal sealed class ZipInspectionContext : IDisposable
{
    private readonly Stream? _stream;
    private readonly ZipArchive? _archive;
    private readonly bool _validDirectory;
    private readonly int? _declaredEntryCount;
    private readonly int _encryptedEntryCount;
    private readonly IReadOnlyList<string> _issues;

    internal ZipInspectionContext(InspectionInput input, ArchiveInspectionBudget budget)
    {
        // ZIP recognition retains the path detector's compatible-writer policy.
        Stream? stream = input.OpenRead(FileShare.ReadWrite | FileShare.Delete);
        try
        {
            _validDirectory = budget.CheckCentralDirectory(stream, out _declaredEntryCount);
            _encryptedEntryCount = budget.EncryptedEntryCount;
            _issues = budget.Issues;
            if (_validDirectory)
            {
                stream.Position = 0;
                _archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
                _stream = stream;
                stream = null;
            }
        }
        finally { stream?.Dispose(); }
    }

    internal bool TryOpen(ArchiveInspectionBudget budget, out ZipArchive? archive, out int? declaredEntryCount)
    {
        InspectionOperation.CheckCancellation();
        // Directory evidence is reusable; visited-entry and expanded-byte counters
        // belong to each stage's separate budget and are never carried forward.
        budget.RetainZipDirectoryEvidence(_encryptedEntryCount, _issues);
        declaredEntryCount = _declaredEntryCount;
        archive = _archive;
        return _validDirectory;
    }

    public void Dispose()
    {
        try { _archive?.Dispose(); }
        finally { _stream?.Dispose(); }
    }
}
