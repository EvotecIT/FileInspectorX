using System.Management.Automation;
using FileInspectorX.PowerShell;

namespace FileInspectorX.Prototypes.FileSystem;

/// <summary>Evaluation-only Get-ChildItem-shaped command over the prototype C# query engine.</summary>
[Cmdlet(VerbsCommon.Get, "FileSystemItem")]
[OutputType(typeof(FileSystemEntry), typeof(FileSystemInfo), typeof(string))]
public sealed class GetFileSystemItemCommand : AsyncPSCmdlet
{
    [Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)]
    [Alias("FullName")]
    public string[] LiteralPath { get; set; } = Array.Empty<string>();
    [Parameter] public EnumerationBackend Backend { get; set; }
    [Parameter] public SwitchParameter AllowVolumeInventory { get; set; }
    [Parameter] public SwitchParameter Recurse { get; set; }
    [Parameter] [ValidateRange(0, int.MaxValue)] public int Depth { get; set; } = int.MaxValue;
    [Parameter] public SwitchParameter File { get; set; }
    [Parameter] public SwitchParameter Directory { get; set; }
    [Parameter] public SwitchParameter Force { get; set; }
    [Parameter] public string Filter { get; set; } = "*";
    [Parameter] public SwitchParameter Name { get; set; }
    [Parameter] public SwitchParameter AsFileSystemInfo { get; set; }
    [Parameter] [ValidateRange(1, long.MaxValue)] public long MaximumMftBytes { get; set; } = 512L * 1024 * 1024;
    [Parameter] [ValidateRange(1, int.MaxValue)] public int MaximumIndexRecords { get; set; } = 4_000_000;
    [Parameter] [ValidateRange(1, long.MaxValue)] public long MaximumIndexBytes { get; set; } = 2L * 1024 * 1024 * 1024;
    [Parameter] [ValidateRange(1, 3600)] public int MaximumCaptureSeconds { get; set; } = 120;
    [Parameter] public MftSnapshot? Snapshot { get; set; }
    [Parameter] public MftReadMode MftReadMode { get; set; } = MftReadMode.Bulk;

    protected override async Task ProcessRecordAsync()
    {
        // Resolve provider paths and capture bound-parameter state on the pipeline thread.
        bool recurse = Recurse || MyInvocation.BoundParameters.ContainsKey(nameof(Depth));
        var roots = new List<string>();
        foreach (var path in LiteralPath)
        {
            try
            {
                var resolved = SessionState.Path.GetUnresolvedProviderPathFromPSPath(path, out var provider, out _);
                if (provider.Name != "FileSystem") throw new PSArgumentException("Prototype supports the FileSystem provider only.");
                roots.Add(resolved);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                WriteError(new ErrorRecord(exception, "FileSystemPrototypePathResolutionFailed", ErrorCategory.InvalidArgument, path));
            }
        }
        foreach (var root in roots)
        {
            var options = new QueryOptions
            {
                Root = root, Backend = Backend, AllowVolumeInventory = AllowVolumeInventory,
                Recurse = recurse, Depth = Depth, File = File, Directory = Directory, Force = Force,
                Filter = Filter, MaximumMftBytes = MaximumMftBytes, CancellationToken = CancelToken,
                MaximumIndexRecords = MaximumIndexRecords, MaximumIndexBytes = MaximumIndexBytes,
                MaximumCaptureTime = TimeSpan.FromSeconds(MaximumCaptureSeconds), MftReadMode = MftReadMode,
                OnError = (exception, path) => WriteError(new ErrorRecord(exception, "FileSystemPrototypeDirectoryReadFailed", ErrorCategory.ReadError, path))
            };
            QueryResult result;
            try { result = await FileSystemQuery.OpenAsync(options, Snapshot).ConfigureAwait(false); }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                WriteError(new ErrorRecord(exception, "FileSystemPrototypeQueryFailed", ErrorCategory.ReadError, root));
                continue;
            }
            WriteVerbose("Backend=" + result.Backend + "; Compatibility=" + result.Compatibility + "; Fallback=" + result.FallbackReason);
            var prefix = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            try
            {
                foreach (var entry in result.Entries)
                {
                    CancelToken.ThrowIfCancellationRequested();
                    if (Name) WriteObject(entry.FullName.Substring(prefix.Length));
                    else if (AsFileSystemInfo)
                    {
                        var native = PSObject.AsPSObject(entry.ToFileSystemInfo());
                        native.Properties.Add(new PSNoteProperty("PSIsContainer", entry.PSIsContainer));
                        WriteObject(native);
                    }
                    else WriteObject(entry);
                }
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                WriteError(new ErrorRecord(exception, "FileSystemPrototypeEnumerationFailed", ErrorCategory.ReadError, root));
            }
        }
    }
}
