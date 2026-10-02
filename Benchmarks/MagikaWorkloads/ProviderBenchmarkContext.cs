using System.Reflection;
using System.Runtime.Loader;

namespace FileInspectorX.Benchmarks;

/// <summary>Loads each measured provider with its own managed and native dependencies.</summary>
public sealed class ProviderBenchmarkContext : AssemblyLoadContext, IDisposable
{
    private readonly AssemblyDependencyResolver _resolver;
    private readonly string _workloadPath;
    private readonly List<IDisposable> _workloads = new();
    private bool _disposed;

    /// <summary>Creates a collectible context from a built workload dependency manifest.</summary>
    public ProviderBenchmarkContext(string root, string name) : base(name, isCollectible: true)
    {
        _workloadPath = Path.Combine(root, "FileInspectorX.Magika.BenchmarkWorkloads.dll");
        _resolver = new AssemblyDependencyResolver(_workloadPath);
    }

    /// <summary>Creates a measured session inside this provider's dependency context.</summary>
    public object CreateWorkload(string corpusPath, string operation, int threads, int calls)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var type = LoadFromAssemblyPath(_workloadPath).GetType("FileInspectorX.Benchmarks.MagikaWorkload", throwOnError: true)!;
        var workload = (IDisposable)Activator.CreateInstance(type, corpusPath, operation, threads, calls)!;
        _workloads.Add(workload);
        return workload;
    }

    /// <summary>Disposes every native session before unloading its dependencies.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { DisposeWorkloads(); }
        finally { Unload(); }
    }

    /// <summary>Closes sessions between lanes so idle native worker pools cannot compete with measurement.</summary>
    public void DisposeWorkloads()
    {
        var errors = new List<Exception>();
        try
        {
            foreach (var workload in _workloads)
                try { workload.Dispose(); } catch (Exception error) { errors.Add(error); }
        }
        finally { _workloads.Clear(); }
        if (errors.Count != 0) throw new AggregateException("Provider benchmark cleanup failed.", errors);
    }

    /// <inheritdoc />
    protected override Assembly? Load(AssemblyName assemblyName)
    {
        var path = _resolver.ResolveAssemblyToPath(assemblyName);
        return path == null ? null : LoadFromAssemblyPath(path);
    }

    /// <inheritdoc />
    protected override IntPtr LoadUnmanagedDll(string unmanagedDllName)
    {
        var path = _resolver.ResolveUnmanagedDllToPath(unmanagedDllName);
        return path == null ? IntPtr.Zero : LoadUnmanagedDllFromPath(path);
    }
}
