namespace FileInspectorX.Prototypes.FileSystem;

/// <summary>Bounded streaming inventory evidence. Fingerprints detect differences; they are not cryptographic proof.</summary>
public sealed class InventorySummary
{
    public long Files { get; private set; }
    public long Directories { get; private set; }
    public long LogicalBytes { get; private set; }
    public long Errors { get; private set; }
    public ulong PathXor { get; private set; }
    public ulong PathSum { get; private set; }
    public ulong MetadataXor { get; private set; }
    public ulong MetadataSum { get; private set; }
    /// <summary>Records one path without retaining it; timestamps are UTC ticks.</summary>
    public void Add(string path, int attributes, long length, long created, long written)
    {
        if ((attributes & (int)FileAttributes.Directory) != 0) Directories++;
        else { Files++; LogicalBytes = checked(LogicalBytes + length); }
        unchecked
        {
            ulong hash = 14695981039346656037UL;
            foreach (char value in path) hash = (hash ^ value) * 1099511628211UL;
            PathXor ^= hash; PathSum += hash;
            hash = (hash ^ (ulong)attributes) * 1099511628211UL;
            hash = (hash ^ (ulong)length) * 1099511628211UL;
            hash = (hash ^ (ulong)created) * 1099511628211UL;
            hash = (hash ^ (ulong)written) * 1099511628211UL;
            MetadataXor ^= hash; MetadataSum += hash;
        }
    }
    /// <summary>Records an enumeration error without storing sensitive paths or unbounded error objects.</summary>
    public void AddError() => Errors++;
}
