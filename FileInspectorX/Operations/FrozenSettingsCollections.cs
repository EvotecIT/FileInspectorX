using System.Collections;
using System.Collections.ObjectModel;

namespace FileInspectorX;

internal static class FrozenSettingsCollections
{
    internal static readonly IReadOnlyList<string> EmptyStrings = Array.AsReadOnly(Array.Empty<string>());
    internal static readonly IReadOnlyDictionary<string, int> EmptyScores = new DictionarySnapshot<int>(new Dictionary<string, int>());
    internal static readonly IReadOnlyDictionary<string, string> EmptyHashes = new DictionarySnapshot<string>(new Dictionary<string, string>());

    internal static IReadOnlyList<string> CopyList(IEnumerable<string> values)
    {
        if (values == null) throw new ArgumentNullException(nameof(values));
        var copy = values.ToArray();
        return copy.Length == 0 ? EmptyStrings : Array.AsReadOnly(copy);
    }

    internal static IReadOnlyDictionary<string, T> CopyDictionary<T>(IEnumerable<KeyValuePair<string, T>> values, IEqualityComparer<string>? explicitComparer = null)
    {
        if (values == null) throw new ArgumentNullException(nameof(values));
        if (values is DictionarySnapshot<T>) return (IReadOnlyDictionary<string, T>)values;
        if (explicitComparer == null && values is SortedDictionary<string, T> sorted)
            return new DictionarySnapshot<T>(new SortedDictionary<string, T>(sorted, sorted.Comparer));
        var comparer = explicitComparer ?? (values is Dictionary<string, T> dictionary ? dictionary.Comparer : StringComparer.Ordinal);
        if (values is System.Collections.Concurrent.ConcurrentDictionary<string, T> concurrent)
        {
#if NET8_0_OR_GREATER
            comparer = explicitComparer ?? concurrent.Comparer;
#else
            // These reference assemblies do not expose ConcurrentDictionary.Comparer. Callers
            // replacing the built-in dictionary provide its comparer when explicitly capturing.
            comparer = explicitComparer ?? (ReferenceEquals(values, Settings.DefaultScoreAdjustments)
                ? StringComparer.OrdinalIgnoreCase
                : throw new ArgumentException("Supply the score comparer when capturing a custom ConcurrentDictionary on this target.", nameof(values)));
#endif
        }
        var copy = new Dictionary<string, T>(comparer);
        foreach (var pair in values) copy.Add(pair.Key, pair.Value);
        return new DictionarySnapshot<T>(copy);
    }

    private sealed class DictionarySnapshot<T> : ReadOnlyDictionary<string, T>
    {
        internal DictionarySnapshot(IDictionary<string, T> values) : base(values) { }
    }

    // The ISet view is used only by existing internal policy code. Its mutators fail closed,
    // including when a caller casts the public IReadOnlyCollection view back to ISet.
    internal sealed class StringSet : ISet<string>, IReadOnlyCollection<string>
    {
        private readonly ISet<string> _values;

        internal StringSet(IEnumerable<string> values)
        {
            _values = values is StringSet frozen ? frozen._values : values is SortedSet<string> sorted
                ? new SortedSet<string>(sorted, sorted.Comparer)
                : new HashSet<string>(values, values is HashSet<string> hash ? hash.Comparer : StringComparer.OrdinalIgnoreCase);
        }

        public int Count => _values.Count;
        public bool IsReadOnly => true;
        public bool Contains(string item) => _values.Contains(item);
        public void CopyTo(string[] array, int arrayIndex) => _values.CopyTo(array, arrayIndex);
        public IEnumerator<string> GetEnumerator() => _values.GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        public bool IsProperSubsetOf(IEnumerable<string> other) => _values.IsProperSubsetOf(other);
        public bool IsProperSupersetOf(IEnumerable<string> other) => _values.IsProperSupersetOf(other);
        public bool IsSubsetOf(IEnumerable<string> other) => _values.IsSubsetOf(other);
        public bool IsSupersetOf(IEnumerable<string> other) => _values.IsSupersetOf(other);
        public bool Overlaps(IEnumerable<string> other) => _values.Overlaps(other);
        public bool SetEquals(IEnumerable<string> other) => _values.SetEquals(other);
        public bool Add(string item) => throw new NotSupportedException("Inspection settings are immutable.");
        void ICollection<string>.Add(string item) => throw new NotSupportedException("Inspection settings are immutable.");
        public void Clear() => throw new NotSupportedException("Inspection settings are immutable.");
        public bool Remove(string item) => throw new NotSupportedException("Inspection settings are immutable.");
        public void ExceptWith(IEnumerable<string> other) => throw new NotSupportedException("Inspection settings are immutable.");
        public void IntersectWith(IEnumerable<string> other) => throw new NotSupportedException("Inspection settings are immutable.");
        public void SymmetricExceptWith(IEnumerable<string> other) => throw new NotSupportedException("Inspection settings are immutable.");
        public void UnionWith(IEnumerable<string> other) => throw new NotSupportedException("Inspection settings are immutable.");
    }
}
