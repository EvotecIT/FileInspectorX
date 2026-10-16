namespace FileInspectorX;

/// <summary>How an optional reader claims or declines the detected source.</summary>
public enum InspectionContentReadDisposition
{
    /// <summary>The format was not claimed. Only empty content, members and work permit built-in fallback.</summary>
    NotApplicable,
    /// <summary>The source was handled, with possibly empty or partial primary text.</summary>
    Handled,
    /// <summary>The format was claimed but the configured profile refused it.</summary>
    Refused,
    /// <summary>The format was claimed but parsing failed.</summary>
    Malformed
}

/// <summary>Detached optional-reader output, admitted by Core before any descendant is dispatched.</summary>
public sealed class InspectionContentReadResult
{
    /// <summary>Create a response with a concrete detached member list.</summary>
    /// <remarks>Content is a portable mutable DTO; Core copies it while the reader's invocation gate remains held.</remarks>
    public InspectionContentReadResult(InspectionContentReadDisposition disposition, ContentProfile content,
        IReadOnlyList<InspectionContentMember> selectedMembers, InspectionContentWork work)
    {
        if (!Enum.IsDefined(typeof(InspectionContentReadDisposition), disposition)) throw new ArgumentOutOfRangeException(nameof(disposition));
        Disposition = disposition;
        Content = content ?? throw new ArgumentNullException(nameof(content));
        if (selectedMembers is null) throw new ArgumentNullException(nameof(selectedMembers));
        var members = new InspectionContentMember[selectedMembers.Count];
        for (var index = 0; index < members.Length; index++)
            members[index] = selectedMembers[index] ?? throw new ArgumentException("Selected members cannot contain null.", nameof(selectedMembers));
        SelectedMembers = Array.AsReadOnly(members);
        Work = work ?? throw new ArgumentNullException(nameof(work));
    }

    /// <summary>Whether the optional reader claimed this format.</summary>
    public InspectionContentReadDisposition Disposition { get; }
    /// <summary>Detached primary content, inventory and structured evidence.</summary>
    public ContentProfile Content { get; }
    /// <summary>Detached complete inert member payloads selected for Core-owned recursion.</summary>
    public IReadOnlyList<InspectionContentMember> SelectedMembers { get; }
    /// <summary>Measured native work, independent of retained payload size.</summary>
    public InspectionContentWork Work { get; }
}

/// <summary>A complete detached member payload. Identity is its reader-scoped ID and ordinal, never its name.</summary>
public sealed class InspectionContentMember
{
    private readonly byte[] _content;

    /// <summary>Create an inert member by privately copying its complete admitted bytes.</summary>
    public InspectionContentMember(int ordinal, string id, string name, ReportArchiveEntryKind kind,
        long? declaredSizeBytes, ReadOnlyMemory<byte> content)
    {
        if (ordinal < 0) throw new ArgumentOutOfRangeException(nameof(ordinal));
        if (id is null) throw new ArgumentNullException(nameof(id));
        if (id.Length == 0) throw new ArgumentException("Member identity cannot be empty.", nameof(id));
        if (!Enum.IsDefined(typeof(ReportArchiveEntryKind), kind)) throw new ArgumentOutOfRangeException(nameof(kind));
        if (declaredSizeBytes < 0) throw new ArgumentOutOfRangeException(nameof(declaredSizeBytes));
        Ordinal = ordinal;
        Id = id;
        Name = name ?? throw new ArgumentNullException(nameof(name));
        Kind = kind;
        DeclaredSizeBytes = declaredSizeBytes;
        _content = content.ToArray();
    }

    /// <summary>Zero-based source occurrence ordinal.</summary>
    public int Ordinal { get; }
    /// <summary>Reader-scoped native identity.</summary>
    public string Id { get; }
    /// <summary>Display name, retained as data.</summary>
    public string Name { get; }
    /// <summary>Native archive/member kind.</summary>
    public ReportArchiveEntryKind Kind { get; }
    /// <summary>Declared expanded size when the native source records it.</summary>
    public long? DeclaredSizeBytes { get; }
    /// <summary>Actual complete selected payload length.</summary>
    public long SizeBytes => _content.LongLength;

    /// <summary>Open an independent neutral seekable read-only stream over the private payload.</summary>
    /// <remarks>The returned stream has no host path or exposable writable buffer. The caller disposes it.</remarks>
    public Stream OpenRead() => ReportSnapshotLease.OpenDetached(_content);
}

/// <summary>Measured optional-reader work, including failed or repeated source reads.</summary>
public sealed class InspectionContentWork
{
    /// <summary>Create measured nonnegative work counters.</summary>
    public InspectionContentWork(long selectedBytes, long readBytes, long decodedBytes, long decompressionWorkBytes)
    {
        SelectedBytes = Nonnegative(selectedBytes, nameof(selectedBytes));
        ReadBytes = Nonnegative(readBytes, nameof(readBytes));
        DecodedBytes = Nonnegative(decodedBytes, nameof(decodedBytes));
        DecompressionWorkBytes = Nonnegative(decompressionWorkBytes, nameof(decompressionWorkBytes));
    }

    /// <summary>Total complete bytes selected for descendant analysis.</summary>
    public long SelectedBytes { get; }
    /// <summary>Total source bytes read, including repeated and failed operations.</summary>
    public long ReadBytes { get; }
    /// <summary>Total measured decoded native bytes.</summary>
    public long DecodedBytes { get; }
    /// <summary>Total decompression work bytes, including data not retained as selected payload.</summary>
    public long DecompressionWorkBytes { get; }

    private static long Nonnegative(long value, string name) => value >= 0 ? value : throw new ArgumentOutOfRangeException(name);
}
