using System.Threading;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class InspectionContentSpiTests
{
    [Fact]
    public void SnapshotCallbacksHideTheOwnerRestorePositionAndExpireEveryLease()
    {
        using var owner = new MemoryStream(new byte[] { 3, 5, 7 });
        owner.Position = 2;
        var request = Request(owner);
        Stream? retained = null;
        request.OpenRead(stream =>
        {
            retained = stream;
            Assert.IsNotType<MemoryStream>(stream);
            Assert.IsNotType<FileStream>(stream);
            Assert.True(stream.CanRead);
            Assert.True(stream.CanSeek);
            Assert.False(stream.CanWrite);
            Assert.Equal(0, stream.Position);
            Assert.Equal(3, stream.ReadByte());
            Assert.Throws<NotSupportedException>(() => stream.WriteByte(11));
            Assert.Throws<NotSupportedException>(() => stream.SetLength(0));
            Assert.Throws<InvalidOperationException>(() => request.OpenRead(other => other.ReadByte()));
            return 0;
        });
        Assert.Equal(2, owner.Position);
        Assert.True(owner.CanRead);
        Assert.False(retained!.CanRead);
        Assert.False(retained.CanSeek);
        Assert.Throws<ObjectDisposedException>(() => retained.ReadByte());
        Assert.Equal(3, request.OpenRead(stream => stream.ReadByte()));
        request.Expire();
        Assert.Throws<ObjectDisposedException>(() => request.OpenRead(stream => stream.ReadByte()));
    }

    [Fact]
    public void CallbackFailureAndLeaseDisposalLeaveTheSnapshotOwnerOpen()
    {
        using var owner = new MemoryStream(new byte[] { 2, 4 });
        owner.Position = 1;
        var request = Request(owner);
        var expected = new InvalidOperationException("provider failure");
        Assert.Same(expected, Assert.Throws<InvalidOperationException>(() => request.OpenRead<int>(stream =>
        {
            stream.ReadByte();
            stream.Dispose();
            throw expected;
        })));
        Assert.True(owner.CanRead);
        Assert.Equal(1, owner.Position);
        Assert.Equal(2, request.OpenRead(stream => stream.ReadByte()));
    }

    [Fact]
    public void SnapshotReadsObserveCancellationEvenAtEof()
    {
        using var owner = new MemoryStream(Array.Empty<byte>());
        using var cancellation = new CancellationTokenSource();
        var request = Request(owner, cancellation.Token);
        Assert.Throws<OperationCanceledException>(() => request.OpenRead(stream =>
        {
            Assert.Equal(-1, stream.ReadByte());
            cancellation.Cancel();
            return stream.ReadByte();
        }));
        Assert.True(owner.CanRead);
        Assert.Equal(0, owner.Position);
    }

    [Fact]
    public void MembersPrivatelyCopyBytesAndExposeIndependentNeutralStreams()
    {
        var bytes = new byte[] { 2, 4, 6 };
        var member = new InspectionContentMember(7, "native:7", "duplicate.txt", ReportArchiveEntryKind.File, null, bytes);
        bytes[0] = 99;
        using var first = member.OpenRead();
        using var second = member.OpenRead();
        Assert.IsNotType<MemoryStream>(first);
        Assert.IsNotType<FileStream>(first);
        Assert.False(first.CanWrite);
        Assert.Equal(3, member.SizeBytes);
        Assert.Null(member.DeclaredSizeBytes);
        Assert.Equal(2, first.ReadByte());
        Assert.Equal(2, second.ReadByte());
        Assert.Throws<NotSupportedException>(() => first.WriteByte(0));
        first.Dispose();
        Assert.Equal(4, second.ReadByte());
        Assert.False(first.CanRead);
    }

    [Fact]
    public void ResultDetachesItsMemberCollectionAndRejectsInvalidCounters()
    {
        var member = new InspectionContentMember(0, "part:1", "member", ReportArchiveEntryKind.File, 1, new byte[] { 1 });
        var members = new[] { member };
        var result = new InspectionContentReadResult(InspectionContentReadDisposition.Handled, new ContentProfile(), members, EmptyWork());
        members[0] = new InspectionContentMember(1, "part:2", "other", ReportArchiveEntryKind.File, 0, ReadOnlyMemory<byte>.Empty);
        Assert.Same(member, Assert.Single(result.SelectedMembers));
        Assert.Throws<NotSupportedException>(() => ((IList<InspectionContentMember>)result.SelectedMembers)[0] = members[0]);
        Assert.Throws<ArgumentOutOfRangeException>(() => new InspectionContentWork(0, -1, 0, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new InspectionContentMember(0, "id", "name", ReportArchiveEntryKind.File, -1, ReadOnlyMemory<byte>.Empty));
    }

    [Fact]
    public void InvocationExpiresAccessBeforeAdmissionAndHoldsTheReaderGateUntilAdmissionEnds()
    {
        using var owner = new MemoryStream(new byte[] { 1 });
        var request = Request(owner);
        Stream? retained = null;
        var reader = new Reader((source, _) =>
        {
            source.OpenRead(stream => { retained = stream; return stream.ReadByte(); });
            return Result();
        });
        var admitted = InspectionContentReaderInvoker.Invoke(reader, request, result =>
        {
            Assert.True(Monitor.IsEntered(reader));
            Assert.False(retained!.CanRead);
            Assert.Throws<ObjectDisposedException>(() => request.OpenRead(stream => stream.ReadByte()));
            return result.Content.Reader;
        }, CancellationToken.None);
        Assert.Equal("unsupported", admitted);
        Assert.False(Monitor.IsEntered(reader));
        Assert.True(owner.CanRead);
    }

    [Fact]
    public void ReentrantInvocationIsRejectedBeforeReadingAndExpiresTheNestedRequest()
    {
        using var owner = new MemoryStream(new byte[] { 1 });
        using var nestedOwner = new MemoryStream(new byte[] { 2 });
        var request = Request(owner);
        var nestedRequest = Request(nestedOwner);
        Reader? reader = null;
        var calls = 0;
        reader = new Reader((_, _) =>
        {
            calls++;
            Assert.Throws<InvalidOperationException>(() => InspectionContentReaderInvoker.Invoke(
                reader!, nestedRequest, result => result, CancellationToken.None));
            return Result();
        });
        InspectionContentReaderInvoker.Invoke(reader, request, result => result, CancellationToken.None);
        Assert.Equal(1, calls);
        Assert.Throws<ObjectDisposedException>(() => nestedRequest.OpenRead(stream => stream.ReadByte()));
    }

    [Fact]
    public void InvocationPreservesTerminalAndContractFailuresAndExpiresRequests()
    {
        using var owner = new MemoryStream(new byte[] { 1 });
        var request = Request(owner);
        var native = new IOException("native source");
        var expected = new InspectionContentLimitException(InspectionContentLimitDomain.Admission,
            "native:ratio", "CompressionRatio", 1.5, double.PositiveInfinity, native);
        var reader = new Reader((_, _) => throw expected);
        Assert.Same(expected, Assert.Throws<InspectionContentLimitException>(() =>
            InspectionContentReaderInvoker.Invoke(reader, request, result => result, CancellationToken.None)));
        Assert.Equal(1.5, expected.Maximum);
        Assert.Equal(double.PositiveInfinity, expected.Actual);
        Assert.Same(native, expected.InnerException);
        Assert.Throws<ObjectDisposedException>(() => request.OpenRead(stream => stream.ReadByte()));
        Assert.False(Monitor.IsEntered(reader));
        var nullRequest = Request(owner);
        Assert.Throws<InvalidOperationException>(() => InspectionContentReaderInvoker.Invoke(
            new Reader((_, _) => null!), nullRequest, result => result, CancellationToken.None));
        Assert.Throws<ObjectDisposedException>(() => nullRequest.OpenRead(stream => stream.ReadByte()));
    }

    [Fact]
    public async Task CanceledWaiterCannotEnterTheReaderAndItsRequestExpires()
    {
        using var owner = new MemoryStream(new byte[] { 1 });
        using var cancellation = new CancellationTokenSource();
        using var held = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        using var started = new ManualResetEventSlim();
        var request = Request(owner, cancellation.Token);
        var calls = 0;
        var reader = new Reader((_, _) => { Interlocked.Increment(ref calls); return Result(); });
        var holder = Task.Factory.StartNew(() =>
        {
            lock (reader)
            {
                held.Set();
                if (!release.Wait(TimeSpan.FromSeconds(15))) throw new TimeoutException("Test reader gate was not released.");
            }
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        try
        {
            Assert.True(held.Wait(TimeSpan.FromSeconds(5)));
            var waiter = Task.Factory.StartNew(() =>
            {
                started.Set();
                return Record.Exception(() => InspectionContentReaderInvoker.Invoke(reader, request, result => result, cancellation.Token));
            }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
            Assert.True(started.Wait(TimeSpan.FromSeconds(5)));
            cancellation.Cancel();
            Assert.Same(waiter, await Task.WhenAny(waiter, Task.Delay(TimeSpan.FromSeconds(5))));
            Assert.IsAssignableFrom<OperationCanceledException>(await waiter);
            Assert.Equal(0, calls);
        }
        finally
        {
            release.Set();
            await holder;
        }
        Assert.Throws<OperationCanceledException>(() => request.OpenRead(stream => stream.ReadByte()));
    }

    private static InspectionContentReadRequest Request(Stream owner, CancellationToken cancellationToken = default) => new(
        owner, "snapshot-sha256", owner.Length, "sample.txt", ".txt", "text/plain", ContentKind.Text, 0,
        new InspectionContentBudgets(owner.Length, 100, 10, 20, 10, 100, 100, 100, 2, 1, 20, 10, 10, 100, 100, 100), cancellationToken);

    private static InspectionContentWork EmptyWork() => new(0, 0, 0, 0);
    private static InspectionContentReadResult Result() => new(InspectionContentReadDisposition.Handled,
        new ContentProfile(), Array.Empty<InspectionContentMember>(), EmptyWork());

    private sealed class Reader : IInspectionContentReader
    {
        private readonly Func<InspectionContentReadRequest, CancellationToken, InspectionContentReadResult> _read;
        public Reader(Func<InspectionContentReadRequest, CancellationToken, InspectionContentReadResult> read) => _read = read;
        public InspectionContentReadResult Read(InspectionContentReadRequest request, CancellationToken cancellationToken = default) => _read(request, cancellationToken);
    }
}
