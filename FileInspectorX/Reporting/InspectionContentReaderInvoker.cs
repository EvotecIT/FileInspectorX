using System.Threading;

namespace FileInspectorX;

/// <summary>Serializes caller-owned readers through response admission without retaining a global instance registry.</summary>
internal static class InspectionContentReaderInvoker
{
    /// <summary>Read once, expire source access immediately, and admit detached output while the reader gate remains held.</summary>
    /// <remarks>Descendant dispatch must occur after this method returns. No invocation failure enables fallback.</remarks>
    internal static T Invoke<T>(IInspectionContentReader reader, InspectionContentReadRequest request,
        Func<InspectionContentReadResult, T> admit, CancellationToken cancellationToken)
    {
        if (reader is null) throw new ArgumentNullException(nameof(reader));
        if (request is null) throw new ArgumentNullException(nameof(request));
        if (admit is null) throw new ArgumentNullException(nameof(admit));
        var entered = false;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Monitor.IsEntered(reader)) throw new InvalidOperationException("Reentrant content-reader invocation is not supported.");
            while (!entered)
            {
                cancellationToken.ThrowIfCancellationRequested();
                Monitor.TryEnter(reader, 50, ref entered);
            }
            cancellationToken.ThrowIfCancellationRequested();
            InspectionContentReadResult result;
            try
            {
                result = reader.Read(request, cancellationToken)
                    ?? throw new InvalidOperationException("The content reader returned a null response.");
            }
            finally
            {
                request.Expire();
            }
            cancellationToken.ThrowIfCancellationRequested();
            var admitted = admit(result);
            cancellationToken.ThrowIfCancellationRequested();
            return admitted;
        }
        finally
        {
            // This also expires a request whose invocation was canceled while waiting for its reader.
            try { request.Expire(); }
            finally { if (entered) Monitor.Exit(reader); }
        }
    }
}
