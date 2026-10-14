using System.Threading;

namespace FileInspectorX;

/// <summary>Explicit optional primary-content reader. The caller owns its lifetime; FileInspectorX never disposes it.</summary>
/// <remarks>Calls on one instance are serialized through admission. Do not lock the reader instance externally.</remarks>
public interface IInspectionContentReader
{
    /// <summary>Read one immutable source snapshot and return detached content and selected inert members.</summary>
    /// <param name="request">Source identity, remaining budgets and callback-scoped snapshot access.</param>
    /// <param name="cancellationToken">Cancellation for this synchronous operation.</param>
    /// <returns>A detached response. Only an empty NotApplicable response permits built-in primary extraction.</returns>
    InspectionContentReadResult Read(InspectionContentReadRequest request, CancellationToken cancellationToken = default);
}
