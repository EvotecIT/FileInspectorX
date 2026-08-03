// (deliberately no extra using requirements; compatible with net472 via System.Memory)

namespace FileInspectorX;

/// <summary>
/// Central registry of magic signatures and helpers; split across partial classes for categories (executables, archives, text/markup, media, riff/images).
/// </summary>
internal static partial class Signatures {
    /// <summary>
    /// Compact magic signature descriptor used by the detector. Internal-only: kept minimal for speed.
    /// </summary>
    internal sealed class Signature {
        /// <summary>Normalized extension to emit when the prefix matches.</summary>
        public readonly string Extension;
        /// <summary>MIME type to emit when the prefix matches.</summary>
        public readonly string MimeType;
        /// <summary>Magic prefix bytes to match.</summary>
        public readonly byte[] Prefix;
        /// <summary>Offset at which to attempt a match (0 for BOF).</summary>
        public readonly int Offset;
        /// <summary>Confidence assigned to a prefix-only match.</summary>
        public readonly string Confidence;
        public Signature(string extension, string mimeType, byte[] prefix, string confidence, int offset = 0) {
            Extension = extension; MimeType = mimeType; Prefix = prefix; Confidence = confidence; Offset = offset;
        }
    }

    // Common magic signatures (subset; easy to expand)
    internal static readonly Signature[] Core = new[] {
        new Signature("xz",   "application/x-xz",     new byte[]{0xFD,0x37,0x7A,0x58,0x5A,0x00}, "High"),
        new Signature("zst",  "application/zstd",     new byte[]{0x28,0xB5,0x2F,0xFD}, "Medium"),
    };

    /// <summary>
    /// Enumerates all known signatures (core + standard sets) used by the detector.
    /// </summary>
    internal static IEnumerable<Signature> All() {
        // Merge core list with consolidated imported signatures
        Signature[] standard;
        try { standard = Standard; } catch { standard = Array.Empty<Signature>(); }
        return Core.Concat(standard);
    }

    /// <summary>
    /// Returns true when <paramref name="src"/> contains the signature <paramref name="sig"/> at its declared offset.
    /// </summary>
    internal static bool Match(ReadOnlySpan<byte> src, Signature sig) {
        var off = sig.Offset;
        if (off < 0 || off + sig.Prefix.Length > src.Length) return false;
        return src.Slice(off, sig.Prefix.Length).SequenceEqual(sig.Prefix);
    }

    // moved riff/images matchers to Signatures.RiffAndImages.cs

    // moved executable matchers to Signatures.Executables.cs

    // moved ISO matcher to Signatures.ArchivesAndDisks.cs

    // moved UDF matcher to Signatures.ArchivesAndDisks.cs

    // moved TAR matcher to Signatures.ArchivesAndDisks.cs

    // moved SQLite matcher to Signatures.DatabasesAndMedia.cs

    // moved ftyp matcher to Signatures.DatabasesAndMedia.cs

    // moved mach-o matcher to Signatures.Executables.cs

}
