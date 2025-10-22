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
        public Signature(string extension, string mimeType, byte[] prefix, int offset = 0) {
            Extension = extension; MimeType = mimeType; Prefix = prefix; Offset = offset;
        }
    }

    // Common magic signatures (subset; easy to expand)
    internal static readonly Signature[] Core = new[] {
        new Signature("png",  "image/png",            new byte[]{0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A}),
        new Signature("jpg",  "image/jpeg",           new byte[]{0xFF,0xD8,0xFF}),
        new Signature("gif",  "image/gif",            System.Text.Encoding.ASCII.GetBytes("GIF87a")),
        new Signature("gif",  "image/gif",            System.Text.Encoding.ASCII.GetBytes("GIF89a")),
        new Signature("pdf",  "application/pdf",      System.Text.Encoding.ASCII.GetBytes("%PDF-")),
        new Signature("zip",  "application/zip",      new byte[]{0x50,0x4B,0x03,0x04}),
        new Signature("zip",  "application/zip",      new byte[]{0x50,0x4B,0x05,0x06}),
        new Signature("zip",  "application/zip",      new byte[]{0x50,0x4B,0x07,0x08}),
        new Signature("7z",   "application/x-7z-compressed", new byte[]{0x37,0x7A,0xBC,0xAF,0x27,0x1C}),
        new Signature("rar",  "application/vnd.rar",  System.Text.Encoding.ASCII.GetBytes("Rar!\x1A\x07")),
        new Signature("gz",   "application/gzip",     new byte[]{0x1F,0x8B}),
        new Signature("bmp",  "image/bmp",            new byte[]{0x42,0x4D}),
        new Signature("ogg",  "application/ogg",      System.Text.Encoding.ASCII.GetBytes("OggS")),
        new Signature("mp3",  "audio/mpeg",          System.Text.Encoding.ASCII.GetBytes("ID3")),
        new Signature("exe",  "application/x-msdownload", new byte[]{0x4D,0x5A}), // MZ
        new Signature("ole2", "application/vnd.ms-office", new byte[]{0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1}),
        // Additional common formats
        new Signature("bz2",  "application/x-bzip2",  System.Text.Encoding.ASCII.GetBytes("BZh")),
        new Signature("xz",   "application/x-xz",     new byte[]{0xFD,0x37,0x7A,0x58,0x5A,0x00}),
        new Signature("zst",  "application/zstd",     new byte[]{0x28,0xB5,0x2F,0xFD}),
        new Signature("wasm", "application/wasm",     new byte[]{0x00,0x61,0x73,0x6D}),
        new Signature("pcapng","application/x-pcapng",new byte[]{0x0A,0x0D,0x0D,0x0A}),
        new Signature("pcap","application/vnd.tcpdump.pcap", new byte[]{0xD4,0xC3,0xB2,0xA1}),
        new Signature("pcap","application/vnd.tcpdump.pcap", new byte[]{0xA1,0xB2,0xC3,0xD4}),
        new Signature("parquet","application/vnd.apache.parquet", System.Text.Encoding.ASCII.GetBytes("PAR1")),
        new Signature("flac","audio/flac",            System.Text.Encoding.ASCII.GetBytes("fLaC")),
        new Signature("crx",  "application/x-chrome-extension", System.Text.Encoding.ASCII.GetBytes("Cr24")),
        new Signature("evtx","application/vnd.ms-windows.evtx", System.Text.Encoding.ASCII.GetBytes("ElfFile\x00")),
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
