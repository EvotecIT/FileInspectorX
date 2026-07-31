using System.IO.Compression;
using Xunit;

namespace FileInspectorX.Tests;

public class ImprovementsTests {
    [Fact]
    public void Pdf_EmbeddedFiles_Flag() {
        var p = Path.GetTempFileName();
        try {
            var content = "%PDF-1.7\n1 0 obj<< /Type /Catalog >>endobj\n2 0 obj<< /Names << /EmbeddedFiles << /Names [] >> >> >>endobj\n%%EOF";
            File.WriteAllText(p, content);
            var a = FileInspector.Analyze(p);
            Assert.True((a.Flags & ContentFlags.PdfHasEmbeddedFiles) != 0);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Zip_NestedArchive_Flag() {
        var p = Path.GetTempFileName();
        var zip = p + ".zip";
        try {
            using (var fs = File.Create(zip))
            using (var za = new ZipArchive(fs, ZipArchiveMode.Create, leaveOpen: true)) {
                var entry = za.CreateEntry("inner.zip");
                using var s = entry.Open();
                var nested = TestHelpers.CreateEmptyZip();
                s.Write(nested, 0, nested.Length);
            }
            var a = FileInspector.Analyze(zip);
            Assert.True((a.Flags & ContentFlags.ContainerContainsArchives) != 0);
        } finally { if (File.Exists(p)) File.Delete(p); if (File.Exists(zip)) File.Delete(zip); }
    }

    [Fact]
    public void Tar_NestedArchive_Flag() {
        var p = Path.GetTempFileName();
        try {
            using (var fs = File.Create(p)) {
                var hdr = new byte[512];
                WriteAscii(hdr, 0, 100, "inner.zip");
                var nested = TestHelpers.CreateEmptyZip();
                WriteOctal(hdr, 124, 12, nested.Length);
                WriteAscii(hdr, 257, 5, "ustar");
                fs.Write(hdr, 0, 512);
                fs.Write(nested, 0, nested.Length);
                // pad to 512
                fs.Write(new byte[512 - nested.Length], 0, 512 - nested.Length);
                // two empty blocks terminator
                fs.Write(new byte[1024], 0, 1024);
            }
            var a = FileInspector.Analyze(p);
            Assert.True((a.Flags & ContentFlags.ContainerContainsArchives) != 0);
        } finally { if (File.Exists(p)) File.Delete(p); }

        static void WriteAscii(byte[] buf, int off, int len, string text) {
            var bytes = System.Text.Encoding.ASCII.GetBytes(text);
            Array.Copy(bytes, 0, buf, off, Math.Min(len, bytes.Length));
        }
        static void WriteOctal(byte[] buf, int off, int len, long value) {
            var s = Convert.ToString(value, 8);
            var bytes = System.Text.Encoding.ASCII.GetBytes(s);
            int pad = len - 1 - bytes.Length; // leave last for NUL
            for (int i = 0; i < pad; i++) buf[off + i] = (byte)'0';
            Array.Copy(bytes, 0, buf, off + pad, bytes.Length);
            buf[off + len - 1] = 0;
        }
    }

    [Fact]
    public void Pdf_NamesTree_Flag() {
        var p = Path.GetTempFileName();
        try {
            var content = "%PDF-1.7\n1 0 obj<< /Type /Catalog /Names << >> >>endobj\n%%EOF";
            File.WriteAllText(p, content);
            var a = FileInspector.Analyze(p);
            Assert.True((a.Flags & ContentFlags.PdfHasNamesTree) != 0);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Js_Minified_Flag() {
        var p = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".js");
        try {
            var sb = new System.Text.StringBuilder();
            sb.Append('a', 8000);
            sb.Append("var x=1;function f(){return x+1;}");
            File.WriteAllText(p, sb.ToString());
            var a = FileInspector.Analyze(p);
            Assert.True((a.Flags & ContentFlags.JsLooksMinified) != 0);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }
}
