using System.IO.Compression;

using Xunit;

using FI = FileInspectorX.FileInspector;

namespace FileInspectorX.Tests;

public class DetectorTests {
    [Fact]
    public void Detect_Png_ByMagic() {
        var tmp = Path.GetTempFileName();
        var png = tmp + ".png";
        try {
            File.WriteAllBytes(tmp, new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A });
            File.Move(tmp, png);
            var res = FI.Detect(png);
            Assert.NotNull(res);
            Assert.Equal("png", res!.Extension);
            Assert.Equal("image/png", res.MimeType);
            Assert.Equal("High", res.Confidence);
        } finally { if (File.Exists(tmp)) File.Delete(tmp); if (File.Exists(png)) File.Delete(png); }
    }

    [Fact]
    public void Detect_Elf64_Little() {
        var elf = Path.GetTempFileName();
        try {
            var buf = new byte[64];
            buf[0] = 0x7F; buf[1] = (byte)'E'; buf[2] = (byte)'L'; buf[3] = (byte)'F';
            buf[4] = 2; // 64-bit
            buf[5] = 1; // little-endian
            File.WriteAllBytes(elf, buf);
            var res = FI.Detect(elf);
            Assert.NotNull(res);
            Assert.Equal("elf", res!.Extension);
            Assert.Equal("application/x-elf", res.MimeType);
            Assert.StartsWith("elf:64-le", res.Reason);
        } finally { if (File.Exists(elf)) File.Delete(elf); }
    }

    [Fact]
    public void Detect_Iso_Cd001() {
        var iso = Path.GetTempFileName();
        try {
            var size = 0x9001 + 10; // ensure large enough buffer
            var buf = new byte[size];
            // put "CD001" at 0x8001
            System.Text.Encoding.ASCII.GetBytes("CD001").CopyTo(buf, 0x8001);
            File.WriteAllBytes(iso, buf);
            var res = FI.Detect(iso);
            Assert.NotNull(res);
            Assert.Equal("iso", res!.Extension);
            Assert.Equal("application/x-iso9660-image", res.MimeType);
        } finally { if (File.Exists(iso)) File.Delete(iso); }
    }

    [Fact]
    public void Detect_M4A_ByFtypBrand() {
        var m4a = Path.GetTempFileName();
        try {
            var buf = new byte[24];
            System.Text.Encoding.ASCII.GetBytes("ftyp").CopyTo(buf, 4);
            System.Text.Encoding.ASCII.GetBytes("M4A ").CopyTo(buf, 8); // major brand
            File.WriteAllBytes(m4a, buf);
            var res = FI.Detect(m4a);
            Assert.NotNull(res);
            Assert.Equal("m4a", res!.Extension);
            Assert.Equal("audio/mp4", res.MimeType);
        } finally { if (File.Exists(m4a)) File.Delete(m4a); }
    }

    [Fact]
    public void Detect_Text_Json() {
        var json = Path.GetTempFileName();
        try {
            File.WriteAllText(json, "{\"a\":1}");
            var res = FI.Detect(json);
            Assert.NotNull(res);
            Assert.Equal("json", res!.Extension);
            Assert.Equal("application/json", res.MimeType);
        } finally { if (File.Exists(json)) File.Delete(json); }
    }

    [Fact]
    public void Detect_Text_Html() {
        var html = Path.GetTempFileName();
        try {
            File.WriteAllText(html, "<!DOCTYPE html><html><head><title>x</title></head><body></body></html>");
            var res = FI.Detect(html);
            Assert.NotNull(res);
            Assert.Equal("html", res!.Extension);
            Assert.Equal("text/html", res.MimeType);
        } finally { if (File.Exists(html)) File.Delete(html); }
    }

    [Fact]
    public void Detect_Docx_ByZipRefinement() {
        var path = Path.GetTempFileName();
        var docx = path + ".zip"; // name does not matter; content does
        try {
            using (var fs = File.Create(docx))
            using (var za = new ZipArchive(fs, ZipArchiveMode.Create, leaveOpen: true)) {
                za.CreateEntry("[Content_Types].xml");
                za.CreateEntry("_rels/.rels");
                za.CreateEntry("word/document.xml");
            }
            var res = FI.Detect(docx);
            Assert.NotNull(res);
            Assert.Equal("docx", res!.Extension);
            Assert.Equal("application/vnd.openxmlformats-officedocument.wordprocessingml.document", res.MimeType);
            Assert.Equal("High", res.Confidence);
        } finally { if (File.Exists(path)) File.Delete(path); if (File.Exists(docx)) File.Delete(docx); }
    }

    [Fact]
    public void Detect_Tar_ByUstar() {
        var tar = Path.GetTempFileName();
        try {
            var buf = new byte[600];
            // place 'ustar' at offset 257
            System.Text.Encoding.ASCII.GetBytes("ustar").CopyTo(buf, 257);
            File.WriteAllBytes(tar, buf);
            var res = FI.Detect(tar);
            Assert.NotNull(res);
            Assert.Equal("tar", res!.Extension);
            Assert.Equal("application/x-tar", res.MimeType);
        } finally { if (File.Exists(tar)) File.Delete(tar); }
    }

    [Fact]
    public void Detect_Sqlite() {
        var db = Path.GetTempFileName();
        try {
            var sig = System.Text.Encoding.ASCII.GetBytes("SQLite format 3\0");
            File.WriteAllBytes(db, sig);
            var res = FI.Detect(db);
            Assert.NotNull(res);
            Assert.Equal("sqlite", res!.Extension);
            Assert.Equal("application/vnd.sqlite3", res.MimeType);
        } finally { if (File.Exists(db)) File.Delete(db); }
    }

    [Fact]
    public void Detect_Riff_Wave() {
        var wav = Path.GetTempFileName();
        try {
            var buf = new byte[16];
            System.Text.Encoding.ASCII.GetBytes("RIFF").CopyTo(buf, 0);
            // size (ignored)
            // WAVE
            System.Text.Encoding.ASCII.GetBytes("WAVE").CopyTo(buf, 8);
            File.WriteAllBytes(wav, buf);
            var res = FI.Detect(wav);
            Assert.NotNull(res);
            Assert.Equal("wav", res!.Extension);
            Assert.Equal("audio/wav", res.MimeType);
        } finally { if (File.Exists(wav)) File.Delete(wav); }
    }

    [Fact]
    public void Detect_Ftyp_Mp4() {
        var mp4 = Path.GetTempFileName();
        try {
            var buf = new byte[16];
            // size 0..3 ignored, set ftyp at 4..7
            System.Text.Encoding.ASCII.GetBytes("ftyp").CopyTo(buf, 4);
            System.Text.Encoding.ASCII.GetBytes("isom").CopyTo(buf, 8);
            File.WriteAllBytes(mp4, buf);
            var res = FI.Detect(mp4);
            Assert.NotNull(res);
            Assert.Equal("mp4", res!.Extension);
            Assert.Equal("video/mp4", res.MimeType);
        } finally { if (File.Exists(mp4)) File.Delete(mp4); }
    }

    [Fact]
    public void Detect_Ftyp_Heic() {
        var heic = Path.GetTempFileName();
        try {
            var buf = new byte[16];
            System.Text.Encoding.ASCII.GetBytes("ftyp").CopyTo(buf, 4);
            System.Text.Encoding.ASCII.GetBytes("heic").CopyTo(buf, 8);
            File.WriteAllBytes(heic, buf);
            var res = FI.Detect(heic);
            Assert.NotNull(res);
            Assert.Equal("heic", res!.Extension);
            Assert.Equal("image/heic", res.MimeType);
        } finally { if (File.Exists(heic)) File.Delete(heic); }
    }

    [Fact]
    public void Detect_BZip2_FromImportedTable() {
        var bz = Path.GetTempFileName();
        try {
            File.WriteAllBytes(bz, new byte[] { 0x42, 0x5A, 0x68 });
            var res = FI.Detect(bz);
            Assert.NotNull(res);
            Assert.Equal("bz2", res!.Extension);
        } finally { if (File.Exists(bz)) File.Delete(bz); }
    }

    [Fact]
    public void Detect_Rtf_Text() {
        var p = Path.GetTempFileName();
        try {
            File.WriteAllText(p, "{\\rtf1\\ansi \\deff0 \\fonttbl{} }");
            var res = FI.Detect(p);
            Assert.NotNull(res);
            Assert.Equal("rtf", res!.Extension);
            Assert.Equal("application/rtf", res.MimeType);
            Assert.True(global::FileInspectorX.InspectHelpers.IsText(res));
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Detect_Yaml_Text() {
        var p = Path.GetTempFileName();
        try {
            File.WriteAllText(p, "---\nname: test\nvalue: 1\n");
            var res = FI.Detect(p);
            Assert.NotNull(res);
            Assert.Equal("yml", res!.Extension);
            Assert.Equal("application/x-yaml", res.MimeType);
            Assert.True(global::FileInspectorX.InspectHelpers.IsText(res));
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Detect_Glb_Binary() {
        var p = Path.GetTempFileName();
        try {
            var buf = new byte[12];
            System.Text.Encoding.ASCII.GetBytes("glTF").CopyTo(buf, 0);
            File.WriteAllBytes(p, buf);
            var res = FI.Detect(p);
            Assert.NotNull(res);
            Assert.Equal("glb", res!.Extension);
            Assert.Equal("model/gltf-binary", res.MimeType);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Detect_Tiff_BigEndian() {
        var p = Path.GetTempFileName();
        try {
            var buf = new byte[] { 0x4D, 0x4D, 0x00, 0x2A, 0, 0, 0, 0 };
            File.WriteAllBytes(p, buf);
            var res = FI.Detect(p);
            Assert.NotNull(res);
            Assert.Equal("tif", res!.Extension);
            Assert.Equal("image/tiff", res.MimeType);
            Assert.Contains("tiff:be", res.Reason);
            Assert.True(global::FileInspectorX.InspectHelpers.IsImage(res));
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Detect_Cab() {
        var p = Path.GetTempFileName();
        try {
            File.WriteAllBytes(p, new byte[] { (byte)'M', (byte)'S', (byte)'C', (byte)'F', 0, 0, 0, 0 });
            var res = FI.Detect(p);
            Assert.NotNull(res);
            Assert.Equal("cab", res!.Extension);
            Assert.Equal("application/vnd.ms-cab-compressed", res.MimeType);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Analyze_Tar_Names_Flags() {
        var p = Path.GetTempFileName();
        try {
            // Build a tiny tar with one file "script.sh" size 1, with ustar signature
            byte[] hdr = new byte[512];
            WriteAscii(hdr, 0, 100, "script.sh");
            WriteOctal(hdr, 124, 12, 1); // size
            WriteAscii(hdr, 257, 6, "ustar\0");
            var data = new byte[512]; data[0] = 0x41; // 'A'
            using (var fs = File.Create(p)) {
                fs.Write(hdr, 0, 512);
                fs.Write(data, 0, 512);
                fs.Write(new byte[1024], 0, 1024); // two empty blocks terminator
            }
            var det = FI.Detect(p);
            Assert.NotNull(det);
            Assert.Equal("tar", det!.Extension);
            var analysis = global::FileInspectorX.FileInspector.Analyze(p);
            Assert.True((analysis.Flags & global::FileInspectorX.ContentFlags.ContainerContainsScripts) != 0);
            Assert.Equal(1, analysis.ContainerEntryCount);
            Assert.Contains("sh", analysis.ContainerTopExtensions!);
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
    public void Detect_Udf_Nsr03() {
        var p = Path.GetTempFileName();
        try {
            // place NSR03 at 0x8001
            int offset = 0x8001;
            var buf = new byte[offset + 5];
            System.Text.Encoding.ASCII.GetBytes("NSR03").CopyTo(buf, offset);
            File.WriteAllBytes(p, buf);
            var res = FI.Detect(p);
            Assert.NotNull(res);
            Assert.Equal("udf", res!.Extension);
            Assert.Equal("application/udf", res.MimeType);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Detect_MachO_64LE() {
        var p = Path.GetTempFileName();
        try {
            // magic CFFA ED FE
            File.WriteAllBytes(p, new byte[] { 0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0 });
            var res = FI.Detect(p);
            Assert.NotNull(res);
            Assert.Equal("macho", res!.Extension);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Detect_Msg_Basic() {
        var p = Path.GetTempFileName();
        try {
            var list = new List<byte>();
            list.AddRange(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 });
            list.AddRange(new byte[128]);
            list.AddRange(System.Text.Encoding.ASCII.GetBytes("__substg1.0_007D"));
            File.WriteAllBytes(p, list.ToArray());
            var res = FI.Detect(p);
            Assert.NotNull(res);
            Assert.Equal("msg", res!.Extension);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Classify_ContentKind_Works() {
        var p = Path.GetTempFileName();
        try {
            File.WriteAllBytes(p, new byte[] { 0x50, 0x4B, 0x03, 0x04 }); // zip
            var res = FI.Detect(p);
            var kind = global::FileInspectorX.KindClassifier.Classify(res);
            Assert.Equal(global::FileInspectorX.ContentKind.Archive, kind);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }

    [Fact]
    public void Guess_Zip_Subtypes_Jar() {
        var p = Path.GetTempFileName();
        var zip = p + ".zip";
        try {
            using (var fs = File.Create(zip))
            using (var za = new ZipArchive(fs, ZipArchiveMode.Create, leaveOpen: true)) {
                za.CreateEntry("META-INF/MANIFEST.MF");
            }
            var res = FI.Detect(zip);
            Assert.NotNull(res);
            Assert.Equal("zip", res!.Extension);
            Assert.Equal("jar", res.GuessedExtension);
        } finally { if (File.Exists(p)) File.Delete(p); if (File.Exists(zip)) File.Delete(zip); }
    }

    [Fact]
    public void Guess_Zip_Subtypes_Epub() {
        var p = Path.GetTempFileName();
        var zip = p + ".zip";
        try {
            using (var fs = File.Create(zip))
            using (var za = new ZipArchive(fs, ZipArchiveMode.Create, leaveOpen: true)) {
                var entry = za.CreateEntry("mimetype");
                using var s = entry.Open();
                using var sw = new StreamWriter(s);
                sw.Write("application/epub+zip");
            }
            var res = FI.Detect(zip);
            Assert.NotNull(res);
            Assert.Equal("zip", res!.Extension);
            Assert.Equal("epub", res.GuessedExtension);
        } finally { if (File.Exists(p)) File.Delete(p); if (File.Exists(zip)) File.Delete(zip); }
    }

    [Fact]
    public void Guess_Zip_Subtypes_Vsix() {
        var p = Path.GetTempFileName();
        var zip = p + ".zip";
        try {
            using (var fs = File.Create(zip))
            using (var za = new ZipArchive(fs, ZipArchiveMode.Create, leaveOpen: true)) {
                za.CreateEntry("extension.vsixmanifest");
            }
            var res = FI.Detect(zip);
            Assert.NotNull(res);
            Assert.Equal("zip", res!.Extension);
            Assert.Equal("vsix", res.GuessedExtension);
        } finally { if (File.Exists(p)) File.Delete(p); if (File.Exists(zip)) File.Delete(zip); }
    }

    [Fact]
    public void Udf_High_When_Bea_Before_Nsr_And_Tea_After() {
        var p = Path.GetTempFileName();
        try {
            const int sector = 2048;
            long start = 16 * sector + 1;
            var len = (int)(start + 3 * sector + 8);
            var buf = new byte[len];
            System.Text.Encoding.ASCII.GetBytes("BEA01").CopyTo(buf, (int)start + 0 * sector);
            System.Text.Encoding.ASCII.GetBytes("NSR03").CopyTo(buf, (int)start + 1 * sector);
            System.Text.Encoding.ASCII.GetBytes("TEA01").CopyTo(buf, (int)start + 2 * sector);
            File.WriteAllBytes(p, buf);
            var res = FI.Detect(p);
            Assert.NotNull(res);
            Assert.Equal("udf", res!.Extension);
            Assert.Equal("application/udf", res.MimeType);
            Assert.Contains("bea+tea", res.Reason);
            Assert.Equal("High", res.Confidence);
        } finally { if (File.Exists(p)) File.Delete(p); }
    }
}