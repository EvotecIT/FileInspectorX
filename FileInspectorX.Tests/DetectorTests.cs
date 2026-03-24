using System.IO.Compression;
using System.Runtime.InteropServices;

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
    public void Analyze_Rar5_With_Encrypted_Headers_Flags_Archive() {
        var rar = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".rar");
        try {
            File.WriteAllBytes(rar, CreateMinimalRar5Archive(headersEncrypted: true));

            var analysis = FI.Analyze(rar);

            Assert.Contains("rar5:headers-encrypted", analysis.SecurityFindings ?? Array.Empty<string>());
            Assert.True((analysis.Flags & global::FileInspectorX.ContentFlags.ArchiveHasEncryptedEntries) != 0);
        } finally { if (File.Exists(rar)) File.Delete(rar); }
    }

    [Fact]
    public void Analyze_Rar5_Without_Encrypted_Headers_DoesNotFlag_HeadersEncrypted() {
        var rar = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".rar");
        try {
            File.WriteAllBytes(rar, CreateMinimalRar5Archive(headersEncrypted: false));

            var analysis = FI.Analyze(rar);

            Assert.DoesNotContain("rar5:headers-encrypted", analysis.SecurityFindings ?? Array.Empty<string>());
            Assert.True((analysis.Flags & global::FileInspectorX.ContentFlags.ArchiveHasEncryptedEntries) == 0);
        } finally { if (File.Exists(rar)) File.Delete(rar); }
    }

    [Fact]
    public void Analyze_Rar4_With_File_Headers_Exposes_Container_Summary()
    {
        var rar = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".rar");
        try
        {
            File.WriteAllBytes(rar, CreateMinimalRar4ArchiveWithFiles(
                "payload.exe",
                "scripts\\deploy.ps1",
                "nested\\inner.zip"));

            var analysis = FI.Analyze(rar);

            Assert.Equal(3, analysis.ContainerEntryCount);
            Assert.NotNull(analysis.ContainerTopExtensions);
            Assert.Contains("exe", analysis.ContainerTopExtensions!);
            Assert.Contains("ps1", analysis.ContainerTopExtensions!);
            Assert.Contains("zip", analysis.ContainerTopExtensions!);
            Assert.True((analysis.Flags & global::FileInspectorX.ContentFlags.ContainerContainsExecutables) != 0);
            Assert.True((analysis.Flags & global::FileInspectorX.ContentFlags.ContainerContainsScripts) != 0);
            Assert.True((analysis.Flags & global::FileInspectorX.ContentFlags.ContainerContainsArchives) != 0);
            Assert.NotNull(analysis.ArchivePreviewEntries);
            Assert.Contains(analysis.ArchivePreviewEntries!, p => string.Equals(p.Name, "payload.exe", StringComparison.Ordinal));
            Assert.Contains(analysis.ArchivePreviewEntries!, p => string.Equals(p.Name, "scripts\\deploy.ps1", StringComparison.Ordinal));
            Assert.Contains(analysis.ArchivePreviewEntries!, p => string.Equals(p.Name, "nested\\inner.zip", StringComparison.Ordinal));
            Assert.NotNull(analysis.InnerExecutableExtCounts);
            Assert.True(analysis.InnerExecutableExtCounts!.TryGetValue("exe", out var exeCount) && exeCount == 1);
            Assert.Contains("rar4:enc=0/3", analysis.SecurityFindings ?? Array.Empty<string>());
        }
        finally { if (File.Exists(rar)) File.Delete(rar); }
    }

    [Fact]
    public void Analyze_7z_With_Encrypted_Headers_Flags_Archive() {
        var sevenZip = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".7z");
        try {
            File.WriteAllBytes(sevenZip, CreateMinimal7zArchive(headersEncrypted: true));

            var analysis = FI.Analyze(sevenZip);

            Assert.Contains("7z:headers-encrypted", analysis.SecurityFindings ?? Array.Empty<string>());
            Assert.True((analysis.Flags & global::FileInspectorX.ContentFlags.ArchiveHasEncryptedEntries) != 0);
        } finally { if (File.Exists(sevenZip)) File.Delete(sevenZip); }
    }

    [Fact]
    public void Analyze_7z_Without_Encrypted_Headers_DoesNotFlag_HeadersEncrypted() {
        var sevenZip = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".7z");
        try {
            File.WriteAllBytes(sevenZip, CreateMinimal7zArchive(headersEncrypted: false));

            var analysis = FI.Analyze(sevenZip);

            Assert.DoesNotContain("7z:headers-encrypted", analysis.SecurityFindings ?? Array.Empty<string>());
            Assert.True((analysis.Flags & global::FileInspectorX.ContentFlags.ArchiveHasEncryptedEntries) == 0);
        } finally { if (File.Exists(sevenZip)) File.Delete(sevenZip); }
    }

    [Fact]
    public void Analyze_7z_With_Plain_Header_Names_Exposes_Container_Summary()
    {
        var sevenZip = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".7z");
        try
        {
            File.WriteAllBytes(sevenZip, CreateMinimal7zArchiveWithNames(
                "payload.exe",
                "scripts\\deploy.ps1",
                "nested\\inner.zip"));

            var analysis = FI.Analyze(sevenZip);

            Assert.Equal(3, analysis.ContainerEntryCount);
            Assert.NotNull(analysis.ContainerTopExtensions);
            Assert.Contains("exe", analysis.ContainerTopExtensions!);
            Assert.Contains("ps1", analysis.ContainerTopExtensions!);
            Assert.Contains("zip", analysis.ContainerTopExtensions!);
            Assert.True((analysis.Flags & global::FileInspectorX.ContentFlags.ContainerContainsExecutables) != 0);
            Assert.True((analysis.Flags & global::FileInspectorX.ContentFlags.ContainerContainsScripts) != 0);
            Assert.True((analysis.Flags & global::FileInspectorX.ContentFlags.ContainerContainsArchives) != 0);
            Assert.NotNull(analysis.ArchivePreviewEntries);
            Assert.Contains(analysis.ArchivePreviewEntries!, p => string.Equals(p.Name, "payload.exe", StringComparison.Ordinal));
            Assert.Contains(analysis.ArchivePreviewEntries!, p => string.Equals(p.Name, "scripts\\deploy.ps1", StringComparison.Ordinal));
            Assert.Contains(analysis.ArchivePreviewEntries!, p => string.Equals(p.Name, "nested\\inner.zip", StringComparison.Ordinal));
            Assert.NotNull(analysis.InnerExecutableExtCounts);
            Assert.True(analysis.InnerExecutableExtCounts!.TryGetValue("exe", out var exeCount) && exeCount == 1);
            Assert.Contains("7z:files=3", analysis.SecurityFindings ?? Array.Empty<string>());
            Assert.Contains("7z:names-exe=1", analysis.SecurityFindings ?? Array.Empty<string>());
        }
        finally { if (File.Exists(sevenZip)) File.Delete(sevenZip); }
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
    public void Detect_Minidump_ByMagic()
    {
        var dump = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".dmp");
        try
        {
            var buf = new byte[32];
            System.Text.Encoding.ASCII.GetBytes("MDMP").CopyTo(buf, 0);
            File.WriteAllBytes(dump, buf);

            var res = FI.Detect(dump);

            Assert.NotNull(res);
            Assert.Equal("dmp", res!.Extension);
            Assert.Equal("application/x-ms-minidump", res.MimeType);
            Assert.Equal("High", res.Confidence);
        }
        finally
        {
            if (File.Exists(dump)) File.Delete(dump);
        }
    }

    [Fact]
    public void Detect_ValidPe_UpgradesConfidence_FromParsedHeader()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return;
        }

        const string samplePath = @"C:\Windows\System32\notepad.exe";
        if (!File.Exists(samplePath))
        {
            return;
        }

        var res = FI.Detect(samplePath);

        Assert.NotNull(res);
        Assert.True(res!.Extension is "exe" or "dll" or "sys");
        Assert.Equal("High", res.Confidence);
        Assert.Contains("pe:header", res.Reason ?? string.Empty);
    }

    [Fact]
    public void Detect_ProtectedDump_ByHeader()
    {
        var dump = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".protected.dmp");
        try
        {
            var buf = new byte[64];
            byte[] signature =
            {
                0xF3, 0x0E, 0x3E, 0xA1, 0x71, 0xD5, 0xAF, 0x4E,
                0x9F, 0xBB, 0xF8, 0x0D, 0x0B, 0x19, 0xA3, 0xC0,
                0x6A, 0x1C, 0x50, 0x10, 0xE1, 0x7A, 0xD4, 0x4B,
                0x8D, 0x2F, 0x12, 0x78, 0x3C, 0x02, 0x74, 0x82
            };
            signature.CopyTo(buf, 0);
            BitConverter.GetBytes(2u).CopyTo(buf, 0x20);
            BitConverter.GetBytes(0x40u).CopyTo(buf, 0x24);
            BitConverter.GetBytes(0x21Bu).CopyTo(buf, 0x30);
            BitConverter.GetBytes(0x200u).CopyTo(buf, 0x34);
            BitConverter.GetBytes(0x20u).CopyTo(buf, 0x38);
            File.WriteAllBytes(dump, buf);

            var res = FI.Detect(dump);

            Assert.NotNull(res);
            Assert.Equal("dmp", res!.Extension);
            Assert.Equal("application/x-ms-protected-dump", res.MimeType);
            Assert.Equal("High", res.Confidence);
            Assert.Equal("dmp:protected", res.Reason);
        }
        finally
        {
            if (File.Exists(dump)) File.Delete(dump);
        }
    }

    [Fact]
    public void Detect_Evtx_When_File_Is_Already_Open_For_Write()
    {
        var evtx = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".evtx");
        try
        {
            var buf = new byte[32];
            System.Text.Encoding.ASCII.GetBytes("ElfFile\0").CopyTo(buf, 0);
            File.WriteAllBytes(evtx, buf);

            using var held = new FileStream(evtx, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);
            var res = FI.Detect(evtx);

            Assert.NotNull(res);
            Assert.Equal("evtx", res!.Extension);
            Assert.Equal("application/vnd.ms-windows.evtx", res.MimeType);
        }
        finally
        {
            if (File.Exists(evtx)) File.Delete(evtx);
        }
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
            Assert.Equal("cab:MSCF", res.Reason);
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
    public void Analyze_Zip_With_Inner_Zip_Flags_Nested_Archive_Subtype() {
        var p = Path.GetTempFileName();
        var zip = p + ".zip";
        try {
            byte[] innerZipBytes;
            using (var ms = new MemoryStream())
            {
                using (var inner = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
                {
                    var entry = inner.CreateEntry("payload.txt");
                    using var s = new StreamWriter(entry.Open());
                    s.Write("hello");
                }
                innerZipBytes = ms.ToArray();
            }

            using (var fs = File.Create(zip))
            using (var outer = new ZipArchive(fs, ZipArchiveMode.Create, leaveOpen: true)) {
                var nested = outer.CreateEntry("inner.zip");
                using var nestedStream = nested.Open();
                nestedStream.Write(innerZipBytes, 0, innerZipBytes.Length);
            }

            var analysis = FI.Analyze(zip);
            Assert.Equal("nested-archive", analysis.ContainerSubtype);
            Assert.True((analysis.Flags & global::FileInspectorX.ContentFlags.ContainerContainsArchives) != 0);
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

    private static byte[] CreateMinimalRar5Archive(bool headersEncrypted)
        => new byte[] {
            0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x03,
            0x01,
            headersEncrypted ? (byte)0x04 : (byte)0x00,
            0x00
        };

    private static byte[] CreateMinimal7zArchive(bool headersEncrypted) {
        var bytes = new byte[36];
        bytes[0] = 0x37;
        bytes[1] = 0x7A;
        bytes[2] = 0xBC;
        bytes[3] = 0xAF;
        bytes[4] = 0x27;
        bytes[5] = 0x1C;
        BitConverter.GetBytes(0L).CopyTo(bytes, 12);
        BitConverter.GetBytes(4L).CopyTo(bytes, 20);
        bytes[32] = 0x01;
        bytes[33] = headersEncrypted ? (byte)0x17 : (byte)0x00;
        return bytes;
    }

    private static byte[] CreateMinimal7zArchiveWithNames(params string[] names)
    {
        using var ms = new MemoryStream();
        using var next = new MemoryStream();

        next.WriteByte(0x01); // kHeader
        next.WriteByte(0x0C); // kFilesInfo
        next.WriteByte((byte)names.Length); // naive varuint file count for quick parser
        foreach (var name in names)
        {
            var bytes = System.Text.Encoding.Unicode.GetBytes(name);
            next.Write(bytes, 0, bytes.Length);
            next.WriteByte(0x00);
            next.WriteByte(0x00);
        }

        var nextBytes = next.ToArray();
        var start = new byte[32];
        start[0] = 0x37;
        start[1] = 0x7A;
        start[2] = 0xBC;
        start[3] = 0xAF;
        start[4] = 0x27;
        start[5] = 0x1C;
        BitConverter.GetBytes(0L).CopyTo(start, 12);
        BitConverter.GetBytes((long)nextBytes.Length).CopyTo(start, 20);
        ms.Write(start, 0, start.Length);
        ms.Write(nextBytes, 0, nextBytes.Length);
        return ms.ToArray();
    }

    private static byte[] CreateMinimalRar4ArchiveWithFiles(params string[] names)
    {
        using var ms = new MemoryStream();
        ms.Write(new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 });
        ms.Write(CreateMinimalRar4MainHeader());
        foreach (var name in names)
            ms.Write(CreateMinimalRar4FileHeader(name, encrypted: false, packedSize: 0));
        return ms.ToArray();
    }

    private static byte[] CreateMinimalRar4MainHeader()
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);
        bw.Write((ushort)0); // HEAD_CRC
        bw.Write((byte)0x73); // MAIN_HEAD
        bw.Write((ushort)0); // flags
        bw.Write((ushort)7); // HEAD_SIZE
        return ms.ToArray();
    }

    private static byte[] CreateMinimalRar4FileHeader(string name, bool encrypted, uint packedSize)
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);
        var nameBytes = System.Text.Encoding.GetEncoding(28591).GetBytes(name);
        ushort flags = encrypted ? (ushort)0x0004 : (ushort)0x0000;
        ushort headSize = (ushort)(7 + 25 + nameBytes.Length);
        bw.Write((ushort)0); // HEAD_CRC
        bw.Write((byte)0x74); // FILE_HEAD
        bw.Write(flags);
        bw.Write(headSize);
        bw.Write(packedSize); // PACK_SIZE
        bw.Write((uint)packedSize); // UNP_SIZE
        bw.Write((byte)0); // HOST_OS
        bw.Write((uint)0); // FILE_CRC
        bw.Write((uint)0); // FTIME
        bw.Write((byte)20); // UNP_VER
        bw.Write((byte)0x30); // METHOD store
        bw.Write((ushort)nameBytes.Length); // NAME_SIZE
        bw.Write((uint)0); // ATTR
        bw.Write(nameBytes);
        return ms.ToArray();
    }
}
