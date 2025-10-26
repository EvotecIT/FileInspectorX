using System;
using System.IO;
using Xunit;

namespace FileInspectorX.Tests;

public class EncryptedArchiveDetectionTests
{

    [Fact]
    public void Rar5_EncryptedHeaders_FlagsArchiveEncrypted()
    {
        var tmp = Path.GetTempFileName();
        try
        {
            using (var fs = File.Create(tmp))
            {
                // RAR5 signature: 52 61 72 21 1A 07 01 00
                fs.Write(new byte[]{0x52,0x61,0x72,0x21,0x1A,0x07,0x01,0x00});
                // CRC32 (4 bytes) + minimal header:
                fs.Write(new byte[]{0x00,0x00,0x00,0x00});
                // varint header size: 0x05 (single byte)
                fs.Write(new byte[]{0x05});
                // type = MAIN (0x01)
                fs.Write(new byte[]{0x01});
                // flags: 0x0004 indicates encrypted headers
                fs.Write(new byte[]{0x04,0x00});
            }
            var a = FileInspector.Analyze(tmp);
            Assert.True((a.Flags & ContentFlags.ArchiveHasEncryptedEntries) != 0);
        }
        finally { try { File.Delete(tmp); } catch { } }
    }

    [Fact]
    public void SevenZ_EncodedHeader_FlagsArchiveEncrypted()
    {
        var tmp = Path.GetTempFileName();
        try
        {
            using (var fs = File.Create(tmp))
            {
                // 7z Start Header (32 bytes)
                var hdr = new byte[32];
                // signature 37 7A BC AF 27 1C
                hdr[0]=0x37; hdr[1]=0x7A; hdr[2]=0xBC; hdr[3]=0xAF; hdr[4]=0x27; hdr[5]=0x1C;
                // next header offset (LE Int64) at 12 => 0
                // next header size (LE Int64) at 20 => 16
                BitConverter.TryWriteBytes(new Span<byte>(hdr, 20, 8), 16L);
                fs.Write(hdr, 0, hdr.Length);
                // Next header region (16 bytes) containing kEncodedHeader (0x17)
                fs.Write(new byte[]{0x17,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0});
            }
            var a = FileInspector.Analyze(tmp);
            Assert.True((a.Flags & ContentFlags.ArchiveHasEncryptedEntries) != 0);
        }
        finally { try { File.Delete(tmp); } catch { } }
    }
}
