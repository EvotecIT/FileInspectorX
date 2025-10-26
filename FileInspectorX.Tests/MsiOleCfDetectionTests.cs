using System;
using System.IO;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public class MsiOleCfDetectionTests
{
    [Fact]
    public void OleCfbf_WithMsiDirectoryNames_IsDetectedAsMsi()
    {
        var tmp = Path.GetTempFileName();
        try
        {
            // Build a tiny synthetic CFBF structure tailored for our mini-reader
            // Header 512 bytes
            var header = new byte[512];
            // Signature D0 CF 11 E0 A1 B1 1A E1
            var sig = new byte[]{0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1};
            Array.Copy(sig, 0, header, 0, sig.Length);
            // sector size shift (0x1E) = 9 => 512 bytes
            header[0x1E] = 0x09; header[0x1F] = 0x00;
            // FAT count (0x2C) = 1
            BitConverter.TryWriteBytes(new Span<byte>(header, 0x2C, 4), 1);
            // Directory start SID (0x30) = 2 (will be at offset 512 + (2+1)*512)
            BitConverter.TryWriteBytes(new Span<byte>(header, 0x30, 4), 2);
            // DIFAT first entry at 0x4C = FAT sector SID 0
            BitConverter.TryWriteBytes(new Span<byte>(header, 0x4C, 4), 0);

            // FAT sector (512 bytes) placed at sector 0 by our reader's formula => offset 1024
            var fat = new byte[512];
            // Mark directory sector (SID 2) as end of chain
            // Entries are 32-bit LE; place ENDOFCHAIN at index 2
            const int ENDOFCHAIN = unchecked((int)0xFFFFFFFE);
            BitConverter.TryWriteBytes(new Span<byte>(fat, 2*4, 4), ENDOFCHAIN);

            // Directory sector (512 bytes) at SID 2 => offset 512 + (2+1)*512
            var dir = new byte[512];
            WriteDirName(dir, 0, "SummaryInformation");
            WriteDirName(dir, 128, "Property");
            WriteDirName(dir, 256, "Directory");

            using (var fs = File.Create(tmp))
            {
                fs.Write(header, 0, header.Length);
                // pad to offset 1024 where FAT will be according to our reader
                fs.Position = 1024;
                fs.Write(fat, 0, fat.Length);
                // write dir sector at offset 512 + (2+1)*512 = 2048
                fs.Position = 2048;
                fs.Write(dir, 0, dir.Length);
            }

            var det = FileInspector.Detect(tmp);
            Assert.NotNull(det);
            Assert.Equal("msi", det!.Extension);
            Assert.True(det.Confidence == "High" || det.Confidence == "Medium");
        }
        finally { try { File.Delete(tmp); } catch { } }

        static void WriteDirName(byte[] buf, int offset, string name)
        {
            // Write UTF-16LE name at entry start, set name length (0x40) in bytes incl. null
            var bytes = Encoding.Unicode.GetBytes(name + "\0");
            Array.Copy(bytes, 0, buf, offset, Math.Min(bytes.Length, 64));
            ushort len = (ushort)Math.Min(bytes.Length, 128);
            buf[offset + 0x40] = (byte)(len & 0xFF);
            buf[offset + 0x41] = (byte)((len >> 8) & 0xFF);
        }
    }
}

