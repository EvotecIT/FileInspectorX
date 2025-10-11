using System.Text;

namespace FileInspectorX;

internal static class PeReader {
    internal sealed class PeInfo {
        public bool IsPE;
        public bool IsPEPlus;
        public long OptionalHeaderStart;
        public ushort NumberOfSections;
        public Section[] Sections = Array.Empty<Section>();
        public uint ResourceRva;
        public uint ResourceSize;
        public uint SecurityOffset; // note: security dir uses file offset, not RVA
        public uint SecuritySize;
    }

    internal sealed class Section {
        public uint VirtualAddress;
        public uint VirtualSize;
        public uint PointerToRawData;
        public uint SizeOfRawData;
    }

    public static bool TryReadPe(string path, out PeInfo info) {
        info = new PeInfo();
        try {
            using var fs = File.OpenRead(path);
            using var br = new BinaryReader(fs);
            if (fs.Length < 0x100) return false;
            if (br.ReadByte() != 0x4D || br.ReadByte() != 0x5A) return false; // MZ
            fs.Seek(0x3C, SeekOrigin.Begin);
            int e_lfanew = br.ReadInt32();
            if (e_lfanew <= 0 || e_lfanew > fs.Length - 256) return false;
            fs.Seek(e_lfanew, SeekOrigin.Begin);
            if (br.ReadByte() != (byte)'P' || br.ReadByte() != (byte)'E' || br.ReadByte() != 0 || br.ReadByte() != 0) return false;
            info.IsPE = true;
            br.ReadUInt16(); // Machine
            ushort numberOfSections = br.ReadUInt16(); info.NumberOfSections = numberOfSections;
            br.ReadUInt32(); // TimeDateStamp
            br.ReadUInt32(); // PointerToSymbolTable
            br.ReadUInt32(); // NumberOfSymbols
            ushort sizeOptionalHeader = br.ReadUInt16();
            br.ReadUInt16(); // Characteristics
            long optStart = fs.Position; info.OptionalHeaderStart = optStart;
            ushort magic = br.ReadUInt16();
            bool isPlus = magic == 0x20b; info.IsPEPlus = isPlus;
            // Skip to DataDirectory
            int ddOffset = isPlus ? 0x70 : 0x60; // offset from opt start
            fs.Seek(optStart + ddOffset, SeekOrigin.Begin);
            // Read 16 data directories (VA/Size)
            uint[] ddVa = new uint[16];
            uint[] ddSz = new uint[16];
            for (int i = 0; i < 16; i++) { ddVa[i] = br.ReadUInt32(); ddSz[i] = br.ReadUInt32(); }
            // 2 = Resource
            info.ResourceRva = ddVa[2]; info.ResourceSize = ddSz[2];
            // 4 = Security (uses file offset instead of RVA)
            info.SecurityOffset = ddVa[4]; info.SecuritySize = ddSz[4];
            // Read sections
            fs.Seek(optStart + sizeOptionalHeader, SeekOrigin.Begin);
            var secs = new List<Section>(numberOfSections);
            for (int i = 0; i < numberOfSections; i++) {
                fs.Seek(8, SeekOrigin.Current); // skip name
                uint virtualSize = br.ReadUInt32();
                uint virtualAddress = br.ReadUInt32();
                uint sizeOfRawData = br.ReadUInt32();
                uint pointerToRawData = br.ReadUInt32();
                fs.Seek(16, SeekOrigin.Current); // skip remainder
                secs.Add(new Section { VirtualAddress = virtualAddress, VirtualSize = virtualSize, SizeOfRawData = sizeOfRawData, PointerToRawData = pointerToRawData });
            }
            info.Sections = secs.ToArray();
            return true;
        } catch { return false; }
    }

    public static bool RvaToFileOffset(PeInfo info, uint rva, out long fileOffset) {
        fileOffset = 0;
        foreach (var s in info.Sections) {
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + Math.Max(s.VirtualSize, s.SizeOfRawData)) {
                fileOffset = (long)(s.PointerToRawData + (rva - s.VirtualAddress));
                return true;
            }
        }
        return false;
    }

    public static Dictionary<string, string>? TryExtractVersionStrings(string path) {
        if (!TryReadPe(path, out var pe)) return null;
        if (pe.ResourceRva == 0 || pe.ResourceSize == 0) return null;
        try {
            using var fs = File.OpenRead(path);
            using var br = new BinaryReader(fs);
            // Resource root directory at RVA ResourceRva
            if (!RvaToFileOffset(pe, pe.ResourceRva, out var resRoot)) return null;
            // The resource directory is a tree: we’ll do a best-effort scan for type 16 (RT_VERSION)
            // Format: IMAGE_RESOURCE_DIRECTORY (16 bytes) followed by entries.
            fs.Seek(resRoot, SeekOrigin.Begin);
            var dir = br.ReadBytes(16);
            ushort numberOfNamed = BitConverter.ToUInt16(dir, 12);
            ushort numberOfId = BitConverter.ToUInt16(dir, 14);
            int count = numberOfNamed + numberOfId;
            for (int i = 0; i < count; i++) {
                uint nameOrId = br.ReadUInt32();
                uint offset = br.ReadUInt32();
                bool isDirectory = (offset & 0x80000000) != 0; uint childOff = offset & 0x7FFFFFFF;
                uint id = nameOrId & 0xFFFF;
                if (id != 16) continue; // we want RT_VERSION
                long typeDir = resRoot + childOff;
                // Next level (name)
                fs.Seek(typeDir, SeekOrigin.Begin);
                dir = br.ReadBytes(16);
                ushort nNamed = BitConverter.ToUInt16(dir, 12);
                ushort nId = BitConverter.ToUInt16(dir, 14);
                int cnt2 = nNamed + nId;
                for (int j = 0; j < cnt2; j++) {
                    uint name2 = br.ReadUInt32(); uint off2 = br.ReadUInt32();
                    long langDir = typeDir + (off2 & 0x7FFFFFFF);
                    fs.Seek(langDir, SeekOrigin.Begin);
                    dir = br.ReadBytes(16);
                    ushort nNamed3 = BitConverter.ToUInt16(dir, 12);
                    ushort nId3 = BitConverter.ToUInt16(dir, 14);
                    if (nNamed3 + nId3 <= 0) continue;
                    // First data entry
                    fs.Seek(langDir + 16 + 8 * (nNamed3 + nId3 - 1), SeekOrigin.Begin);
                    uint dataRva = br.ReadUInt32(); br.ReadUInt32(); br.ReadUInt32(); br.ReadUInt32();
                    if (!RvaToFileOffset(pe, dataRva, out var dataOff)) continue;
                    fs.Seek(dataOff, SeekOrigin.Begin);
                    // Read a small block and heuristically parse UTF-16 string pairs
                    var data = br.ReadBytes(4096);
                    var text = Encoding.Unicode.GetString(data);
                    var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    Extract(text, "CompanyName", map);
                    Extract(text, "ProductName", map);
                    Extract(text, "FileVersion", map);
                    Extract(text, "ProductVersion", map);
                    Extract(text, "FileDescription", map);
                    Extract(text, "OriginalFilename", map);
                    Extract(text, "InternalName", map);
                    Extract(text, "LegalCopyright", map);
                    if (map.Count > 0) return map;
                }
            }
        } catch { }
        return null;

        static void Extract(string text, string key, Dictionary<string, string> map) {
            var idx = text.IndexOf(key + "\0\0", StringComparison.Ordinal);
            if (idx < 0) return;
            // value follows after key + two nulls; collect until double-null
            int start = idx + key.Length + 2;
            int end = text.IndexOf("\0\0", start, StringComparison.Ordinal);
            if (end > start) {
                var val = text.Substring(start, end - start).Replace("\0", string.Empty).Trim();
                if (!string.IsNullOrEmpty(val)) map[key] = val;
            }
        }
    }
}