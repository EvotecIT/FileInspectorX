using System.IO.Compression;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace FileInspectorX;

public static partial class FileInspector
{
    // Parse OOXML .rels fragments to count external targets and categorize by allowed domains.
    private static void CountOoxmlExternalTargets(string xml, ref int allowed, ref int disallowed, ref int unc)
    {
        try
        {
            int idx = 0;
            while (idx < xml.Length)
            {
                int at = xml.IndexOf("Target=\"", idx, StringComparison.OrdinalIgnoreCase);
                if (at < 0) break; at += 8; // after Target="
                int end = xml.IndexOf('"', at);
                if (end < 0) break;
                var raw = xml.Substring(at, end - at).Trim();
                idx = end + 1;
                if (string.IsNullOrWhiteSpace(raw)) continue;
                if (raw.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || raw.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || raw.StartsWith("//"))
                {
                    var host = TryGetHost(raw);
                    if (!string.IsNullOrEmpty(host))
                    {
                        if (IsAllowedDomain(host!)) allowed++; else disallowed++;
                    }
                }
                else if (raw.StartsWith("\\\\") || raw.StartsWith("file://", StringComparison.OrdinalIgnoreCase))
                {
                    unc++;
                }
            }
        } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { }
    }

    // Overload: also captures up to 5 unique hosts encountered (order of first appearance)
    private static void CountOoxmlExternalTargets(string xml, ref int allowed, ref int disallowed, ref int unc, List<string> hosts)
    {
        try
        {
            int idx = 0;
            while (idx < xml.Length)
            {
                int at = xml.IndexOf("Target=\"", idx, StringComparison.OrdinalIgnoreCase);
                if (at < 0) break; at += 8;
                int end = xml.IndexOf('"', at);
                if (end < 0) break;
                var raw = xml.Substring(at, end - at).Trim();
                idx = end + 1;
                if (string.IsNullOrWhiteSpace(raw)) continue;
                if (raw.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || raw.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || raw.StartsWith("//"))
                {
                    var host = TryGetHost(raw);
                    if (!string.IsNullOrEmpty(host))
                    {
                        if (IsAllowedDomain(host!)) allowed++; else disallowed++;
                        if (hosts.Count < 5 && !hosts.Contains(host!, StringComparer.OrdinalIgnoreCase)) hosts.Add(host!);
                    }
                }
                else if (raw.StartsWith("\\\\") || raw.StartsWith("file://", StringComparison.OrdinalIgnoreCase))
                {
                    unc++;
                }
            }
        } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { }
    }

    private static string? TryGetHost(string url)
    {
        try
        {
            if (url.StartsWith("//")) url = "http:" + url;
            if (Uri.TryCreate(url, UriKind.Absolute, out var u)) return u.Host;
        } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { }
        return null;
    }

    private static bool IsAllowedDomain(string host)
    {
        return SecurityHeuristics.IsHostAllowedByDomains(host, OperationSettings.HtmlAllowedDomains);
    }

    // Counts RAR4 encrypted files by walking file headers quickly under a simple budget.
    // Returns true when parsing succeeded, with 'enc' and 'total' counts.
    private static bool TryCountRar4EncryptedFiles(InspectionInput input, int maxFiles, out int enc, out int total)
    {
        var path = input.Name;
        enc = 0; total = 0;
        try {
            using var fs = input.OpenRead();
            var sig = new byte[]{ (byte)'R',(byte)'a',(byte)'r', (byte)'!', 0x1A, 0x07, 0x00 };
            var head = new byte[sig.Length];
            if (ReadAvailable(fs, head, 0, head.Length) != head.Length) return false;
            for (int i=0;i<sig.Length;i++) if (head[i]!=sig[i]) return false;
            // RAR4 blocks: [HEAD_CRC(2)][HEAD_TYPE(1)][HEAD_FLAGS(2)][HEAD_SIZE(2)] ...
            var br = new BinaryReader(fs);
            int filesSeen = 0;
            int blocksSeen = 0;
            int maxBlocks = GetRar4BlockSafetyLimit(maxFiles);
            long byteBudget = Math.Max(7, OperationSettings.DetectionReadBudgetBytes);
            long walkStart = fs.Position;
            while (fs.Position + 7 <= fs.Length && filesSeen < maxFiles &&
                   blocksSeen++ < maxBlocks && fs.Position - walkStart < byteBudget)
            {
                ushort headCrc = br.ReadUInt16();
                byte headType = br.ReadByte();
                ushort headFlags = br.ReadUInt16();
                ushort headSize = br.ReadUInt16();
                if (headSize < 7) break; // guard
                long next = fs.Position + headSize - 7; // subtract header bytes already read
                // File header
                if (headType == 0x74) // HEAD_TYPE_FILE
                {
                    filesSeen++; total = filesSeen;
                    // In RAR v2/3/4, FILE_HEADER flags bit 0x04 means password/encrypted
                    if ((headFlags & 0x04) != 0) enc++;
                    // Skip extra fields (pack & unpack sizes already inside header; we just jump to next)
                }
                // Move to next block
                if (next < fs.Position || next > fs.Length || next - walkStart > byteBudget) break;
                fs.Seek(next, SeekOrigin.Begin);
            }
            if (total == 0) total = filesSeen;
            return true;
        } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { return false; }
    }

    private static bool TryInspectRar4Entries(
        InspectionInput input,
        out int? entryCount,
        out IReadOnlyList<string>? topExtensions,
        out bool hasExecutables,
        out bool hasScripts,
        out bool hasNestedArchives,
        out List<InnerEntryPreview>? previews,
        out Dictionary<string,int>? innerExecExtCounts)
    {
        var path = input.Name;
        entryCount = null; topExtensions = null; hasExecutables = false; hasScripts = false; hasNestedArchives = false; previews = null; innerExecExtCounts = null;
        try
        {
            using var fs = input.OpenRead();
            var sig = new byte[]{ (byte)'R',(byte)'a',(byte)'r', (byte)'!', 0x1A, 0x07, 0x00 };
            var head = new byte[sig.Length];
            if (ReadAvailable(fs, head, 0, head.Length) != head.Length) return false;
            for (int i = 0; i < sig.Length; i++) if (head[i] != sig[i]) return false;

            var br = new BinaryReader(fs);
            int count = 0;
            var exts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var localPreviews = new List<InnerEntryPreview>();
            var execExts = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
            int previewCap = Math.Min(5, OperationSettings.DeepContainerMaxEntries);
            int entryLimit = Math.Max(1, OperationSettings.DeepContainerMaxEntries);
            int blocksSeen = 0;
            int maxBlocks = GetRar4BlockSafetyLimit(entryLimit);
            long byteBudget = Math.Max(7, OperationSettings.DetectionReadBudgetBytes);
            long walkStart = fs.Position;

            while (fs.Position + 7 <= fs.Length && count < entryLimit &&
                   blocksSeen++ < maxBlocks && fs.Position - walkStart < byteBudget)
            {
                long hdrStart = fs.Position;
                br.ReadUInt16(); // head crc
                byte headType = br.ReadByte();
                ushort headFlags = br.ReadUInt16();
                ushort headSize = br.ReadUInt16();
                if (headSize < 7) break;
                long headerEnd = hdrStart + headSize;
                if (headerEnd <= hdrStart || headerEnd > fs.Length) return false;

                if (headType == 0x74) // FILE_HEADER
                {
                    long afterBase = fs.Position;
                    if (afterBase + 4 + 4 + 1 + 4 + 4 + 1 + 1 + 2 + 4 > headerEnd)
                    {
                        fs.Seek(headerEnd, SeekOrigin.Begin);
                        continue;
                    }

                    uint packLow = br.ReadUInt32();
                    br.ReadUInt32(); // unpLow
                    br.ReadByte();   // hostOS
                    br.ReadUInt32(); // fileCRC
                    br.ReadUInt32(); // ftime
                    br.ReadByte();   // unpVer
                    br.ReadByte();   // method
                    ushort nameSize = br.ReadUInt16();
                    br.ReadUInt32(); // attr

                    ulong packSize = packLow;
                    if ((headFlags & 0x0100) != 0)
                    {
                        if (fs.Position + 8 > headerEnd)
                        {
                            fs.Seek(headerEnd, SeekOrigin.Begin);
                            continue;
                        }
                        uint highPack = br.ReadUInt32();
                        br.ReadUInt32(); // highUnp
                        packSize |= ((ulong)highPack << 32);
                    }

                    string name = string.Empty;
                    try
                    {
                        int toRead = (int)Math.Min((long)nameSize, headerEnd - fs.Position);
                        if (toRead > 0)
                        {
                            var nb = br.ReadBytes(toRead);
                            name = Latin1String(nb);
                        }
                    }
                    catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { }

                    fs.Seek(headerEnd, SeekOrigin.Begin);

                    count++;
                    if (!string.IsNullOrWhiteSpace(name))
                    {
                        var ext = GetExtension(name);
                        if (!string.IsNullOrEmpty(ext))
                            exts[ext] = exts.TryGetValue(ext, out var c) ? c + 1 : 1;
                        if (IsExecutableName(name))
                        {
                            hasExecutables = true;
                            if (!string.IsNullOrEmpty(ext))
                                execExts[ext] = execExts.TryGetValue(ext, out var c) ? c + 1 : 1;
                        }
                        if (IsScriptName(name)) hasScripts = true;
                        if (IsArchiveLikeExtension(ext)) hasNestedArchives = true;
                        if (localPreviews.Count < previewCap)
                            localPreviews.Add(new InnerEntryPreview { Name = name, DetectedExtension = string.IsNullOrEmpty(ext) ? null : ext });
                    }

                    ulong remaining = (ulong)(fs.Length - headerEnd);
                    if (packSize > remaining) return false;
                    long nextBlock = checked(headerEnd + (long)packSize);
                    if (nextBlock <= hdrStart) return false;
                    fs.Seek(nextBlock, SeekOrigin.Begin);
                    continue;
                }

                fs.Seek(headerEnd, SeekOrigin.Begin);
            }

            entryCount = count;
            if (exts.Count > 0) topExtensions = exts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).Take(5).Select(kv => kv.Key).ToArray();
            if (localPreviews.Count > 0) previews = localPreviews;
            if (execExts.Count > 0) innerExecExtCounts = execExts;
            return true;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { return false; }
    }

    private static int GetRar4BlockSafetyLimit(int fileLimit)
    {
        fileLimit = Math.Max(1, fileLimit);
        int metadataBlockBudget = Math.Max(1, OperationSettings.ArchiveMaxEntries);
        return fileLimit > int.MaxValue - metadataBlockBudget
            ? int.MaxValue
            : fileLimit + metadataBlockBudget;
    }

    /// <summary>
    /// Best-effort inner signer sampling for RAR4 archives, limited to entries stored without compression (method 0x30) and not encrypted.
    /// Walks headers and reads up to <paramref name="maxEntryBytes"/> for at most <paramref name="maxEntries"/> executable-looking entries.
    /// </summary>
    private static bool TrySampleRar4InnerSigners(InspectionInput input, DetectionOptions? options, int maxEntries, int maxEntryBytes, out int innerExecutablesSampled, out int innerSigned, out int innerValid, out Dictionary<string,int>? publishers, out ArchiveInspectionBudget budget)
    {
        budget = ArchiveInspectionBudget.FromSettings();
        innerExecutablesSampled = 0; innerSigned = 0; innerValid = 0; publishers = null;
        try
        {
            using var fs = input.OpenRead();
            // Verify RAR4 signature
            var sig = new byte[]{ (byte)'R',(byte)'a',(byte)'r', (byte)'!', 0x1A, 0x07, 0x00 };
            var head = new byte[sig.Length];
            if (ReadAvailable(fs, head, 0, head.Length) != head.Length) return false;
            for (int i=0;i<sig.Length;i++) if (head[i]!=sig[i]) return false;

            var br = new BinaryReader(fs);
            int sampled = 0; var pubs = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
            int blocks = 0;
            int blockBudget = GetRar4BlockSafetyLimit(Math.Max(1, maxEntries));
            while (fs.Position + 7 <= fs.Length && sampled < maxEntries)
            {
                InspectionOperation.CheckCancellation();
                if (++blocks > blockBudget) { budget.AddIssue("archive:rar-metadata-block-limit"); break; }
                long hdrStart = fs.Position;
                ushort headCrc = br.ReadUInt16();
                byte headType = br.ReadByte();
                ushort headFlags = br.ReadUInt16();
                ushort headSize = br.ReadUInt16();
                if (headSize < 7) break; // guard
                long headerEnd = hdrStart + headSize;
                if (headerEnd > fs.Length) { budget.AddIssue("archive:rar-header-truncated"); break; }

                if (headType == 0x74) // FILE_HEADER
                {
                    if (!budget.TryVisitEntry()) break;
                    // Parse fixed fields relative to after base header
                    long afterBase = fs.Position; // position right after 7-byte base header
                    // Required fields exist within header size budget; if not readable, break
                    if (afterBase + 4 + 4 + 1 + 4 + 4 + 1 + 1 + 2 + 4 > headerEnd) { fs.Seek(headerEnd, SeekOrigin.Begin); continue; }
                    uint packLow = br.ReadUInt32();
                    uint unpLow  = br.ReadUInt32();
                    br.ReadByte(); // hostOS
                    br.ReadUInt32(); // fileCRC
                    br.ReadUInt32(); // ftime
                    br.ReadByte();   // unpVer
                    byte method = br.ReadByte();
                    ushort nameSize = br.ReadUInt16();
                    br.ReadUInt32(); // attr
                    ulong packSize = packLow; ulong unpSize = unpLow;
                    if ((headFlags & 0x0100) != 0)
                    {
                        if (fs.Position + 8 > headerEnd) { fs.Seek(headerEnd, SeekOrigin.Begin); continue; }
                        uint hPack = br.ReadUInt32(); uint hUnp = br.ReadUInt32();
                        packSize |= ((ulong)hPack << 32); unpSize |= ((ulong)hUnp << 32);
                    }
                    // Read name (best-effort) to decide if it's executable by name; if can't, leave empty
                    string name = string.Empty;
                    try
                    {
                        int toRead = (int)Math.Min((long)nameSize, headerEnd - fs.Position);
                        if (toRead > 0)
                        {
                            var nb = br.ReadBytes(toRead);
                            name = Latin1String(nb);
                        }
                    } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { }
                    // Skip any remaining header fields to reach data start
                    fs.Seek(headerEnd, SeekOrigin.Begin);

                    bool encrypted = (headFlags & 0x0004) != 0;
                    bool store = method == 0x30; // '0' => stored without compression
                    if (packSize > (ulong)(fs.Length - headerEnd)) { budget.AddIssue("archive:rar-payload-truncated"); break; }
                    if (!encrypted && store && packSize > 0 && packSize <= (ulong)Math.Max(0, maxEntryBytes) && sampled < maxEntries)
                    {
                        long dataStart = headerEnd; long dataEnd = Math.Min(fs.Length, dataStart + (long)packSize);
                        fs.Seek(dataStart, SeekOrigin.Begin);
                        var cap = (int)Math.Min(maxEntryBytes, (long)packSize);
                        try
                        {
                            using var payload = budget.OpenTarPayload(fs, (long)packSize, cap);
                            if (payload == null) continue;
                            using var entryInput = new MemoryStream();
                            {
                                int left = cap; var buf = new byte[Math.Min(8192, cap)];
                                while (left > 0)
                                {
                                    int r = payload.Read(buf, 0, Math.Min(buf.Length, left)); if (r <= 0) break; entryInput.Write(buf, 0, r); left -= r;
                                }
                                if (left > 0) { budget.AddIssue("archive:rar-payload-truncated"); continue; }
                            }
                            // Analyze extracted sample and update stats if it is an executable
                            var childOptions = CreateInnerAnalysisOptions(options, GetNestedContainerBudget(options), options?.NestedContainerDepth ?? 0, includeContainer: false);
                            var ia = AnalyzeArchiveChild(input, entryInput, name, childOptions, budget, nativeSignerSampling: true);
                            sampled++;
                            // Decide if it was an executable by original name or detection
                            bool looksExec = (!string.IsNullOrEmpty(name) && IsExecutableName(name)) || (ia?.Detection?.Extension is "exe" or "dll" or "sys" or "cpl");
                            if (looksExec)
                            {
                                innerExecutablesSampled++;
                                if (ia?.Authenticode?.Present == true)
                                {
                                    innerSigned++;
                                    bool v = GetSignatureStatus(ia)?.IsValid == true;
                                    if (v) innerValid++;
                                    var pub = ia.Authenticode.SignerSubjectCN ?? ia.Authenticode.SignerSubject ?? "<unknown>";
                                    if (publishers == null) publishers = pubs;
                                    if (publishers!.TryGetValue(pub, out var pc)) publishers[pub] = pc + 1; else publishers[pub] = 1;
                                }
                            }
                        }
                        catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { /* ignore per-entry errors */ }
                        finally
                        {
                            // Move to end of this file's packed data to continue with the next block
                            fs.Seek(dataEnd, SeekOrigin.Begin);
                        }
                        continue;
                    }
                    else
                    {
                        // Skip packed data of this entry to reach the next block
                        fs.Seek((long)Math.Min((ulong)fs.Length, (ulong)headerEnd + packSize), SeekOrigin.Begin);
                        continue;
                    }
                }
                // Non-file header: just skip to header end
                fs.Seek(headerEnd, SeekOrigin.Begin);
            }
            if (publishers == null && pubs.Count > 0) publishers = pubs;
            return true;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { return false; }
    }

    private static bool TryInspectRarQuick(InspectionInput input)
    {
        var path = input.Name;
        // Best-effort: detect RAR4 header-encryption flag in main header (not extraction)
        try {
            using var fs = input.OpenRead();
            var sig = new byte[8];
            int r = ReadAvailable(fs, sig, 0, sig.Length);
            if (r < 7) return false;
            bool rar4 = sig[0] == 0x52 && sig[1] == 0x61 && sig[2] == 0x72 && sig[3] == 0x21 && sig[4] == 0x1A && sig[5] == 0x07 && sig[6] == 0x00;
            if (rar4)
            {
                fs.Seek(7, SeekOrigin.Begin);
                // Read next header: CRC(2), Type(1), Flags(2), Size(2)
                var hdr = new byte[7];
                if (ReadAvailable(fs, hdr, 0, 7) != 7) return false;
                byte type = hdr[2];
                int flags = hdr[3] | (hdr[4] << 8);
                // Type 0x73 (MAIN_HEADER), bit 0x0080 = encrypted headers
                if (type == 0x73 && (flags & 0x0080) != 0) return true;
                return false;
            }
            // RAR5 quick probe: after signature, RAR5 uses a block with CRC32 (4), header size (varint), type (1), flags (2)
            bool rar5 = sig[0] == 0x52 && sig[1] == 0x61 && sig[2] == 0x72 && sig[3] == 0x21 && sig[4] == 0x1A && sig[5] == 0x07 && sig[6] == 0x01 && sig[7] == 0x00;
            if (!rar5) return false;
            var buf = new byte[16];
            if (ReadAvailable(fs, buf, 0, 7) < 7) return false; // Read CRC32 (4) + at least 3 bytes of header
            // Very rough varint skip: header size is little-endian base-128; read until high bit cleared
            int idx = 4; long hdrSize = 0; int shift = 0; int guard = 0;
            while (idx < buf.Length && guard++ < 8)
            {
                byte b = buf[idx++]; hdrSize |= (long)(b & 0x7F) << shift; shift += 7; if ((b & 0x80) == 0) break;
                if (idx >= buf.Length) { var ext = new byte[8]; int rr = ReadAvailable(fs, ext, 0, ext.Length); if (rr <= 0) break; buf = buf.Concat(ext).ToArray(); }
            }
            if (idx + 3 > buf.Length) { var more = new byte[8]; ReadAvailable(fs, more, 0, more.Length); buf = buf.Concat(more).ToArray(); }
            byte bType = buf[idx++];
            if (idx + 2 > buf.Length) return false;
            int bFlags = buf[idx++] | (buf[idx++] << 8);
            // RAR5: bit 0x04 in flags of MAIN block indicates that headers are encrypted
            const byte RAR5_MAIN = 0x01;
            if (bType == RAR5_MAIN && (bFlags & 0x0004) != 0) return true;
            // Read next header: CRC(2), Type(1), Flags(2), Size(2)
        } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { }
        return false;
    }

    private static bool TryDetect7zEncryptedHeaders(InspectionInput input)
    {
        var path = input.Name;
        // Heuristic: parse Start Header to locate Next Header region, then check for kEncodedHeader (0x17)
        try {
            using var fs = input.OpenRead();
            if (fs.Length < 32) return false;
            var head = new byte[32];
            if (ReadAvailable(fs, head, 0, head.Length) != head.Length) return false;
            // Verify 7z signature
            if (!(head[0] == 0x37 && head[1] == 0x7A && head[2] == 0xBC && head[3] == 0xAF && head[4] == 0x27 && head[5] == 0x1C)) return false;
            // Next Header offset and size (LE 64-bit)
            long nextOff = System.BitConverter.ToInt64(head, 12);
            long nextSz  = System.BitConverter.ToInt64(head, 20);
            if (nextOff < 0 || nextSz <= 0 || nextOff + nextSz > fs.Length) return false;
            fs.Seek(nextOff + 32, SeekOrigin.Begin); // Next Header is offset from after the 32-byte Start Header
            int toRead = (int)System.Math.Min(nextSz, OperationSettings.DetectionReadBudgetBytes);
            var buf = new byte[toRead];
            int n = ReadAvailable(fs, buf, 0, toRead);
            if (n <= 0) return false;
            // Search for property id 0x17 (kEncodedHeader) in the next header region
            for (int i = 0; i < n; i++) if (buf[i] == 0x17) return true;
        } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { }
        return false;
    }

    // Best-effort: count files in 7z when Next Header is not encoded/compressed and headers are not encrypted.
    private static bool TryCount7zFilesQuick(InspectionInput input, int byteBudget, out int fileCount)
    {
        var path = input.Name;
        fileCount = 0;
        try {
            using var fs = input.OpenRead();
            if (fs.Length < 32) return false;
            var head = new byte[32];
            if (ReadAvailable(fs, head, 0, head.Length) != head.Length) return false;
            if (!(head[0] == 0x37 && head[1] == 0x7A && head[2] == 0xBC && head[3] == 0xAF && head[4] == 0x27 && head[5] == 0x1C)) return false;
            long nextOff = System.BitConverter.ToInt64(head, 12);
            long nextSz  = System.BitConverter.ToInt64(head, 20);
            if (nextOff < 0 || nextSz <= 0 || nextOff + nextSz > fs.Length) return false;
            fs.Seek(nextOff + 32, SeekOrigin.Begin);
            int toRead = (int)System.Math.Min(nextSz, byteBudget);
            var buf = new byte[toRead]; int n = ReadAvailable(fs, buf, 0, toRead); if (n <= 0) return false;
            var span = new ReadOnlySpan<byte>(buf, 0, n);
            // If encoded header is present, bail out
            for (int i = 0; i < n; i++) if (buf[i] == 0x17) return false; // kEncodedHeader
            // Expect kHeader (0x01)
            int idx = 0; if (idx >= span.Length || span[idx++] != 0x01) return false;
            // Naive scan for kFilesInfo (0x0C) and then read next varuint as number of files
            int pos = idx; while (pos < span.Length) { if (span[pos++] == 0x0C) { idx = pos; break; } }
            if (idx >= span.Length) return false;
            if (!TryRead7zVarUInt(span, ref idx, out ulong files)) return false;
            if (files == 0 || files > 10_000_000) return false;
            fileCount = (int)files; return true;
        } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { return false; }
    }

    private static bool TryRead7zVarUInt(ReadOnlySpan<byte> s, ref int idx, out ulong value)
    {
        value = 0; int shift = 0; int guard = 0;
        while (idx < s.Length && guard++ < 10)
        {
            byte b = s[idx++]; value |= (ulong)(b & 0x7Fu) << shift; shift += 7; if ((b & 0x80) == 0) return true;
        }
        return false;
    }

    // Best-effort: read a plain 7z Next Header buffer and extract likely UTF-16LE entry names.
    private static bool TryRead7zEntryNamesFromHeader(InspectionInput input, int byteBudget, out List<string> entryNames)
    {
        var path = input.Name;
        entryNames = new List<string>();
        try
        {
            using var fs = input.OpenRead();
            if (fs.Length < 32) return false;
            var head = new byte[32]; if (ReadAvailable(fs, head, 0, head.Length) != head.Length) return false;
            if (!(head[0] == 0x37 && head[1] == 0x7A && head[2] == 0xBC && head[3] == 0xAF && head[4] == 0x27 && head[5] == 0x1C)) return false;
            long nextOff = System.BitConverter.ToInt64(head, 12);
            long nextSz  = System.BitConverter.ToInt64(head, 20);
            if (nextOff < 0 || nextSz <= 0 || nextOff + nextSz > fs.Length) return false;
            fs.Seek(nextOff + 32, SeekOrigin.Begin);
            int toRead = (int)System.Math.Min(nextSz, byteBudget);
            var buf = new byte[toRead]; int n = ReadAvailable(fs, buf, 0, toRead); if (n <= 0) return false;
            // If encoded header present, bail (we don't parse it)
            for (int i = 0; i < n; i++) if (buf[i] == 0x17) return false;
            int cap = Math.Min(n, toRead);
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int offset = 0; offset <= 1 && entryNames.Count < 32; offset++)
            {
                int usable = ((cap - offset) / 2) * 2;
                if (usable < 4) continue;
                string decoded;
                try
                {
                    decoded = System.Text.Encoding.Unicode.GetString(buf, offset, usable);
                }
                catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException)
                {
                    continue;
                }

                foreach (var raw in decoded.Split('\0'))
                {
                    if (entryNames.Count >= 32) break;
                    var name = Normalize7zEntryName(raw);
                    if (LooksLike7zEntryName(name) && seen.Add(name))
                        entryNames.Add(name);
                }
            }
            return entryNames.Count > 0;
        } catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not OperationCanceledException) { return false; }
    }

    // Backward-compatible helper for callers that only need executable-ish names.
    private static bool TryScan7zExecutablesFromHeader(InspectionInput input, int byteBudget, out List<string> exeNames, out List<string> dllNames)
    {
        var path = input.Name;
        exeNames = new List<string>(); dllNames = new List<string>();
        if (!TryRead7zEntryNamesFromHeader(input, byteBudget, out var entryNames)) return false;
        foreach (var name in entryNames)
        {
            var lower = name.ToLowerInvariant();
            if (lower.EndsWith(".exe"))
            {
                if (!exeNames.Contains(name)) exeNames.Add(name);
            }
            else if (lower.EndsWith(".dll"))
            {
                if (!dllNames.Contains(name)) dllNames.Add(name);
            }
        }
        return (exeNames.Count + dllNames.Count) > 0;
    }

    private static bool LooksLike7zEntryName(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        var name = value.Trim('\0').Trim();
        if (name.Length < 3 || name.Length > 260) return false;
        if (name.IndexOfAny(new[] { '\r', '\n', '\t' }) >= 0) return false;
        if (name.Any(ch => char.IsControl(ch))) return false;
        return name.IndexOf('.') >= 0 || name.IndexOf('/') >= 0 || name.IndexOf('\\') >= 0;
    }

    private static string Normalize7zEntryName(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        var name = value.Trim('\0').Trim();
        if (string.IsNullOrEmpty(name)) return string.Empty;

        int start = 0;
        while (start < name.Length)
        {
            var ch = name[start];
            if (char.IsLetterOrDigit(ch) || ch == '.' || ch == '_' || ch == '-' || ch == '\\' || ch == '/')
                break;
            start++;
        }

        return start > 0 ? name.Substring(start) : name;
    }

}
