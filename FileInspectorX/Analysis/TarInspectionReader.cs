using System.Globalization;
using System.Text;

namespace FileInspectorX;

/// <summary>
/// Bounded TAR metadata reader. Entries leave the stream at the payload start;
/// the next call skips its padded payload. Names include USTAR, PAX and GNU overrides.
/// </summary>
internal sealed class TarInspectionReader
{
    private readonly Stream _stream;
    private readonly ArchiveInspectionBudget _budget;
    private readonly byte[] _header = new byte[512];
    private readonly Dictionary<string, string> _global = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _local = new(StringComparer.Ordinal);
    private readonly long _metadataLimit = Math.Max(1, Settings.ArchiveMaxEntryReadBytes);
    private readonly long _totalMetadataLimit = Math.Max(1, Settings.ArchiveMaxTotalReadBytes);
    private long _metadataBytes;
    private long _nextHeader;
    private bool _ended;

    internal TarInspectionReader(Stream stream, ArchiveInspectionBudget budget) { _stream = stream; _budget = budget; }
    internal string Name { get; private set; } = string.Empty;
    internal string LinkName { get; private set; } = string.Empty;
    internal byte Type { get; private set; }
    internal long Size { get; private set; }

    internal bool MoveNext()
    {
        if (_ended) return false;
        try
        {
            while (true)
            {
                _stream.Position = _nextHeader;
                if (ReadFully(_header) != 512) return Fail("tar:truncated-header");
                if (_header.All(b => b == 0)) { _ended = true; return false; }
                // Count headers, including directories and metadata records: an archive
                // cannot evade the entry budget with records that have no file extension.
                if (!_budget.TryVisitEntry()) { _ended = true; return false; }
                long checksum = Octal(_header.AsSpan(148, 8));
                long actual = 0;
                for (int i = 0; i < 512; i++) actual += i >= 148 && i < 156 ? 32 : _header[i];
                if (checksum != actual) return Fail("tar:invalid-header");
                Name = CString(_header.AsSpan(0, 100));
                var prefix = CString(_header.AsSpan(345, 155));
                if (!string.IsNullOrEmpty(prefix) && CString(_header.AsSpan(257, 6)) == "ustar") Name = prefix + "/" + Name;
                LinkName = CString(_header.AsSpan(157, 100));
                Type = _header[156];
                Size = Octal(_header.AsSpan(124, 12));
                if (Type is (byte)'x' or (byte)'g' or (byte)'L' or (byte)'K')
                {
                    SetNextHeader();
                    if (Size > _metadataLimit || Size > _totalMetadataLimit - _metadataBytes || Size > int.MaxValue)
                        return Fail("tar:metadata-read-limit");
                    var bytes = new byte[(int)Size];
                    if (ReadFully(bytes) != bytes.Length) return Fail("tar:truncated-metadata");
                    _metadataBytes += Size;
                    if (Type == (byte)'L') _local["path"] = CString(bytes);
                    else if (Type == (byte)'K') _local["linkpath"] = CString(bytes);
                    else ReadPax(bytes, Type == (byte)'g' ? _global : _local);
                    continue;
                }
                var effective = new Dictionary<string, string>(_global, StringComparer.Ordinal);
                foreach (var pair in _local)
                {
                    if (pair.Value.Length == 0) effective.Remove(pair.Key);
                    else effective[pair.Key] = pair.Value;
                }
                _local.Clear();
                if (effective.TryGetValue("path", out var name)) Name = name;
                if (effective.TryGetValue("linkpath", out var link)) LinkName = link;
                if (effective.TryGetValue("size", out var size))
                {
                    if (!long.TryParse(size, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed)) return Fail("tar:invalid-size");
                    Size = parsed;
                }
                if (Type == (byte)'S' || effective.Keys.Any(key => key.StartsWith("GNU.sparse", StringComparison.Ordinal)))
                    return Fail("tar:sparse-unsupported");
                SetNextHeader();
                return true;
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or OverflowException or FormatException)
        { return Fail("tar:invalid-or-truncated"); }
    }

    private void SetNextHeader()
    {
        _nextHeader = checked(_stream.Position + checked((Size + 511) / 512) * 512);
        if (_nextHeader > _stream.Length) throw new InvalidDataException("Truncated TAR payload.");
    }

    private bool Fail(string issue) { _budget.AddIssue(issue); _ended = true; return false; }

    private int ReadFully(byte[] buffer)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = _stream.Read(buffer, total, buffer.Length - total);
            if (read == 0) break;
            total += read;
        }
        return total;
    }

    private static string CString(ReadOnlySpan<byte> bytes)
    {
        int end = bytes.IndexOf((byte)0);
        return Encoding.UTF8.GetString(bytes.Slice(0, end < 0 ? bytes.Length : end).ToArray());
    }

    private static long Octal(ReadOnlySpan<byte> bytes)
    {
        long value = 0;
        bool ended = false;
        foreach (byte b in bytes)
        {
            if (b is 0 or 32) { if (value != 0) ended = true; continue; }
            if (ended || b < '0' || b > '7') throw new InvalidDataException("Unsupported TAR numeric field.");
            value = checked(value * 8 + b - '0');
        }
        return value;
    }

    private static void ReadPax(byte[] bytes, Dictionary<string, string> target)
    {
        int offset = 0;
        while (offset < bytes.Length)
        {
            int space = Array.IndexOf(bytes, (byte)' ', offset);
            if (space < 0 || !int.TryParse(Encoding.ASCII.GetString(bytes, offset, space - offset), NumberStyles.None, CultureInfo.InvariantCulture, out int length) ||
                length <= space - offset + 2 || length > bytes.Length - offset || bytes[offset + length - 1] != '\n')
                throw new InvalidDataException("Invalid PAX record.");
            string record = Encoding.UTF8.GetString(bytes, space + 1, offset + length - space - 2);
            int equals = record.IndexOf('=');
            if (equals <= 0) throw new InvalidDataException("Invalid PAX key.");
            string key = record.Substring(0, equals), value = record.Substring(equals + 1);
            target[key] = value;
            offset += length;
        }
    }
}
