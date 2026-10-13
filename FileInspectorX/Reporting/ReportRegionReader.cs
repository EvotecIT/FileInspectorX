using System.Security.Cryptography;

namespace FileInspectorX;

internal static class ReportRegionReader
{
    internal static IReadOnlyList<ReportRegion> Read(Stream stream, FileAnalysis analysis, InspectionReportOptions options, HashSet<string> issues)
    {
        var regions = new List<ReportRegion>();
        long hashRemaining = options.MaxRegionHashBytes;
        if (PeReader.TryReadPe(stream, out var pe))
        {
            var sections = pe.Sections.Where(section => section.SizeOfRawData > 0).ToArray();
            for (int index = 0; index < sections.Length; index++)
            {
                var section = sections[index];
                if (regions.Count >= options.MaxRegions) { issues.Add("content:region-count-limit"); break; }
                long offset = section.PointerToRawData, length = section.SizeOfRawData;
                // Validate declared ownership against every section before hashing any range, including unretained siblings.
                bool overlaps = sections.Where((_, otherIndex) => otherIndex != index).Any(other =>
                    (long)other.PointerToRawData < offset + length && offset < (long)other.PointerToRawData + other.SizeOfRawData);
                if (offset > stream.Length || length > stream.Length - offset)
                    regions.Add(new ReportRegion { Name = section.Name, Kind = "pe-section", ByteOffset = offset, ByteLength = length,
                        Status = InspectionStageStatus.Failed, Issues = overlaps ? new[] { "content:region-range-invalid", "content:region-overlap" } : new[] { "content:region-range-invalid" } });
                else if (overlaps)
                    regions.Add(new ReportRegion { Name = section.Name, Kind = "pe-section", ByteOffset = offset, ByteLength = length,
                        Status = InspectionStageStatus.Partial, Issues = new[] { "content:region-overlap" } });
                else regions.Add(Hash(stream, section.Name, "pe-section", offset, length, options, ref hashRemaining));
            }
        }
        else if (analysis.Kind != ContentKind.Text && analysis.Kind != ContentKind.Archive && stream.Length > 0)
        {
            // Fixed blocks are explicitly sampled byte regions, not an interoperable fuzzy digest.
            const int blockBytes = 64 * 1024;
            for (long offset = 0; offset < stream.Length; offset += blockBytes)
            {
                if (regions.Count >= options.MaxRegions || hashRemaining == 0) { issues.Add("content:region-coverage-limit"); break; }
                regions.Add(Hash(stream, (offset / blockBytes).ToString(System.Globalization.CultureInfo.InvariantCulture), "fixed-block",
                    offset, Math.Min(blockBytes, stream.Length - offset), options, ref hashRemaining));
            }
        }
        foreach (var region in regions) foreach (var issue in region.Issues) issues.Add(issue);
        return regions;
    }

    private static ReportRegion Hash(Stream stream, string name, string kind, long offset, long length, InspectionReportOptions options, ref long remaining)
    {
        var region = new ReportRegion { Name = name, Kind = kind, ByteOffset = offset, ByteLength = length };
        if (offset < 0 || length < 0 || offset > stream.Length || length > stream.Length - offset)
        { region.Status = InspectionStageStatus.Failed; region.Issues = new[] { "content:region-range-invalid" }; return region; }
        if (length > options.MaxRegionBytes || length > remaining)
        { region.Status = InspectionStageStatus.Partial; region.Issues = new[] { "content:region-hash-budget" }; return region; }
        using var sha = SHA256.Create();
        stream.Position = offset;
        var buffer = new byte[8192];
        long left = length;
        while (left > 0)
        {
            InspectionOperation.CheckCancellation();
            var count = stream.Read(buffer, 0, (int)Math.Min(left, buffer.Length));
            if (count == 0) throw new EndOfStreamException("The captured binary region is incomplete.");
            sha.TransformBlock(buffer, 0, count, buffer, 0); left -= count;
        }
        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        region.Sha256 = BitConverter.ToString(sha.Hash!).Replace("-", string.Empty).ToLowerInvariant();
        region.HashBytes = length; region.Status = InspectionStageStatus.Completed; remaining -= length;
        return region;
    }
}
