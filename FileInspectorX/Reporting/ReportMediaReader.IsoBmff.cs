namespace FileInspectorX;

internal static partial class ReportMediaReader
{
    private sealed class MediaTrack
    {
        internal string Part = string.Empty;
        internal uint TimeScale;
        internal ulong Duration;
        internal bool UnknownDuration;
        internal bool HasEditList;
    }

    private static void ReadIsoBmff(Probe probe)
    {
        int tracks = 0; bool movie = false, fragmented = false;
        WalkBoxes(probe, 0, probe.Length, 0, null, ref tracks, ref movie, ref fragmented);
        probe.Fact("Media.SampledTracks", tracks, 0, 0, derived: true);
        if (!movie) probe.Issue("media:movie-tracks-unavailable");
        if (fragmented) probe.Issue("media:fragmented-timing-not-inspected");
    }

    private static void WalkBoxes(Probe probe, long start, long end, int depth, MediaTrack? track,
        ref int tracks, ref bool movie, ref bool fragmented)
    {
        if (depth > 8) throw new MetadataLimitException();
        for (long offset = start; offset < end;)
        {
            probe.Record();
            if (end - offset < 8) throw new InvalidDataException();
            var header = probe.Read(offset, 8); ulong encodedSize = U32(header, 0); string type = Ascii(header, 4, 4); int headerBytes = 8;
            if (encodedSize == 1) { encodedSize = U64(probe.Read(offset + 8, 8), 0); headerBytes = 16; }
            long size = encodedSize == 0 ? end - offset : encodedSize <= long.MaxValue ? (long)encodedSize : throw new InvalidDataException();
            if (size < headerBytes || size > end - offset) throw new InvalidDataException();
            long payload = offset + headerBytes, payloadBytes = size - headerBytes;
            if (type == "ftyp")
            {
                if (payloadBytes < 8 || (payloadBytes - 8) % 4 != 0) throw new InvalidDataException();
                var brand = probe.Read(payload, 8); probe.Fact("Media.MajorBrand", Ascii(brand, 0, 4), payload, 4);
                probe.Fact("Media.MinorVersion", U32(brand, 4), payload + 4, 4);
                if (payloadBytes > 8)
                {
                    if (payloadBytes - 8 > 4096) { probe.Issue("media:compatible-brand-limit"); }
                    else
                    {
                        var brands = probe.Read(payload + 8, (int)payloadBytes - 8);
                        for (int i = 0; i < brands.Length; i += 4) probe.Fact("Media.CompatibleBrand", Ascii(brands, i, 4), payload + 8 + i, 4, "brand[" + (i / 4) + "]");
                    }
                }
            }
            else if (type == "moov") { movie = true; WalkBoxes(probe, payload, offset + size, depth + 1, null, ref tracks, ref movie, ref fragmented); }
            else if (type == "trak")
            {
                var child = new MediaTrack { Part = "track[" + tracks.ToString(System.Globalization.CultureInfo.InvariantCulture) + "]" }; tracks++;
                WalkBoxes(probe, payload, offset + size, depth + 1, child, ref tracks, ref movie, ref fragmented);
                if (child.TimeScale > 0 && !child.UnknownDuration && !child.HasEditList)
                    probe.Fact("Track.DeclaredMediaDurationSeconds", child.Duration / (double)child.TimeScale, payload, 0, child.Part, derived: true);
                else probe.Issue("media:track-duration-unavailable-or-edited");
            }
            else if (type is "mdia" or "minf" or "stbl" or "edts")
                WalkBoxes(probe, payload, offset + size, depth + 1, track, ref tracks, ref movie, ref fragmented);
            else if (type is "mvex" or "moof") fragmented = true;
            else if (type == "elst") { if (track != null) track.HasEditList = true; probe.Issue("media:edit-list-not-applied"); }
            else if (track != null && type == "tkhd") ReadTrackHeader(probe, track, payload, payloadBytes);
            else if (track != null && type == "mdhd") ReadMediaHeader(probe, track, payload, payloadBytes);
            else if (track != null && type == "hdlr")
            {
                if (payloadBytes < 12) throw new InvalidDataException();
                var handler = probe.Read(payload, 12); probe.Fact("Track.Handler", Ascii(handler, 8, 4), payload + 8, 4, track.Part);
            }
            else if (track != null && type == "stsd") ReadSampleDescriptions(probe, track, payload, payloadBytes);
            offset += size;
        }
    }

    private static void ReadTrackHeader(Probe probe, MediaTrack track, long offset, long size)
    {
        var version = probe.Read(offset, 1)[0]; int expected = version == 0 ? 84 : version == 1 ? 96 : 0;
        if (expected == 0) { probe.Issue("media:track-header-version-unsupported"); return; }
        if (size < expected) throw new InvalidDataException(); var data = probe.Read(offset, expected);
        int idOffset = version == 0 ? 12 : 20;
        probe.Fact("Track.Id", U32(data, idOffset), offset + idOffset, 4, track.Part);
        probe.Fact("Track.DeclaredWidth", U32(data, expected - 8) / 65536.0, offset + expected - 8, 4, track.Part);
        probe.Fact("Track.DeclaredHeight", U32(data, expected - 4) / 65536.0, offset + expected - 4, 4, track.Part);
        probe.Issue("media:track-transform-not-applied");
    }

    private static void ReadMediaHeader(Probe probe, MediaTrack track, long offset, long size)
    {
        var version = probe.Read(offset, 1)[0]; int expected = version == 0 ? 24 : version == 1 ? 36 : 0;
        if (expected == 0) { probe.Issue("media:media-header-version-unsupported"); return; }
        if (size < expected) throw new InvalidDataException(); var data = probe.Read(offset, expected);
        int scaleOffset = version == 0 ? 12 : 20, durationOffset = scaleOffset + 4;
        track.TimeScale = U32(data, scaleOffset); track.Duration = version == 0 ? U32(data, durationOffset) : U64(data, durationOffset);
        track.UnknownDuration = version == 0 ? track.Duration == uint.MaxValue : track.Duration == ulong.MaxValue;
        if (track.TimeScale == 0) throw new InvalidDataException();
        probe.Fact("Track.TimeScale", track.TimeScale, offset + scaleOffset, 4, track.Part);
        if (!track.UnknownDuration) probe.Fact("Track.DeclaredDurationUnits", track.Duration, offset + durationOffset, version == 0 ? 4 : 8, track.Part);
    }

    private static void ReadSampleDescriptions(Probe probe, MediaTrack track, long offset, long size)
    {
        if (size < 8) throw new InvalidDataException(); var data = probe.Read(offset, 8); uint count = U32(data, 4);
        if (count > 128) throw new MetadataLimitException(); long position = offset + 8, end = offset + size;
        for (uint i = 0; i < count; i++)
        {
            probe.Record(); if (end - position < 8) throw new InvalidDataException();
            var entry = probe.Read(position, 8); uint length = U32(entry, 0);
            if (length < 8 || length > end - position) throw new InvalidDataException();
            probe.Fact("Track.CodecIdentifier", Ascii(entry, 4, 4), position + 4, 4, track.Part + "/sample[" + i + "]"); position += length;
        }
        probe.Issue("media:sample-description-payload-not-inspected");
    }
}
