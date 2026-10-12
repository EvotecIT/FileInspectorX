namespace FileInspectorX;

internal static partial class Signatures
{
    // Called only after complete JSON passed the operation's existing structural
    // validator. The GLB JSON token reader supplies bounded value traversal.
    internal static bool TryGetGltfAssetVersion(ReadOnlySpan<byte> json, out string? version)
    {
        version = null;
        int cursor = 0;
        SkipJsonWhitespace(json, ref cursor);
        if (cursor >= json.Length || json[cursor++] != (byte)'{') return false;
        bool foundAsset = false;
        while (TryReadJsonProperty(json, ref cursor, out var key, out var value))
        {
            if (!JsonAsciiStringEquals(key, "asset")) continue;
            if (foundAsset) return false;
            foundAsset = true;
            int assetCursor = 0;
            SkipJsonWhitespace(value, ref assetCursor);
            if (assetCursor >= value.Length || value[assetCursor++] != (byte)'{') return false;
            bool foundVersion = false;
            while (TryReadJsonProperty(value, ref assetCursor, out var assetKey, out var assetValue))
            {
                if (!JsonAsciiStringEquals(assetKey, "version")) continue;
                if (foundVersion) return false;
                foundVersion = true;
                if (JsonAsciiStringEquals(assetValue, "2.0")) version = "2.0";
                else if (JsonAsciiStringEquals(assetValue, "1.0")) version = "1.0";
                else return false;
            }
        }
        return foundAsset && version != null;
    }

    private static bool TryReadJsonProperty(ReadOnlySpan<byte> json, ref int cursor,
        out ReadOnlySpan<byte> key, out ReadOnlySpan<byte> value)
    {
        key = value = default;
        SkipJsonWhitespace(json, ref cursor);
        if (cursor >= json.Length || json[cursor] == (byte)'}') return false;
        if (json[cursor] == (byte)',') { cursor++; SkipJsonWhitespace(json, ref cursor); }
        int keyStart = cursor;
        if (!TryReadJsonString(json, ref cursor)) return false;
        key = json.Slice(keyStart, cursor - keyStart);
        SkipJsonWhitespace(json, ref cursor);
        if (cursor >= json.Length || json[cursor++] != (byte)':') return false;
        SkipJsonWhitespace(json, ref cursor);
        int valueStart = cursor;
        if (!TryReadJsonValue(json, ref cursor, 0)) return false;
        value = json.Slice(valueStart, cursor - valueStart);
        return true;
    }

    // Property names and version strings are ASCII. Decode equivalent JSON
    // Unicode escapes without allocating strings or treating nested text as keys.
    private static bool JsonAsciiStringEquals(ReadOnlySpan<byte> token, string expected)
    {
        if (token.Length < 2 || token[0] != (byte)'"' || token[token.Length - 1] != (byte)'"') return false;
        int expectedIndex = 0;
        for (int cursor = 1; cursor < token.Length - 1; cursor++)
        {
            int value = token[cursor];
            if (value == (byte)'\\')
            {
                if (++cursor >= token.Length - 1) return false;
                if (token[cursor] == (byte)'u')
                {
                    if (cursor + 4 >= token.Length - 1) return false;
                    value = 0;
                    for (int digit = 0; digit < 4; digit++)
                    {
                        byte hex = token[++cursor];
                        int nibble = hex is >= (byte)'0' and <= (byte)'9' ? hex - '0' :
                            hex is >= (byte)'a' and <= (byte)'f' ? hex - 'a' + 10 :
                            hex is >= (byte)'A' and <= (byte)'F' ? hex - 'A' + 10 : -1;
                        if (nibble < 0) return false;
                        value = value * 16 + nibble;
                    }
                }
                else if (token[cursor] is (byte)'"' or (byte)'\\' or (byte)'/') value = token[cursor];
                else return false;
            }
            if (expectedIndex >= expected.Length || value != expected[expectedIndex++]) return false;
        }
        return expectedIndex == expected.Length;
    }
}
