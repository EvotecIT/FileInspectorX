namespace FileInspectorX;

/// <summary>
/// JVM-specific binary validation shared by byte and seekable class-file detection.
/// </summary>
internal static partial class Signatures
{
    private static bool TryDecodeJavaModifiedUtf8(ReadOnlySpan<byte> bytes, out string? value)
    {
        value = null;
        var characters = new char[bytes.Length];
        int characterCount = 0;
        int cursor = 0;
        while (cursor < bytes.Length)
        {
            byte first = bytes[cursor++];
            if (first is >= 0x01 and <= 0x7F)
            {
                characters[characterCount++] = (char)first;
                continue;
            }
            if (first is >= 0xC0 and <= 0xDF)
            {
                if (cursor >= bytes.Length) return false;
                byte second = bytes[cursor++];
                if ((second & 0xC0) != 0x80 || first == 0xC0 && second != 0x80 || first == 0xC1) return false;
                characters[characterCount++] = (char)(((first & 0x1F) << 6) | (second & 0x3F));
                continue;
            }
            if (first is >= 0xE0 and <= 0xEF)
            {
                if (cursor + 2 > bytes.Length) return false;
                byte second = bytes[cursor++];
                byte third = bytes[cursor++];
                if ((second & 0xC0) != 0x80 || (third & 0xC0) != 0x80 || first == 0xE0 && second < 0xA0) return false;
                characters[characterCount++] = (char)(((first & 0x0F) << 12) | ((second & 0x3F) << 6) | (third & 0x3F));
                continue;
            }
            return false;
        }
        value = new string(characters, 0, characterCount);
        return true;
    }
}
