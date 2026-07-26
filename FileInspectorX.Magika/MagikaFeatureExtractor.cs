namespace FileInspectorX.Magika;

internal static class MagikaFeatureExtractor
{
    internal static int[] Extract(ReadOnlyMemory<byte> content, MagikaModelConfig config)
    {
        var bytes = content.Span;
        var blockLength = Math.Min(config.BlockSize, bytes.Length);
        var beginningBlock = bytes.Slice(0, blockLength);
        var endBlock = bytes.Slice(bytes.Length - blockLength, blockLength);
        return Build(beginningBlock, endBlock, config);
    }

    internal static int[] Extract(Stream content, MagikaModelConfig config)
        => Extract(content, config, out _, out _);

    internal static int[] Extract(
        Stream content,
        MagikaModelConfig config,
        out byte[] beginningBlock,
        out int beginningLength)
    {
        if (!content.CanRead)
            throw new ArgumentException("The content stream must be readable.", nameof(content));
        if (!content.CanSeek)
            throw new NotSupportedException("Magika classification requires a seekable stream.");

        var originalPosition = content.Position;
        try
        {
            var length = content.Length;
            if (length > int.MaxValue)
            {
                return ExtractBlocks(content, length, config, out beginningBlock, out beginningLength);
            }
            return ExtractBlocks(content, length, config, out beginningBlock, out beginningLength);
        }
        finally
        {
            content.Seek(originalPosition, SeekOrigin.Begin);
        }
    }

    private static int[] ExtractBlocks(
        Stream content,
        long length,
        MagikaModelConfig config,
        out byte[] beginning,
        out int beginningLength)
    {
        var blockLength = (int)Math.Min(config.BlockSize, length);
        beginning = new byte[blockLength];
        var ending = new byte[blockLength];

        content.Seek(0, SeekOrigin.Begin);
        beginningLength = ReadExactlyAvailable(content, beginning);
        int endingLength;
        if (beginningLength < blockLength)
        {
            Array.Copy(beginning, ending, beginningLength);
            endingLength = beginningLength;
        }
        else
        {
            content.Seek(Math.Max(0, length - blockLength), SeekOrigin.Begin);
            endingLength = ReadExactlyAvailable(content, ending);
        }

        return Build(
            beginning.AsSpan(0, beginningLength),
            ending.AsSpan(0, endingLength),
            config);
    }

    private static int[] Build(
        ReadOnlySpan<byte> beginningBlock,
        ReadOnlySpan<byte> endBlock,
        MagikaModelConfig config)
    {
        var beginning = TrimLeftAsciiWhitespace(beginningBlock);
        var ending = TrimRightAsciiWhitespace(endBlock);
        if (beginning.Length > config.BeginningSize)
            beginning = beginning.Slice(0, config.BeginningSize);
        if (ending.Length > config.EndSize)
            ending = ending.Slice(ending.Length - config.EndSize, config.EndSize);

        var features = new int[config.BeginningSize + config.MiddleSize + config.EndSize];
        for (var i = 0; i < features.Length; i++)
            features[i] = config.PaddingToken;
        for (var i = 0; i < beginning.Length; i++)
            features[i] = beginning[i];

        var endOffset = config.BeginningSize + config.MiddleSize + config.EndSize - ending.Length;
        for (var i = 0; i < ending.Length; i++)
            features[endOffset + i] = ending[i];
        return features;
    }

    private static int ReadExactlyAvailable(Stream stream, byte[] buffer)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = stream.Read(buffer, offset, buffer.Length - offset);
            if (read == 0)
                break;
            offset += read;
        }
        return offset;
    }

    private static ReadOnlySpan<byte> TrimLeftAsciiWhitespace(ReadOnlySpan<byte> value)
    {
        var index = 0;
        while (index < value.Length && IsAsciiWhitespace(value[index]))
            index++;
        return value.Slice(index);
    }

    private static ReadOnlySpan<byte> TrimRightAsciiWhitespace(ReadOnlySpan<byte> value)
    {
        var length = value.Length;
        while (length > 0 && IsAsciiWhitespace(value[length - 1]))
            length--;
        return value.Slice(0, length);
    }

    private static bool IsAsciiWhitespace(byte value)
        => value is 9 or 10 or 11 or 12 or 13 or 32;
}
