namespace FileInspectorX;

/// <summary>
/// PNG-specific stream helpers used to preserve exact DEFLATE framing evidence.
/// </summary>
internal static partial class Signatures
{
    private enum PngIdatValidation
    {
        Invalid,
        BudgetOrUnsupported,
        Valid
    }

    private static PngIdatValidation ValidatePngIdat(byte[] idat, bool budgetExceeded, uint width, uint height,
        byte bitDepth, byte colorType, int paletteEntries, byte interlace, int budget)
    {
        if (budgetExceeded || interlace != 0) return PngIdatValidation.BudgetOrUnsupported;
        if (idat.Length < 7) return PngIdatValidation.Invalid;
        int header = idat[0] << 8 | idat[1];
        int windowBits = (idat[0] >> 4) + 8;
        if ((idat[0] & 0x0F) != 8 || windowBits > 15 || header % 31 != 0 || (idat[1] & 0x20) != 0)
            return PngIdatValidation.Invalid;

        int channels = colorType switch { 0 => 1, 2 => 3, 3 => 1, 4 => 2, 6 => 4, _ => 0 };
        ulong rowBytes = ((ulong)width * (uint)channels * bitDepth + 7) / 8;
        ulong expectedLength = (rowBytes + 1) * height;
        if (channels == 0 || expectedLength == 0 || expectedLength > (ulong)budget || expectedLength > int.MaxValue)
            return PngIdatValidation.BudgetOrUnsupported;

        var decoded = new byte[(int)expectedLength];
        try
        {
            using var compressed = new MemoryStream(idat, 2, idat.Length - 6, writable: false);
            using var exactCompressed = new SingleByteReadStream(compressed);
            using var inflater = new System.IO.Compression.DeflateStream(
                exactCompressed, System.IO.Compression.CompressionMode.Decompress, leaveOpen: true);
            int read = 0;
            while (read < decoded.Length)
            {
                int count = inflater.Read(decoded, read, decoded.Length - read);
                if (count == 0) return PngIdatValidation.Invalid;
                read += count;
            }
            if (inflater.ReadByte() != -1 || compressed.Position != compressed.Length)
                return PngIdatValidation.Invalid;
        }
        catch (InvalidDataException)
        {
            return PngIdatValidation.Invalid;
        }
        catch (IOException)
        {
            return PngIdatValidation.Invalid;
        }

        uint storedAdler = (uint)idat[idat.Length - 4] << 24 | (uint)idat[idat.Length - 3] << 16 |
                           (uint)idat[idat.Length - 2] << 8 | idat[idat.Length - 1];
        if (storedAdler != ComputePngAdler32(decoded)) return PngIdatValidation.Invalid;

        int rowLength = checked((int)rowBytes);
        if (colorType == 3 && !TryValidateIndexedPngRows(decoded, checked((int)width), checked((int)height),
                rowLength, bitDepth, paletteEntries)) return PngIdatValidation.Invalid;
        if (colorType != 3)
        {
            int rowStride = rowLength + 1;
            for (int row = 0; row < (int)height; row++)
                if (decoded[row * rowStride] > 4) return PngIdatValidation.Invalid;
        }

        // DeflateStream consumes a raw stream and cannot enforce a smaller CINFO window.
        return windowBits < 15 ? PngIdatValidation.BudgetOrUnsupported : PngIdatValidation.Valid;
    }

    private static bool TryValidateIndexedPngRows(byte[] decoded, int width, int height, int rowLength,
        byte bitDepth, int paletteEntries)
    {
        if (paletteEntries < 1) return false;
        var previous = new byte[rowLength];
        var current = new byte[rowLength];
        int bytesPerPixel = Math.Max(1, (bitDepth + 7) / 8);
        int rowStride = rowLength + 1;
        for (int row = 0; row < height; row++)
        {
            int rowOffset = row * rowStride;
            byte filter = decoded[rowOffset];
            if (filter > 4) return false;
            for (int column = 0; column < rowLength; column++)
            {
                byte left = column >= bytesPerPixel ? current[column - bytesPerPixel] : (byte)0;
                byte up = previous[column];
                byte upperLeft = column >= bytesPerPixel ? previous[column - bytesPerPixel] : (byte)0;
                byte filtered = decoded[rowOffset + 1 + column];
                current[column] = filter switch
                {
                    0 => filtered,
                    1 => unchecked((byte)(filtered + left)),
                    2 => unchecked((byte)(filtered + up)),
                    3 => unchecked((byte)(filtered + ((left + up) >> 1))),
                    4 => unchecked((byte)(filtered + PaethPredictor(left, up, upperLeft))),
                    _ => 0
                };
            }
            for (int pixel = 0; pixel < width; pixel++)
            {
                int samplesPerByte = 8 / bitDepth;
                int shift = 8 - bitDepth - pixel % samplesPerByte * bitDepth;
                int sample = current[pixel / samplesPerByte] >> shift & (1 << bitDepth) - 1;
                if (sample >= paletteEntries) return false;
            }
            (previous, current) = (current, previous);
            Array.Clear(current, 0, current.Length);
        }
        return true;
    }

    private static byte PaethPredictor(byte left, byte up, byte upperLeft)
    {
        int prediction = left + up - upperLeft;
        int leftDistance = Math.Abs(prediction - left);
        int upDistance = Math.Abs(prediction - up);
        int upperLeftDistance = Math.Abs(prediction - upperLeft);
        return leftDistance <= upDistance && leftDistance <= upperLeftDistance ? left :
            upDistance <= upperLeftDistance ? up : upperLeft;
    }

    private static uint ComputePngAdler32(ReadOnlySpan<byte> data)
    {
        const uint modulus = 65521;
        uint a = 1, b = 0;
        for (int index = 0; index < data.Length; index++)
        {
            a = (a + data[index]) % modulus;
            b = (b + a) % modulus;
        }
        return b << 16 | a;
    }

    /// <summary>
    /// Prevents <see cref="System.IO.Compression.DeflateStream"/> from reading ahead
    /// across the logical end of a DEFLATE stream, so trailing compressed bytes remain
    /// observable to the PNG validator.
    /// </summary>
    private sealed class SingleByteReadStream : Stream
    {
        private readonly Stream _inner;

        internal SingleByteReadStream(Stream inner) => _inner = inner;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
            => count == 0 ? 0 : _inner.Read(buffer, offset, 1);

        public override int ReadByte() => _inner.ReadByte();
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
