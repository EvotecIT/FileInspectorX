using System;
using System.IO;

namespace FileInspectorX;

public static partial class FileInspector
{
    private static string ReadHeadText(string path, int cap)
    {
        try
        {
            using var fs = File.OpenRead(path);
            int len = (int)Math.Min(fs.Length, cap);
            if (len <= 0) return string.Empty;
            var buf = new byte[len];
            int n = fs.Read(buf, 0, buf.Length);
            return ReadHeadTextWithBomDetection(buf, n);
        }
        catch (Exception ex)
        {
            if (Settings.Logger.IsWarning)
                Settings.Logger.WriteWarning("text:read failed ({0})", ex.GetType().Name);
            else if (Settings.Logger.IsDebug)
                Settings.Logger.WriteDebug("text:read failed ({0})", ex.GetType().Name);
            return string.Empty;
        }
    }

    private static string ReadHeadTextWithBomDetection(byte[] buffer, int bytesRead)
    {
        if (buffer == null || bytesRead <= 0) return string.Empty;
        int n = Math.Min(bytesRead, buffer.Length);
        if (n <= 0) return string.Empty;

        if (n >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF)
            return n > 3 ? System.Text.Encoding.UTF8.GetString(buffer, 3, n - 3) : string.Empty;
        if (n >= 4 && buffer[0] == 0xFF && buffer[1] == 0xFE && buffer[2] == 0x00 && buffer[3] == 0x00)
            return n > 4 ? new System.Text.UTF32Encoding(false, true, true).GetString(buffer, 4, n - 4) : string.Empty;
        if (n >= 4 && buffer[0] == 0x00 && buffer[1] == 0x00 && buffer[2] == 0xFE && buffer[3] == 0xFF)
            return n > 4 ? new System.Text.UTF32Encoding(true, true, true).GetString(buffer, 4, n - 4) : string.Empty;
        if (n >= 2 && buffer[0] == 0xFF && buffer[1] == 0xFE)
            return n > 2 ? System.Text.Encoding.Unicode.GetString(buffer, 2, n - 2) : string.Empty;
        if (n >= 2 && buffer[0] == 0xFE && buffer[1] == 0xFF)
            return n > 2 ? System.Text.Encoding.BigEndianUnicode.GetString(buffer, 2, n - 2) : string.Empty;
        return System.Text.Encoding.UTF8.GetString(buffer, 0, n);
    }
}
