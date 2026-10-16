using System.Globalization;
using System.Text;

namespace FileInspectorX;

public static partial class MarkdownRenderer
{
    // Every interpolation passes through this formatter. Only renderer-owned markup may
    // bypass it; raw report values remain unchanged for JSON and other consumers.
    private static void AppendSafeLine(this StringBuilder builder, FormattableString line)
        => builder.AppendLine(line.ToString(MarkdownValueFormatter.Instance));

    private static void AppendTextLine(this StringBuilder builder, string? text)
    {
        var escaped = EscapeText(text ?? string.Empty);
        // These values occupy a whole paragraph rather than a renderer-owned bullet.
        // Prevent file-controlled prefixes from creating lists or thematic breaks.
        int start = 0;
        while (start < escaped.Length && escaped[start] == ' ') start++;
        if (start < escaped.Length && escaped[start] is '-' or '+')
            escaped = escaped.Insert(start, "\\");
        else
        {
            int end = start;
            while (end < escaped.Length && end - start < 9 && char.IsDigit(escaped[end])) end++;
            if (end > start && end < escaped.Length && escaped[end] is '.' or ')')
                escaped = escaped.Insert(end, "\\");
        }
        builder.AppendLine(escaped);
    }

    private static SafeMarkdown Code(string text) => new(FormatCode(text));

    private static SafeMarkdown InlineEvidence(string? evidence)
        => new(string.IsNullOrWhiteSpace(evidence) ? string.Empty : " -> " + FormatCode(evidence!));

    private static string EscapeText(string value)
    {
        var escaped = new StringBuilder(value.Length);
        for (int index = 0; index < value.Length; index++)
        {
            var character = value[index];
            switch (character)
            {
                case '&': escaped.Append("&amp;"); break;
                case '<': escaped.Append("&lt;"); break;
                case '>': escaped.Append("&gt;"); break;
                // Character references display the original text without forming bare-URL
                // or email autolinks. References in a report are evidence, not actions.
                case ':': escaped.Append("&#58;"); break;
                case '@': escaped.Append("&#64;"); break;
                case '.' when index >= 3 && string.Equals(value.Substring(index - 3, 3), "www", StringComparison.OrdinalIgnoreCase):
                    escaped.Append("&#46;"); break;
                case '\\': case '`': case '~': case '*': case '_': case '[': case ']': case '!': case '#': case '|':
                    escaped.Append('\\').Append(character); break;
                default:
                    escaped.Append(char.IsControl(character) || character is '\u2028' or '\u2029' ? ' ' : character);
                    break;
            }
        }
        return escaped.ToString();
    }

    private static string FormatCode(string text)
    {
        var normalized = new StringBuilder(text.Length);
        int longestRun = 0, run = 0;
        foreach (var character in text)
        {
            normalized.Append(char.IsControl(character) || character is '\u2028' or '\u2029' ? ' ' : character);
            run = character == '`' ? run + 1 : 0;
            longestRun = Math.Max(longestRun, run);
        }
        var delimiter = new string('`', longestRun + 1);
        // Padding stops input backticks from merging with our delimiters. CommonMark
        // removes the surrounding spaces when the content is not entirely spaces.
        var content = normalized.ToString();
        var padding = content.Length > 0 && (content[0] is '`' or ' ' || content[content.Length - 1] is '`' or ' ')
            ? " " : string.Empty;
        return delimiter + padding + content + padding + delimiter;
    }

    private readonly struct SafeMarkdown
    {
        internal string Value { get; }
        internal SafeMarkdown(string value) => Value = value;
    }

    private sealed class MarkdownValueFormatter : IFormatProvider, ICustomFormatter
    {
        internal static readonly MarkdownValueFormatter Instance = new();
        public object? GetFormat(Type? formatType) => formatType == typeof(ICustomFormatter) ? this : null;
        public string Format(string? format, object? argument, IFormatProvider? provider)
        {
            if (argument is SafeMarkdown markup) return markup.Value;
            if (argument is string textValue) return EscapeText(textValue);
            var text = argument is IFormattable formattable
                ? formattable.ToString(format, CultureInfo.InvariantCulture)
                : argument?.ToString();
            return text ?? string.Empty;
        }
    }
}
