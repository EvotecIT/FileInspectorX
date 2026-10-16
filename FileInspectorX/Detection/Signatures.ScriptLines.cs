namespace FileInspectorX;

internal static partial class Signatures
{
    private static bool LooksLikeVbsScript(string lower)
    {
        foreach (var rawLine in lower.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line[0] == '\'') continue;
            if (StartsScriptStatement(line, "option explicit") ||
                StartsScriptStatement(line, "on error resume next") ||
                line.StartsWith("wscript.", StringComparison.Ordinal) ||
                StartsScriptStatement(line, "msgbox") ||
                StartsScriptStatement(line, "dim") && IsVbsVariableDeclaration(line.Substring(3)) ||
                StartsScriptStatement(line, "set") && line.Contains("=") &&
                (line.Contains("createobject(") || line.Contains("wscript."))) return true;
            if (StartsScriptStatement(line, "sub") && line.Contains("(") && lower.Contains("end sub") ||
                StartsScriptStatement(line, "function") && line.Contains("(") && lower.Contains("end function")) return true;
        }
        return false;
    }

    private static bool IsVbsVariableDeclaration(string declaration)
    {
        // DIM accepts comma-separated identifiers with optional array bounds.
        // Requiring the whole declaration avoids treating ordinary prose as code.
        int start = 0;
        int depth = 0;
        for (int cursor = 0; cursor <= declaration.Length; cursor++)
        {
            if (cursor < declaration.Length)
            {
                if (declaration[cursor] == '(') depth++;
                else if (declaration[cursor] == ')') depth--;
                if (depth < 0) return false;
                if (declaration[cursor] != ',' || depth != 0) continue;
            }
            if (depth != 0) return false;
            var name = declaration.Substring(start, cursor - start).Trim();
            start = cursor + 1;
            int comment = name.IndexOf('\'');
            if (comment >= 0) name = name.Substring(0, comment).TrimEnd();
            int array = name.IndexOf('(');
            if (array >= 0)
            {
                if (!name.EndsWith(")", StringComparison.Ordinal)) return false;
                name = name.Substring(0, array).TrimEnd();
            }
            if (name.Length == 0 || !char.IsLetter(name[0]) && name[0] != '_') return false;
            for (int index = 1; index < name.Length; index++)
                if (!char.IsLetterOrDigit(name[index]) && name[index] != '_') return false;
        }
        return true;
    }

    private static bool LooksLikeBatchScript(string lower)
    {
        foreach (var rawLine in lower.Split('\n'))
        {
            var line = rawLine.TrimStart();
            if (line.StartsWith("@", StringComparison.Ordinal)) line = line.Substring(1);
            if (StartsScriptStatement(line, "echo off") || StartsScriptStatement(line, "setlocal") ||
                StartsScriptStatement(line, "endlocal") || StartsScriptStatement(line, "goto") ||
                StartsScriptStatement(line, "rem")) return true;
        }
        return false;
    }

    private static bool StartsScriptStatement(string line, string statement)
        => line.StartsWith(statement, StringComparison.Ordinal) &&
           (line.Length == statement.Length || char.IsWhiteSpace(line[statement.Length]) ||
            line[statement.Length] is '(' or ':' or '\'');
}
