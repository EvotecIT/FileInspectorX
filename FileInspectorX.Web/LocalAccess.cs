using System.Security.Cryptography;
using System.Text;

namespace FileInspectorX.Web;

/// <summary>Grants access to the running owner's catalog through a private startup link.</summary>
internal sealed class LocalAccess
{
    internal string Token { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

    internal bool Allows(string? authorization)
    {
        const string prefix = "Bearer ";
        return authorization?.Length == prefix.Length + Token.Length &&
            authorization.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
            CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(authorization.Substring(prefix.Length)), Encoding.ASCII.GetBytes(Token));
    }
}
