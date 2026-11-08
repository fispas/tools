using System.Text;
using System.Text.RegularExpressions;

namespace FispaSspr.Core.Security;

/// <summary>Validazione e normalizzazione degli input inseriti dagli utenti.</summary>
public static partial class Normalization
{
    // parte locale: solo caratteri "atext" (niente virgolette, virgole, spazi, < >); dominio: etichette DNS (IDN in forma punycode)
    [GeneratedRegex(@"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}$", RegexOptions.CultureInvariant)]
    private static partial Regex EmailRegex();

    /// <summary>Numero in formato E.164 (+393331234567). Senza prefisso internazionale si usa <paramref name="defaultCountryCode"/>.</summary>
    public static string? Phone(string? input, string defaultCountryCode = "39")
    {
        if (string.IsNullOrWhiteSpace(input)) return null;
        var s = input.Trim();
        var plus = s.StartsWith('+');
        if (s.StartsWith("00", StringComparison.Ordinal)) { plus = true; s = s[2..]; }
        var digits = new StringBuilder();
        foreach (var c in s)
        {
            if (char.IsAsciiDigit(c)) digits.Append(c);
            else if (c is ' ' or '-' or '.' or '(' or ')' or '/' or '+') continue;
            else return null;
        }
        var d = digits.ToString();
        if (!plus) d = defaultCountryCode + d;
        if (d.Length < 8 || d.Length > 15) return null;
        return "+" + d;
    }

    public static string? Email(string? input)
    {
        if (string.IsNullOrWhiteSpace(input)) return null;
        var s = input.Trim();
        if (s.Length > 254 || !EmailRegex().IsMatch(s)) return null;
        var at = s.LastIndexOf('@');
        if (at > 64) return null;
        return s[..at] + "@" + s[(at + 1)..].ToLowerInvariant();
    }

    /// <summary>
    /// Nome utente inserito nel modulo di reset: accetta sAMAccountName, DOMINIO\utente o UPN.
    /// Restituisce null se contiene caratteri non ammessi (protegge anche le query LDAP).
    /// </summary>
    public static string? UserName(string? input)
    {
        if (string.IsNullOrWhiteSpace(input)) return null;
        var s = input.Trim();
        if (s.Length > 256) return null;
        var bs = s.IndexOf('\\');
        if (bs >= 0) s = s[(bs + 1)..];
        foreach (var c in s)
        {
            if (char.IsControl(c) || "\"/[]:;|=,+*?<>()\\".Contains(c)) return null;
        }
        return s.Length == 0 ? null : s;
    }
}
