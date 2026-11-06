namespace FispaSspr.Core.Security;

/// <summary>Mascheramento dei metodi registrati mostrati all'utente durante il reset.</summary>
public static class Masking
{
    /// <summary>+393331234567 -> "+39 *** *** 567"; 3331234567 -> "*** *** 567".</summary>
    public static string Phone(string? phone)
    {
        if (string.IsNullOrWhiteSpace(phone)) return string.Empty;
        var trimmed = phone.Trim();
        var digits = new string(trimmed.Where(char.IsAsciiDigit).ToArray());
        if (digits.Length < 4) return "***";
        var last = digits[^3..];
        if (trimmed.StartsWith('+') && digits.Length > 5) return $"+{digits[..2]} *** *** {last}";
        return $"*** *** {last}";
    }

    /// <summary>mario.rossi@gmail.com -> "m***@g***.com".</summary>
    public static string Email(string? email)
    {
        if (string.IsNullOrWhiteSpace(email)) return string.Empty;
        var at = email.LastIndexOf('@');
        if (at <= 0 || at == email.Length - 1) return "***";
        var local = email[..at];
        var domain = email[(at + 1)..];
        var dot = domain.LastIndexOf('.');
        var tld = dot > 0 ? domain[dot..] : string.Empty;
        return $"{local[0]}***@{domain[0]}***{tld}";
    }
}
