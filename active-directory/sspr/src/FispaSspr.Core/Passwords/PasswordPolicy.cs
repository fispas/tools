namespace FispaSspr.Core.Passwords;

/// <summary>Regole della password: quelle di dominio/PSO lette da AD, piu' quelle del portale.</summary>
public sealed record PasswordRules
{
    public int MinLength { get; init; } = 12;
    public int MaxLength { get; init; } = 256;
    /// <summary>Complessita' di Windows: 3 categorie su 5 e niente nome utente / nome visualizzato.</summary>
    public bool RequireComplexity { get; init; } = true;
    /// <summary>Parole vietate (nome azienda, prodotti...), confrontate anche in forma "leet" (P4ssw0rd).</summary>
    public IReadOnlyList<string> BannedWords { get; init; } = Array.Empty<string>();
}

public sealed record PasswordContext(string? SamAccountName, string? DisplayName);

/// <summary>Verifica di una nuova password prima di inviarla ad AD, con messaggi comprensibili per l'utente.</summary>
public static class PasswordPolicy
{
    private static readonly char[] NameDelimiters = { ',', '.', '-', '_', ' ', '#', '\t' };

    public static IReadOnlyList<string> Validate(string? password, PasswordRules rules, PasswordContext context)
    {
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(context);
        var errors = new List<string>();
        if (string.IsNullOrEmpty(password))
        {
            errors.Add("Inserire una password.");
            return errors;
        }
        if (password.Length < rules.MinLength) errors.Add($"La password deve avere almeno {rules.MinLength} caratteri.");
        if (password.Length > rules.MaxLength) errors.Add($"La password non puo' superare {rules.MaxLength} caratteri.");
        if (password.Any(char.IsControl)) errors.Add("La password contiene caratteri non ammessi.");

        if (rules.RequireComplexity)
        {
            if (Categories(password) < 3)
                errors.Add("La password deve contenere almeno tre tipi di caratteri tra maiuscole, minuscole, numeri e simboli.");
            if (ContainsName(password, context))
                errors.Add("La password non puo' contenere il nome utente o parti del nome.");
        }

        var normalized = Deleet(password);
        foreach (var w in rules.BannedWords.Where(w => !string.IsNullOrWhiteSpace(w) && w.Trim().Length >= 3))
        {
            var word = w.Trim();
            if (password.Contains(word, StringComparison.OrdinalIgnoreCase) || normalized.Contains(Deleet(word), StringComparison.OrdinalIgnoreCase))
            {
                errors.Add("La password contiene una parola non ammessa (ad esempio il nome dell'azienda).");
                break;
            }
        }
        return errors;
    }

    /// <summary>Categorie di caratteri secondo Windows: maiuscole, minuscole, cifre, simboli, altri caratteri Unicode alfabetici.</summary>
    internal static int Categories(string password)
    {
        bool upper = false, lower = false, digit = false, symbol = false, other = false;
        foreach (var c in password)
        {
            if (char.IsUpper(c)) upper = true;
            else if (char.IsLower(c)) lower = true;
            else if (char.IsDigit(c)) digit = true;
            else if (char.IsLetter(c)) other = true;
            else symbol = true;
        }
        return (upper ? 1 : 0) + (lower ? 1 : 0) + (digit ? 1 : 0) + (symbol ? 1 : 0) + (other ? 1 : 0);
    }

    private static bool ContainsName(string password, PasswordContext ctx)
    {
        if (!string.IsNullOrEmpty(ctx.SamAccountName) && ctx.SamAccountName.Length >= 3 &&
            password.Contains(ctx.SamAccountName, StringComparison.OrdinalIgnoreCase))
            return true;
        if (string.IsNullOrEmpty(ctx.DisplayName)) return false;
        return ctx.DisplayName
            .Split(NameDelimiters, StringSplitOptions.RemoveEmptyEntries)
            .Where(t => t.Length >= 3)
            .Any(t => password.Contains(t, StringComparison.OrdinalIgnoreCase));
    }

    internal static string Deleet(string s)
    {
        var chars = s.ToLowerInvariant().ToCharArray();
        for (var i = 0; i < chars.Length; i++)
        {
            chars[i] = chars[i] switch
            {
                '0' => 'o',
                '1' or '!' or '|' => 'i',
                '3' => 'e',
                '4' or '@' => 'a',
                '5' or '$' => 's',
                '7' => 't',
                '8' => 'b',
                _ => chars[i],
            };
        }
        return new string(chars);
    }
}
