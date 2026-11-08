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

/// <summary>Requisito non rispettato: codice stabile (chiave del catalogo dei testi) ed eventuale valore ({min}, {max}).</summary>
public sealed record PasswordIssue(string Code, int? Value = null);

/// <summary>Verifica di una nuova password prima di inviarla ad AD, con messaggi comprensibili per l'utente.</summary>
public static class PasswordPolicy
{
    private static readonly char[] NameDelimiters = { ',', '.', '-', '_', ' ', '#', '\t' };

    public const string Empty = "pwd.err.empty";
    public const string MinLength = "pwd.err.minLength";
    public const string MaxLength = "pwd.err.maxLength";
    public const string Control = "pwd.err.control";
    public const string Complexity = "pwd.err.complexity";
    public const string Name = "pwd.err.name";
    public const string Banned = "pwd.err.banned";

    /// <summary>Requisiti non rispettati, come codici: il servizio li traduce nella lingua dell'utente.</summary>
    public static IReadOnlyList<PasswordIssue> Check(string? password, PasswordRules rules, PasswordContext context)
    {
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(context);
        var issues = new List<PasswordIssue>();
        if (string.IsNullOrEmpty(password))
        {
            issues.Add(new PasswordIssue(Empty));
            return issues;
        }
        if (password.Length < rules.MinLength) issues.Add(new PasswordIssue(MinLength, rules.MinLength));
        if (password.Length > rules.MaxLength) issues.Add(new PasswordIssue(MaxLength, rules.MaxLength));
        if (password.Any(char.IsControl)) issues.Add(new PasswordIssue(Control));

        if (rules.RequireComplexity)
        {
            if (Categories(password) < 3) issues.Add(new PasswordIssue(Complexity));
            if (ContainsName(password, context)) issues.Add(new PasswordIssue(Name));
        }

        var normalized = Deleet(password);
        foreach (var w in rules.BannedWords.Where(w => !string.IsNullOrWhiteSpace(w) && w.Trim().Length >= 3))
        {
            var word = w.Trim();
            if (password.Contains(word, StringComparison.OrdinalIgnoreCase) || normalized.Contains(Deleet(word), StringComparison.OrdinalIgnoreCase))
            {
                issues.Add(new PasswordIssue(Banned));
                break;
            }
        }
        return issues;
    }

    /// <summary>Come <see cref="Check"/>, con i messaggi italiani predefiniti.</summary>
    public static IReadOnlyList<string> Validate(string? password, PasswordRules rules, PasswordContext context)
        => Check(password, rules, context).Select(DefaultMessage).ToList();

    public static string DefaultMessage(PasswordIssue issue)
    {
        ArgumentNullException.ThrowIfNull(issue);
        return issue.Code switch
        {
            Empty => "Inserire una password.",
            MinLength => $"La password deve avere almeno {issue.Value} caratteri.",
            MaxLength => $"La password non puo' superare {issue.Value} caratteri.",
            Control => "La password contiene caratteri non ammessi.",
            Complexity => "La password deve contenere almeno tre tipi di caratteri tra maiuscole, minuscole, numeri e simboli.",
            Name => "La password non puo' contenere il nome utente o parti del nome.",
            Banned => "La password contiene una parola non ammessa (ad esempio il nome dell'azienda).",
            _ => issue.Code,
        };
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
