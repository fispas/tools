namespace FispaSspr.Core.Model;

public enum VerificationMethod
{
    Totp,
    Sms,
    Email,
}

/// <summary>Utente letto da AD, con le informazioni necessarie a decidere se e' gestibile dal portale.</summary>
public sealed record DirectoryUser
{
    public required string Sid { get; init; }
    public required string SamAccountName { get; init; }
    public required string DistinguishedName { get; init; }
    public string? UserPrincipalName { get; init; }
    public string? DisplayName { get; init; }
    public bool Enabled { get; init; } = true;
    public bool LockedOut { get; init; }
    public bool PasswordExpired { get; init; }
    public int AdminCount { get; init; }
    /// <summary>SID di tutti i gruppi, anche annidati (tokenGroups).</summary>
    public IReadOnlyCollection<string> GroupSids { get; init; } = Array.Empty<string>();
    public IReadOnlyCollection<string> ObjectClasses { get; init; } = Array.Empty<string>();
}

/// <summary>Stato della registrazione (contenuto dell'attributo fispaSsprState, cifrato).</summary>
public sealed record EnrollmentState
{
    public int V { get; init; } = 1;
    public DateTimeOffset? EnrolledAt { get; init; }
    public DateTimeOffset? TotpVerifiedAt { get; init; }
    public DateTimeOffset? MobileVerifiedAt { get; init; }
    public DateTimeOffset? EmailVerifiedAt { get; init; }
    public DateTimeOffset? LastResetAt { get; init; }
    public long LastTotpStep { get; init; }
}

/// <summary>Metodi registrati da un utente, in chiaro (solo in memoria del servizio).</summary>
public sealed record Enrollment
{
    public byte[]? TotpSecret { get; init; }
    public string? Mobile { get; init; }
    public string? Email { get; init; }
    public EnrollmentState State { get; init; } = new();

    public static Enrollment Empty { get; } = new();

    public IReadOnlyList<VerificationMethod> Methods
    {
        get
        {
            var m = new List<VerificationMethod>(3);
            if (TotpSecret is { Length: > 0 } && State.TotpVerifiedAt is not null) m.Add(VerificationMethod.Totp);
            if (!string.IsNullOrEmpty(Mobile) && State.MobileVerifiedAt is not null) m.Add(VerificationMethod.Sms);
            if (!string.IsNullOrEmpty(Email) && State.EmailVerifiedAt is not null) m.Add(VerificationMethod.Email);
            return m;
        }
    }

    public bool IsEnrolled(int minimumMethods) => Methods.Count >= Math.Max(1, minimumMethods);
}
