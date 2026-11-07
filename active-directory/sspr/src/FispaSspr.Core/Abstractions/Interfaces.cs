using FispaSspr.Core.Model;
using FispaSspr.Core.Passwords;

namespace FispaSspr.Core.Abstractions;

public enum PasswordOperationResult
{
    Ok,
    /// <summary>Rifiutata da AD: complessita', cronologia o eta' minima.</summary>
    PolicyViolation,
    /// <summary>Password attuale errata (solo cambio).</summary>
    WrongCurrentPassword,
    AccountLocked,
    AccessDenied,
    Error,
}

/// <summary>Accesso ad Active Directory. L'implementazione gira con l'identita' del gMSA del servizio.</summary>
public interface IDirectory
{
    /// <summary>Cerca per sAMAccountName o UPN, solo nel dominio del servizio. Null se non trovato.</summary>
    Task<DirectoryUser?> FindUserAsync(string userName, CancellationToken ct = default);
    Task<DirectoryUser?> FindUserBySidAsync(string sid, CancellationToken ct = default);
    Task<IReadOnlyList<DirectoryUser>> SearchUsersAsync(string text, int max, CancellationToken ct = default);

    /// <summary>Regole delle password effettive per l'utente (policy di dominio o PSO).</summary>
    Task<PasswordRules> GetPasswordRulesAsync(DirectoryUser user, CancellationToken ct = default);

    /// <summary>Reset amministrativo (dopo la verifica dell'identita'). Opzionale: cambio obbligatorio al prossimo accesso.</summary>
    Task<PasswordOperationResult> ResetPasswordAsync(DirectoryUser user, string newPassword, bool mustChangeAtNextLogon, CancellationToken ct = default);

    /// <summary>Cambio eseguito come l'utente: rispetta cronologia ed eta' minima.</summary>
    Task<PasswordOperationResult> ChangePasswordAsync(DirectoryUser user, string currentPassword, string newPassword, CancellationToken ct = default);

    /// <summary>Verifica la password attuale con un bind LDAP (accesso da VPN senza autenticazione Windows).</summary>
    Task<bool> ValidateCredentialsAsync(DirectoryUser user, string password, CancellationToken ct = default);

    Task<PasswordOperationResult> UnlockAsync(DirectoryUser user, CancellationToken ct = default);
}

/// <summary>Lettura e scrittura degli attributi fispaSspr* (valori gia' cifrati).</summary>
public interface IEnrollmentStore
{
    Task<IReadOnlyDictionary<string, string?>> ReadAsync(DirectoryUser user, CancellationToken ct = default);
    Task WriteAsync(DirectoryUser user, IReadOnlyDictionary<string, string?> values, CancellationToken ct = default);
}

/// <summary>Invio di un messaggio (codice o notifica) su un canale.</summary>
public interface IMessageChannel
{
    VerificationMethod Method { get; }
    Task SendAsync(string destination, string subject, string text, CancellationToken ct = default);
}

public enum AuditOutcome
{
    Success,
    Failure,
    Blocked,
}

public sealed record AuditEntry(
    AuditEventId EventId,
    AuditOutcome Outcome,
    string? TargetUser,
    string? Actor,
    string? ClientIp,
    string Message);

public interface IAuditLog
{
    Task WriteAsync(AuditEntry entry, CancellationToken ct = default);
}

/// <summary>ID degli eventi nel Registro eventi "SSPR" (documentati in docs/eventi.md).</summary>
public enum AuditEventId
{
    ServiceStarted = 1000,
    ServiceStopped = 1001,
    EnrollmentMethodAdded = 1101,
    EnrollmentMethodRemoved = 1102,
    EnrollmentResetByAdmin = 1103,
    EnrollmentInvalidData = 1104,
    StepUpVerified = 1105,
    StepUpFailed = 1106,
    UserSignIn = 1150,
    UserSignInFailed = 1151,
    PasswordChanged = 1201,
    PasswordChangeFailed = 1202,
    ResetRequested = 1301,
    ResetVerificationFailed = 1302,
    PasswordReset = 1303,
    ResetBlocked = 1304,
    AccountUnlocked = 1401,
    UnlockFailed = 1402,
    AdminSignIn = 1501,
    AdminAction = 1502,
    AdminDenied = 1503,
    ProtectedAccountAttempt = 1601,
    RateLimitTriggered = 1602,
    ConfigurationChanged = 1900,
    BrandingChanged = 1901,
    Error = 1990,
}
