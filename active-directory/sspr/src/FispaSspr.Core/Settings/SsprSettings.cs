namespace FispaSspr.Core.Settings;

/// <summary>
/// Configurazione del portale (file %ProgramData%\FispaSSPR\config.json, scritto dall'installer e dal pannello).
/// I segreti (password SMTP, credenziali del gateway SMS) sono cifrati con la chiave master, mai in chiaro.
/// </summary>
public sealed record SsprSettings
{
    public int ConfigVersion { get; init; } = 1;
    public GeneralSettings General { get; init; } = new();
    public HostingSettings Hosting { get; init; } = new();
    public DirectorySettings Directory { get; init; } = new();
    public VerificationSettings Verification { get; init; } = new();
    public RateLimitSettings RateLimits { get; init; } = new();
    public PasswordSettings Passwords { get; init; } = new();
    public SmtpSettings Smtp { get; init; } = new();
    public SmsSettings Sms { get; init; } = new();
    public AdminSettings Admin { get; init; } = new();
}

public sealed record GeneralSettings
{
    public string CompanyName { get; init; } = "";
    public string PortalUrl { get; init; } = "";
    public string? LogoPath { get; init; }
    public string HelpdeskContact { get; init; } = "";
    public string DefaultCountryCode { get; init; } = "39";
    public string Culture { get; init; } = "it-IT";
}

public sealed record HostingSettings
{
    public int Port { get; init; } = 443;
    /// <summary>Impronta del certificato in LocalMachine\My (accesso alla chiave privata concesso al gMSA dall'installer).</summary>
    public string CertificateThumbprint { get; init; } = "";
    /// <summary>SID del gMSA del servizio: descrittore DPAPI-NG della chiave master.</summary>
    public string ServiceAccountSid { get; init; } = "";
}

public sealed record DirectorySettings
{
    /// <summary>Vuoto = DC individuato automaticamente nel dominio del server.</summary>
    public string DomainController { get; init; } = "";
    public IReadOnlyList<string> AllowedOus { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> ExcludedGroupSids { get; init; } = Array.Empty<string>();
}

public sealed record VerificationSettings
{
    public bool TotpEnabled { get; init; } = true;
    public bool SmsEnabled { get; init; } = true;
    public bool EmailEnabled { get; init; } = true;
    /// <summary>Metodi da registrare per considerare l'utente registrato.</summary>
    public int MinimumEnrolledMethods { get; init; } = 2;
    /// <summary>Verifiche richieste per il reset (metodi diversi).</summary>
    public int ResetVerifications { get; init; } = 2;
    public int UnlockVerifications { get; init; } = 1;
    /// <summary>Verifica richiesta anche per il cambio con password nota.</summary>
    public bool ChangeRequiresVerification { get; init; } = true;
    public int CodeLifetimeMinutes { get; init; } = 5;
    public int CodeMaxAttempts { get; init; } = 5;
    public int TotpWindowSteps { get; init; } = 1;
    public int FlowSessionMinutes { get; init; } = 10;
    public string TotpIssuer { get; init; } = "FispaSSPR";
}

public sealed record RateLimitSettings
{
    public int PerUserPerHour { get; init; } = 5;
    public int PerIpPerHour { get; init; } = 30;
    public int GlobalPerMinute { get; init; } = 120;
    public int CodesPerUserPerHour { get; init; } = 6;
}

public enum BreachedCheckMode
{
    Off,
    OnlineKAnonymity,
    OfflineList,
}

public sealed record PasswordSettings
{
    /// <summary>Minimo del portale: si applica il maggiore tra questo e quello di dominio/PSO.</summary>
    public int MinLength { get; init; } = 12;
    public IReadOnlyList<string> BannedWords { get; init; } = Array.Empty<string>();
    public BreachedCheckMode BreachedCheck { get; init; } = BreachedCheckMode.OnlineKAnonymity;
    public string? OfflineListPath { get; init; }
    /// <summary>Se il servizio delle password compromesse non risponde: true = si rifiuta la password.</summary>
    public bool BlockWhenBreachCheckUnavailable { get; init; }
}

public sealed record SmtpSettings
{
    public string Host { get; init; } = "";
    public int Port { get; init; } = 25;
    public bool UseStartTls { get; init; } = true;
    public string From { get; init; } = "";
    public string? UserName { get; init; }
    /// <summary>Password cifrata (busta v1), vuota per relay anonimo.</summary>
    public string? PasswordEnvelope { get; init; }
}

public enum SmsProvider
{
    None,
    /// <summary>SMS Gateway for Android (sms-gate.app) in modalita' Local Server: telefono Android in LAN.</summary>
    AndroidGatewayLocal,
    /// <summary>Connettore HTTP generico configurabile.</summary>
    GenericHttp,
}

public sealed record SmsSettings
{
    public SmsProvider Provider { get; init; } = SmsProvider.None;
    /// <summary>URL completo di invio, es. http://192.168.1.50:8080/message per SMS Gateway for Android.</summary>
    public string Endpoint { get; init; } = "";
    public string? UserName { get; init; }
    public string? PasswordEnvelope { get; init; }
    /// <summary>Solo GenericHttp: corpo JSON con i segnaposto {to} e {text}.</summary>
    public string? GenericBodyTemplate { get; init; }
    public string SenderName { get; init; } = "";
}

public sealed record AdminSettings
{
    /// <summary>SID del gruppo SSPR-Admins (configurazione, reset con password temporanea, report).</summary>
    public string AdminGroupSid { get; init; } = "";
    /// <summary>SID del gruppo SSPR-Helpdesk (sblocco, azzeramento metodi, inviti).</summary>
    public string HelpdeskGroupSid { get; init; } = "";
    public bool RequireTotpForAdmins { get; init; } = true;
    public int SessionMinutes { get; init; } = 30;
}
