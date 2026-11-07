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
    public FeatureSettings Features { get; init; } = new();
    public BrandingSettings Branding { get; init; } = new();
    public NotificationSettings Notifications { get; init; } = new();
    public SessionSettings Sessions { get; init; } = new();
    public AuditSettings Audit { get; init; } = new();
}

/// <summary>Funzioni attivabili singolarmente (controllate dal servizio, non solo nascoste nell'interfaccia).</summary>
public sealed record FeatureSettings
{
    public bool ResetEnabled { get; init; } = true;
    public bool UnlockEnabled { get; init; } = true;
    public bool ChangeEnabled { get; init; } = true;
    public bool EnrollmentEnabled { get; init; } = true;
    public bool WindowsLoginEnabled { get; init; } = true;
    public bool PasswordLoginEnabled { get; init; } = true;
    /// <summary>La prima registrazione dei metodi e' consentita solo con autenticazione Windows (PC aziendale).</summary>
    public bool FirstEnrollmentRequiresWindowsLogin { get; init; }
    /// <summary>Utente gia' registrato: per aggiungere, sostituire o rimuovere metodi conferma con un metodo esistente.</summary>
    public bool StepUpForEnrollmentChanges { get; init; } = true;
    public bool AllowMethodRemoval { get; init; } = true;
    /// <summary>Reset: sblocca anche l'account se bloccato.</summary>
    public bool ResetUnlocksAccount { get; init; } = true;
    /// <summary>Reset: obbliga a cambiare la password al prossimo accesso.</summary>
    public bool ResetForcesChangeAtNextLogon { get; init; }
    /// <summary>Codici di reset/sblocco inviati in background: tempi di risposta indipendenti dal gateway (anti-enumerazione).</summary>
    public bool BackgroundCodeDelivery { get; init; } = true;
    public bool ShowPasswordRequirements { get; init; } = true;
    public bool HelpdeskCanUnlock { get; init; } = true;
    public bool HelpdeskCanClearEnrollment { get; init; } = true;
    public bool HelpdeskCanInvite { get; init; } = true;
    public bool AdminCanTemporaryReset { get; init; } = true;
}

/// <summary>Aspetto del portale: loghi, colori, testi. I file caricati stanno in %ProgramData%\FispaSSPR\branding.</summary>
public sealed record BrandingSettings
{
    public string PortalTitle { get; init; } = "";
    public string Tagline { get; init; } = "";
    public bool ShowCompanyNameInHeader { get; init; } = true;
    public string? LogoFile { get; init; }
    public string? FaviconFile { get; init; }
    public string? BackgroundFile { get; init; }
    public int LogoHeight { get; init; } = 36;
    public string PrimaryColor { get; init; } = "#1d4ed8";
    public string PrimaryDarkColor { get; init; } = "#1e40af";
    public string BackgroundColor { get; init; } = "#f4f6f9";
    public string CardColor { get; init; } = "#ffffff";
    public string TextColor { get; init; } = "#1a202c";
    public string MutedColor { get; init; } = "#64748b";
    public string HeaderColor { get; init; } = "#ffffff";
    public string HeaderTextColor { get; init; } = "#1a202c";
    public string SuccessColor { get; init; } = "#15803d";
    public string ErrorColor { get; init; } = "#b91c1c";
    public string FontFamily { get; init; } = "\"Segoe UI\", system-ui, -apple-system, Arial, sans-serif";
    public int CornerRadius { get; init; } = 10;
    /// <summary>CSS aggiuntivo (solo amministratori). Risorse esterne comunque bloccate dalla CSP.</summary>
    public string CustomCss { get; init; } = "";
    public string HelpUrl { get; init; } = "";
    public AnnouncementSettings Announcement { get; init; } = new();
    /// <summary>Testi personalizzati: chiave del catalogo -> testo. Le chiavi assenti usano il testo predefinito.</summary>
    public IReadOnlyDictionary<string, string> Texts { get; init; } = new Dictionary<string, string>();
}

public sealed record AnnouncementSettings
{
    public bool Enabled { get; init; }
    /// <summary>info, warn, err</summary>
    public string Level { get; init; } = "info";
    public string Text { get; init; } = "";
}

/// <summary>Notifiche all'utente, attivabili per evento. Oggetto e testo sono nel catalogo dei testi (chiavi notify.*).</summary>
public sealed record NotificationSettings
{
    public bool MethodAdded { get; init; } = true;
    public bool MethodRemoved { get; init; } = true;
    public bool PasswordChanged { get; init; } = true;
    public bool PasswordReset { get; init; } = true;
    public bool AccountUnlocked { get; init; } = true;
    public bool AdminUnlock { get; init; } = true;
    public bool AdminClearEnrollment { get; init; } = true;
    public bool AdminTemporaryReset { get; init; } = true;
    /// <summary>Canali usati per le notifiche: email personale, SMS, email aziendale (attributo mail).</summary>
    public bool ViaPersonalEmail { get; init; } = true;
    public bool ViaSms { get; init; } = true;
    public bool ViaCorporateEmail { get; init; }
}

public sealed record SessionSettings
{
    public int UserIdleMinutes { get; init; } = 15;
    public int UserAbsoluteMinutes { get; init; } = 120;
    /// <summary>Validita' della conferma d'identita' (step-up) per modificare metodi o password.</summary>
    public int StepUpMinutes { get; init; } = 5;
    /// <summary>Tempo minimo delle risposte di reset/sblocco/login (anti-enumerazione).</summary>
    public int MinResponseMilliseconds { get; init; } = 700;
    public int MaxSessions { get; init; } = 20000;
}

public sealed record AuditSettings
{
    public int RetentionMonths { get; init; } = 24;
}

public sealed record GeneralSettings
{
    public string CompanyName { get; init; } = "";
    public string PortalUrl { get; init; } = "";
    /// <summary>Obsoleto: sostituito da Branding.LogoFile (caricamento dal pannello). Ignorato.</summary>
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
    /// <summary>Modificabile solo da config.json/installer, mai dal pannello.</summary>
    public bool RequireTotpForAdmins { get; init; } = true;
    /// <summary>Durata massima della sessione dell'operatore dopo il secondo fattore.</summary>
    public int SessionMinutes { get; init; } = 30;
    /// <summary>Tentativi errati del secondo fattore per operatore e per ora.</summary>
    public int MaxSecondFactorFailuresPerHour { get; init; } = 5;
}
