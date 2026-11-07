using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FispaSspr.Core.Abstractions;
using FispaSspr.Core.Crypto;
using FispaSspr.Core.Model;
using FispaSspr.Core.Otp;
using FispaSspr.Core.Policy;
using FispaSspr.Core.Security;
using FispaSspr.Core.Settings;
using FispaSspr.Web.Infrastructure;

namespace FispaSspr.Web.App;

/// <summary>Pannello di amministrazione: ruoli Helpdesk e Admin, secondo fattore TOTP obbligatorio.</summary>
public sealed class AdminService
{
    private readonly SettingsStore _settings;
    private readonly AdDirectory _ad;
    private readonly PortalService _portal;
    private readonly AuditLog _audit;
    private readonly AdminTotpStore _totp;
    private readonly KeyStore _keys;
    private readonly SmtpChannel _mail;
    private readonly SmsChannel _sms;
    private readonly TimeProvider _time;
    private readonly SlidingWindowRateLimiter _limiter;
    private readonly TextCatalog _texts;

    public AdminService(SettingsStore settings, AdDirectory ad, PortalService portal, AuditLog audit, AdminTotpStore totp, KeyStore keys, SmtpChannel mail, SmsChannel sms, TimeProvider time,
        SlidingWindowRateLimiter limiter, TextCatalog texts)
    {
        _settings = settings; _ad = ad; _portal = portal; _audit = audit; _totp = totp; _keys = keys; _mail = mail; _sms = sms; _time = time; _limiter = limiter; _texts = texts;
    }

    private SsprSettings S => _settings.Current;
    private FeatureSettings F => _settings.Current.Features;

    private Task Audit(AuditEventId id, AuditOutcome o, string? target, SessionData s, string? ip, string message) =>
        _audit.WriteAsync(new AuditEntry(id, o, target, s.UserName, ip, message));

    // ------------------------------------------------------------------ accesso e secondo fattore

    public void RequireOperator(SessionData s, bool adminOnly = false)
    {
        if (!s.Authenticated || !s.IsOperator || s.AuthMethod != "windows") throw new PortalException(403, "Accesso al pannello riservato agli operatori autenticati con Windows.", code: "admin.windows");
        if (S.Admin.RequireTotpForAdmins)
        {
            if (!s.AdminSecondFactor) throw new PortalException(403, "Completare la verifica con l'app di autenticazione.", code: "admin.2fa");
            var max = TimeSpan.FromMinutes(Math.Clamp(S.Admin.SessionMinutes, 5, 480));
            if (s.AdminSecondFactorAt is null || _time.GetUtcNow() - s.AdminSecondFactorAt.Value > max)
            {
                s.AdminSecondFactor = false;
                throw new PortalException(403, "Sessione del pannello scaduta: ripetere la verifica con l'app di autenticazione.", code: "admin.2fa");
            }
        }
        if (adminOnly && !s.IsAdmin) throw new PortalException(403, "Operazione riservata agli amministratori.");
    }

    /// <summary>Azione consentita all'help desk solo se attivata in configurazione; gli amministratori possono sempre.</summary>
    private void RequireHelpdeskAction(SessionData s, bool helpdeskAllowed)
    {
        RequireOperator(s);
        if (!s.IsAdmin && !helpdeskAllowed) throw new PortalException(403, "Operazione non consentita all'help desk.");
    }

    public object SecondFactorStatus(SessionData s) => new
    {
        operatorSession = s.IsOperator && s.AuthMethod == "windows",
        enrolled = s.UserSid is not null && _totp.IsEnrolled(s.UserSid),
        verified = s.AdminSecondFactor,
        isAdmin = s.IsAdmin,
        isHelpdesk = s.IsHelpdesk,
        operatorName = s.DisplayName ?? s.UserName,
        can = new
        {
            unlock = s.IsAdmin || F.HelpdeskCanUnlock,
            clearEnrollment = s.IsAdmin || F.HelpdeskCanClearEnrollment,
            invite = s.IsAdmin || F.HelpdeskCanInvite,
            temporaryReset = s.IsAdmin && F.AdminCanTemporaryReset,
            settings = s.IsAdmin,
        },
    };

    public object SecondFactorSetup(SessionData s)
    {
        if (!s.IsOperator || s.AuthMethod != "windows" || s.UserSid is null) throw new PortalException(403, "Accesso negato.");
        if (_totp.IsEnrolled(s.UserSid)) throw new PortalException(409, "App gia' configurata: per sostituirla serve un altro amministratore.");
        s.PendingAdminTotp = Totp.NewSecret();
        var uri = Totp.ProvisioningUri(s.PendingAdminTotp, S.Verification.TotpIssuer + " Admin", s.UserName ?? s.UserSid);
        return new { qrCodeSvg = PortalService.QrSvg(uri), manualKey = Base32.Encode(s.PendingAdminTotp) };
    }

    public async Task<object> SecondFactorVerify(SessionData s, string? code, string? ip)
    {
        if (!s.IsOperator || s.AuthMethod != "windows" || s.UserSid is null) throw new PortalException(403, "Accesso negato.");
        _portal.LimitGlobal(ip);
        var key = "admin2fa:" + s.UserSid;
        var max = Math.Clamp(S.Admin.MaxSecondFactorFailuresPerHour, 3, 20);
        var wait = _limiter.RetryAfter(key, max, TimeSpan.FromHours(1));
        if (wait > TimeSpan.Zero) throw new PortalException(429, "Troppi codici errati: riprovare piu' tardi.", retryAfter: wait);
        var now = _time.GetUtcNow();
        var stored = _totp.Get(s.UserSid);
        if (stored is null)
        {
            if (s.PendingAdminTotp is null) throw new PortalException(400, "Configurare prima l'app.");
            var step = Totp.Verify(s.PendingAdminTotp, code, now, 0, S.Verification.TotpWindowSteps) ?? throw new PortalException(400, "Codice non valido.");
            _totp.Set(s.UserSid, s.PendingAdminTotp, step);
            s.PendingAdminTotp = null;
        }
        else
        {
            var step = Totp.Verify(stored.Value.Secret, code, now, stored.Value.LastStep, S.Verification.TotpWindowSteps);
            if (step is null)
            {
                _limiter.TryAcquire(key, max, TimeSpan.FromHours(1));
                await Audit(AuditEventId.AdminDenied, AuditOutcome.Failure, s.UserName, s, ip, "Secondo fattore errato").ConfigureAwait(false);
                throw new PortalException(400, "Codice non valido.");
            }
            _totp.Set(s.UserSid, stored.Value.Secret, step.Value);
        }
        s.AdminSecondFactor = true;
        s.AdminSecondFactorAt = now;
        await Audit(AuditEventId.AdminSignIn, AuditOutcome.Success, s.UserName, s, ip, s.IsAdmin ? "Accesso come Admin" : "Accesso come Helpdesk").ConfigureAwait(false);
        return SecondFactorStatus(s);
    }

    // ------------------------------------------------------------------ utenti

    private async Task<object> UserDto(DirectoryUser u, bool withEvents)
    {
        var p = AccountProtection.Evaluate(u, _portal.Scope);
        object? enrollment = null;
        if (p.Manageable)
        {
            var (e, _) = await _portal.LoadEnrollment(u, CancellationToken.None).ConfigureAwait(false);
            enrollment = _portal.EnrollmentStatus(e);
        }
        var events = withEvents
            ? _audit.Query(_time.GetUtcNow().AddDays(-90), _time.GetUtcNow(), u.SamAccountName, null, 30).Select(r => new { time = r.Time, eventId = r.EventId, message = r.Message }).ToArray()
            : Array.Empty<object>();
        return new
        {
            sid = u.Sid, userName = u.SamAccountName, displayName = u.DisplayName, upn = u.UserPrincipalName,
            enabled = u.Enabled, lockedOut = u.LockedOut, manageable = p.Manageable, notManageableReason = p.Reason, enrollment, lastEvents = events,
        };
    }

    public async Task<object[]> Search(SessionData s, string? q)
    {
        RequireOperator(s);
        if (string.IsNullOrWhiteSpace(q) || q.Trim().Length < 2) return Array.Empty<object>();
        var users = await _ad.SearchUsersAsync(q.Trim(), 50).ConfigureAwait(false);
        var list = new List<object>();
        foreach (var u in users) list.Add(await UserDto(u, false).ConfigureAwait(false));
        return list.ToArray();
    }

    private async Task<DirectoryUser> Target(SessionData s, string sid, bool requireManageable = true)
    {
        var u = await _ad.FindUserBySidAsync(sid).ConfigureAwait(false) ?? throw new PortalException(404, "Utente non trovato.");
        if (!AccountProtection.IsInScope(u.DistinguishedName, S.Directory.AllowedOus)) throw new PortalException(403, "Utente fuori dalle OU abilitate.");
        if (string.Equals(u.Sid, s.UserSid, StringComparison.OrdinalIgnoreCase) && requireManageable) throw new PortalException(403, "Non e' possibile operare sul proprio account.");
        if (requireManageable)
        {
            var p = AccountProtection.Evaluate(u, _portal.Scope);
            if (!p.Manageable) throw new PortalException(403, "Account non gestibile: " + p.Reason + ".");
        }
        return u;
    }

    public async Task<object> Detail(SessionData s, string sid)
    {
        RequireOperator(s);
        return await UserDto(await Target(s, sid, requireManageable: false).ConfigureAwait(false), true).ConfigureAwait(false);
    }

    private static string Reason(string? reason)
    {
        var r = (reason ?? string.Empty).Trim();
        if (r.Length < 5) throw new PortalException(400, "Indicare il motivo (almeno 5 caratteri).");
        return r.Length > 500 ? r[..500] : r;
    }

    private async Task NotifyUser(DirectoryUser u, string name)
    {
        try
        {
            var (e, _) = await _portal.LoadEnrollment(u, CancellationToken.None).ConfigureAwait(false);
            await _portal.Notify(u, e, name, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or InvalidOperationException) { }
    }

    public async Task Unlock(SessionData s, string sid, string? reason, string? ip)
    {
        RequireHelpdeskAction(s, F.HelpdeskCanUnlock);
        var why = Reason(reason);
        var u = await Target(s, sid).ConfigureAwait(false);
        var r = await _ad.UnlockAsync(u).ConfigureAwait(false);
        if (r != PasswordOperationResult.Ok) throw new PortalException(500, "Sblocco non riuscito: " + r);
        await Audit(AuditEventId.AdminAction, AuditOutcome.Success, u.SamAccountName, s, ip, "Sblocco dal pannello. Motivo: " + why).ConfigureAwait(false);
        await NotifyUser(u, "adminUnlock").ConfigureAwait(false);
    }

    public async Task ClearEnrollment(SessionData s, string sid, string? reason, string? ip)
    {
        RequireHelpdeskAction(s, F.HelpdeskCanClearEnrollment);
        var why = Reason(reason);
        var u = await Target(s, sid).ConfigureAwait(false);
        // la notifica parte prima dell'azzeramento: dopo non ci sarebbero piu' recapiti
        await NotifyUser(u, "adminClearEnrollment").ConfigureAwait(false);
        await _ad.WriteAsync(u, SsprAttributes.All.ToDictionary(a => a, _ => (string?)null)).ConfigureAwait(false);
        await Audit(AuditEventId.EnrollmentResetByAdmin, AuditOutcome.Success, u.SamAccountName, s, ip, "Metodi di verifica azzerati. Motivo: " + why).ConfigureAwait(false);
    }

    public async Task Invite(SessionData s, string sid, string? ip)
    {
        RequireHelpdeskAction(s, F.HelpdeskCanInvite);
        var u = await Target(s, sid).ConfigureAwait(false);
        var mail = await _ad.GetMailAsync(u).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(mail)) throw new PortalException(400, "L'utente non ha un indirizzo email aziendale (attributo mail).");
        if (!_mail.Configured) throw new PortalException(400, "SMTP non configurato.");
        var (subject, body, _) = _texts.Notification("invite", ("user", u.SamAccountName), ("displayName", u.DisplayName ?? u.SamAccountName));
        await _mail.SendAsync(mail, subject, body).ConfigureAwait(false);
        await Audit(AuditEventId.AdminAction, AuditOutcome.Success, u.SamAccountName, s, ip, "Invito a registrarsi inviato").ConfigureAwait(false);
    }

    public async Task<object> TemporaryReset(SessionData s, string sid, string? reason, string? ip)
    {
        RequireOperator(s, adminOnly: true);
        if (!F.AdminCanTemporaryReset) throw new PortalException(403, "Reset con password temporanea disattivato in configurazione.");
        var why = Reason(reason);
        var u = await Target(s, sid).ConfigureAwait(false);
        var rules = await _ad.GetPasswordRulesAsync(u).ConfigureAwait(false);
        var pwd = GeneratePassword(Math.Max(16, rules.MinLength));
        var r = await _ad.ResetPasswordAsync(u, pwd, mustChangeAtNextLogon: true).ConfigureAwait(false);
        if (r != PasswordOperationResult.Ok) throw new PortalException(500, "Reset non riuscito: " + r);
        await Audit(AuditEventId.AdminAction, AuditOutcome.Success, u.SamAccountName, s, ip, "Reset con password temporanea e cambio obbligatorio. Motivo: " + why).ConfigureAwait(false);
        await NotifyUser(u, "adminTemporaryReset").ConfigureAwait(false);
        return new { temporaryPassword = pwd };
    }

    internal static string GeneratePassword(int length)
    {
        const string upper = "ABCDEFGHJKLMNPQRSTUVWXYZ", lower = "abcdefghijkmnpqrstuvwxyz", digits = "23456789", symbols = "!#%+-=?@_";
        var all = upper + lower + digits + symbols;
        var chars = new List<char>
        {
            upper[RandomNumberGenerator.GetInt32(upper.Length)], lower[RandomNumberGenerator.GetInt32(lower.Length)],
            digits[RandomNumberGenerator.GetInt32(digits.Length)], symbols[RandomNumberGenerator.GetInt32(symbols.Length)],
        };
        while (chars.Count < length) chars.Add(all[RandomNumberGenerator.GetInt32(all.Length)]);
        for (var i = chars.Count - 1; i > 0; i--) { var j = RandomNumberGenerator.GetInt32(i + 1); (chars[i], chars[j]) = (chars[j], chars[i]); }
        return new string(chars.ToArray());
    }

    // ------------------------------------------------------------------ cruscotto, audit, stato, configurazione

    public async Task<object> Dashboard(SessionData s)
    {
        RequireOperator(s);
        var now = _time.GetUtcNow();
        var ev = _audit.Query(now.AddDays(-30), now, null, null, int.MaxValue);
        (int inScope, int enrolled) = (0, 0);
        try { (inScope, enrolled) = await _ad.CountUsersAsync().ConfigureAwait(false); } catch (System.Runtime.InteropServices.COMException) { }
        return new
        {
            usersInScope = inScope,
            usersEnrolled = enrolled,
            resetsLast30Days = ev.Count(e => e.EventId == (int)AuditEventId.PasswordReset),
            changesLast30Days = ev.Count(e => e.EventId == (int)AuditEventId.PasswordChanged),
            unlocksLast30Days = ev.Count(e => e.EventId == (int)AuditEventId.AccountUnlocked),
            blockedAttemptsLast24h = ev.Count(e => e.Time > now.AddDays(-1) && (e.EventId == (int)AuditEventId.RateLimitTriggered || e.EventId == (int)AuditEventId.ProtectedAccountAttempt || e.EventId == (int)AuditEventId.ResetVerificationFailed)),
        };
    }

    public IReadOnlyList<AuditLog.Record> AuditQuery(SessionData s, DateTimeOffset? from, DateTimeOffset? to, string? user, int? eventId)
    {
        RequireOperator(s);
        var now = _time.GetUtcNow();
        return _audit.Query(from ?? now.AddDays(-30), to ?? now, user, eventId, 5000);
    }

    public object Health(SessionData s)
    {
        RequireOperator(s);
        string dc;
        try { dc = "OK - " + _ad.NamingContext; } catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or InvalidOperationException) { dc = "ERRORE - " + ex.Message; }
        string cert = "non configurato";
        if (!string.IsNullOrEmpty(S.Hosting.CertificateThumbprint))
        {
            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            var c = store.Certificates.Find(X509FindType.FindByThumbprint, S.Hosting.CertificateThumbprint, false).FirstOrDefault();
            cert = c is null ? "ERRORE - certificato non trovato" : $"{c.Subject} - scade il {c.NotAfter:dd/MM/yyyy}" + (c.NotAfter < DateTime.Now.AddDays(30) ? " (IN SCADENZA)" : string.Empty);
        }
        return new
        {
            version = typeof(AdminService).Assembly.GetName().Version?.ToString(),
            domainController = dc,
            smtp = _mail.Configured ? $"{S.Smtp.Host}:{S.Smtp.Port}" : "non configurato",
            sms = _sms.Configured ? $"{S.Sms.Provider} - {S.Sms.Endpoint}" : "non configurato",
            certificate = cert,
            masterKey = _keys.HasKey ? "OK - " + _keys.Current.Id : "ERRORE - " + _keys.LoadError,
            server = Environment.MachineName,
        };
    }

    public async Task TestChannel(SessionData s, string channel, string? destination, string? ip)
    {
        RequireOperator(s, adminOnly: true);
        if (string.IsNullOrWhiteSpace(destination)) throw new PortalException(400, "Indicare la destinazione del test.");
        IMessageChannel ch = channel == "sms" ? _sms : _mail;
        try { await ch.SendAsync(destination.Trim(), "Test FispaSSPR", "Messaggio di prova dal portale password.").ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException) { throw new PortalException(502, "Invio non riuscito: " + ex.Message); }
        await Audit(AuditEventId.AdminAction, AuditOutcome.Success, null, s, ip, "Test del canale " + channel).ConfigureAwait(false);
    }

    /// <summary>Configurazione senza segreti.</summary>
    public object GetSettings(SessionData s)
    {
        RequireOperator(s, adminOnly: true);
        var c = S;
        var smtp = c.Smtp with { PasswordEnvelope = string.IsNullOrEmpty(c.Smtp.PasswordEnvelope) ? null : "***" };
        var sms = c.Sms with { PasswordEnvelope = string.IsNullOrEmpty(c.Sms.PasswordEnvelope) ? null : "***" };
        return c with { Smtp = smtp, Sms = sms };
    }

    /// <summary>Catalogo dei testi con predefiniti, gruppi e descrizioni, per l'editor del pannello.</summary>
    public object TextCatalogDto(SessionData s)
    {
        RequireOperator(s, adminOnly: true);
        return _texts.Defaults.Select(kv => new
        {
            key = kv.Key, group = kv.Value.Group, description = kv.Value.Description, defaultText = kv.Value.Text,
            customText = S.Branding.Texts.TryGetValue(kv.Key, out var v) ? v : null,
        }).ToArray();
    }

    public sealed record SettingsUpdate(SsprSettings Settings, string? SmtpPassword, string? SmsPassword);

    public async Task SaveSettings(SessionData s, SettingsUpdate update, string? ip)
    {
        RequireOperator(s, adminOnly: true);
        var cur = S;
        var n = update.Settings ?? throw new PortalException(400, "Configurazione mancante.");
        var errors = Validate(n);
        var texts = _texts.Sanitize(n.Branding?.Texts, errors);
        if (errors.Count > 0) throw new PortalException(400, "Configurazione non valida.", errors);
        var key = _keys.Current;
        var smtpEnv = update.SmtpPassword is null ? cur.Smtp.PasswordEnvelope : SettingsStore.Encrypt(update.SmtpPassword, key, "smtp");
        var smsEnv = update.SmsPassword is null ? cur.Sms.PasswordEnvelope : SettingsStore.Encrypt(update.SmsPassword, key, "sms");
        // Hosting, gruppi degli operatori e obbligo del secondo fattore si cambiano solo dall'installer / config.json
        var admin = n.Admin with { AdminGroupSid = cur.Admin.AdminGroupSid, HelpdeskGroupSid = cur.Admin.HelpdeskGroupSid, RequireTotpForAdmins = cur.Admin.RequireTotpForAdmins };
        // i file dell'aspetto si cambiano solo con il caricamento dedicato
        var branding = n.Branding! with { Texts = texts, LogoFile = cur.Branding.LogoFile, FaviconFile = cur.Branding.FaviconFile, BackgroundFile = cur.Branding.BackgroundFile };
        var smtp = n.Smtp with { PasswordEnvelope = smtpEnv };
        var sms = n.Sms with { PasswordEnvelope = smsEnv };
        var general = n.General with { LogoPath = null };
        var merged = n with { ConfigVersion = cur.ConfigVersion, Hosting = cur.Hosting, Admin = admin, Branding = branding, Smtp = smtp, Sms = sms, General = general };
        _settings.Save(merged);
        await Audit(AuditEventId.ConfigurationChanged, AuditOutcome.Success, null, s, ip, "Configurazione modificata dal pannello").ConfigureAwait(false);
    }

    private static List<string> Validate(SsprSettings n)
    {
        var e = new List<string>();
        if (n.General is null || n.Verification is null || n.Branding is null || n.Features is null || n.Directory is null || n.Smtp is null || n.Sms is null
            || n.Admin is null || n.Passwords is null || n.RateLimits is null || n.Notifications is null || n.Sessions is null || n.Audit is null)
        {
            e.Add("Sezioni della configurazione mancanti.");
            return e;
        }
        var v = n.Verification;
        if (v.MinimumEnrolledMethods is < 1 or > 3) e.Add("Metodi minimi: da 1 a 3.");
        if (v.ResetVerifications is < 1 or > 3 || v.UnlockVerifications is < 1 or > 3) e.Add("Verifiche per reset e sblocco: da 1 a 3.");
        if (v.ResetVerifications > v.MinimumEnrolledMethods) e.Add("Le verifiche per il reset non possono superare i metodi minimi da registrare.");
        if (v.CodeLifetimeMinutes is < 1 or > 30) e.Add("Durata dei codici: da 1 a 30 minuti.");
        if (v.CodeMaxAttempts is < 1 or > 10) e.Add("Tentativi per codice: da 1 a 10.");
        if (v.TotpWindowSteps is < 0 or > 3) e.Add("Tolleranza TOTP: da 0 a 3 intervalli.");
        if (v.FlowSessionMinutes is < 3 or > 60) e.Add("Durata del flusso di reset: da 3 a 60 minuti.");
        var methods = (v.TotpEnabled ? 1 : 0) + (v.SmsEnabled ? 1 : 0) + (v.EmailEnabled ? 1 : 0);
        if (methods < v.MinimumEnrolledMethods) e.Add($"Metodi attivi ({methods}) inferiori al minimo richiesto ({v.MinimumEnrolledMethods}).");
        var r = n.RateLimits;
        if (r.PerUserPerHour is < 1 or > 100 || r.PerIpPerHour is < 1 or > 10000 || r.GlobalPerMinute is < 1 or > 10000 || r.CodesPerUserPerHour is < 1 or > 50) e.Add("Limiti dei tentativi fuori intervallo.");
        if (n.Passwords.MinLength is < 8 or > 128) e.Add("Lunghezza minima della password: da 8 a 128.");
        if (n.Passwords.BannedWords.Count > 500 || n.Passwords.BannedWords.Any(w => w.Length > 100)) e.Add("Parole vietate: massimo 500, ciascuna fino a 100 caratteri.");
        foreach (var ou in n.Directory.AllowedOus)
            if (!ou.Contains("DC=", StringComparison.OrdinalIgnoreCase) || ou.IndexOfAny(new[] { '(', ')', '*', '\0' }) >= 0) e.Add("OU non valida: " + ou);
        if (n.Directory.AllowedOus.Count == 0) e.Add("Indicare almeno una OU abilitata.");
        foreach (var sid in n.Directory.ExcludedGroupSids)
            try { _ = new System.Security.Principal.SecurityIdentifier(sid); } catch (ArgumentException) { e.Add("SID non valido: " + sid); }
        if (!string.IsNullOrWhiteSpace(n.Directory.DomainController) && !System.Text.RegularExpressions.Regex.IsMatch(n.Directory.DomainController, @"^[A-Za-z0-9.\-]{1,255}$")) e.Add("Nome del domain controller non valido.");
        if (!IsUrl(n.General.PortalUrl, httpsOnly: true)) e.Add("Indirizzo del portale: URL https completo o vuoto.");
        if (!IsUrl(n.Branding.HelpUrl, httpsOnly: false)) e.Add("Collegamento alla guida: URL http(s) completo o vuoto.");
        if (n.Sms.Provider != SmsProvider.None && !IsUrl(n.Sms.Endpoint, httpsOnly: false)) e.Add("URL del gateway SMS non valido.");
        if (n.Smtp.Port is < 1 or > 65535) e.Add("Porta SMTP non valida.");
        if (!string.IsNullOrWhiteSpace(n.Smtp.From) && FispaSspr.Core.Security.Normalization.Email(n.Smtp.From) is null) e.Add("Mittente SMTP non valido.");
        var b = n.Branding;
        foreach (var (name, color) in new[] { ("primario", b.PrimaryColor), ("primario scuro", b.PrimaryDarkColor), ("sfondo", b.BackgroundColor), ("riquadri", b.CardColor), ("testo", b.TextColor),
                     ("testo secondario", b.MutedColor), ("intestazione", b.HeaderColor), ("testo intestazione", b.HeaderTextColor), ("successo", b.SuccessColor), ("errore", b.ErrorColor) })
            if (!BrandingStore.IsColor(color)) e.Add($"Colore {name} non valido: usare il formato #RRGGBB.");
        if (!BrandingStore.IsFont(b.FontFamily)) e.Add("Carattere non valido (solo lettere, numeri, spazi, virgole, trattini e virgolette).");
        if (BrandingStore.CssProblem(b.CustomCss) is { } css) e.Add(css);
        if (b.CornerRadius is < 0 or > 30 || b.LogoHeight is < 16 or > 160) e.Add("Arrotondamento (0-30) o altezza del logo (16-160) fuori intervallo.");
        if (b.Announcement.Level is not ("info" or "warn" or "err")) e.Add("Livello dell'avviso: info, warn o err.");
        if (b.Announcement.Text.Length > 1000 || b.PortalTitle.Length > 100 || b.Tagline.Length > 300 || n.General.CompanyName.Length > 100 || n.General.HelpdeskContact.Length > 200)
            e.Add("Testi dell'aspetto troppo lunghi.");
        if (n.Sessions.UserIdleMinutes is < 2 or > 240 || n.Sessions.UserAbsoluteMinutes is < 5 or > 1440 || n.Sessions.StepUpMinutes is < 1 or > 30 || n.Sessions.MinResponseMilliseconds is < 200 or > 5000)
            e.Add("Durate delle sessioni fuori intervallo.");
        if (n.Admin.SessionMinutes is < 5 or > 480 || n.Admin.MaxSecondFactorFailuresPerHour is < 3 or > 20) e.Add("Impostazioni degli operatori fuori intervallo.");
        if (n.Audit.RetentionMonths is < 1 or > 120) e.Add("Conservazione dell'audit: da 1 a 120 mesi.");
        if (!n.Features.WindowsLoginEnabled && !n.Features.PasswordLoginEnabled && (n.Features.ChangeEnabled || n.Features.EnrollmentEnabled))
            e.Add("Con accesso Windows e accesso con password entrambi disattivati, cambio password e registrazione non sono utilizzabili.");
        return e;
    }

    private static bool IsUrl(string? value, bool httpsOnly) =>
        string.IsNullOrWhiteSpace(value) ||
        (Uri.TryCreate(value, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttps || (!httpsOnly && u.Scheme == Uri.UriSchemeHttp)) && string.IsNullOrEmpty(u.UserInfo));

    // ------------------------------------------------------------------ aspetto: file caricati

    public sealed record AssetUpload(string? DataBase64);

    public async Task UploadAsset(SessionData s, string asset, AssetUpload upload, string? ip)
    {
        RequireOperator(s, adminOnly: true);
        if (!BrandingStore.Assets.Contains(asset)) throw new PortalException(404, "Elemento non valido.");
        byte[] data;
        try { data = Convert.FromBase64String(upload.DataBase64 ?? string.Empty); }
        catch (FormatException) { throw new PortalException(400, "File non valido."); }
        string file;
        try { file = BrandingStore.Save(asset, data); }
        catch (ArgumentException ex) { throw new PortalException(400, ex.Message); }
        SetAssetFile(asset, file);
        await Audit(AuditEventId.BrandingChanged, AuditOutcome.Success, null, s, ip, $"Caricato {asset} ({data.Length / 1024} KB)").ConfigureAwait(false);
    }

    public async Task DeleteAsset(SessionData s, string asset, string? ip)
    {
        RequireOperator(s, adminOnly: true);
        if (!BrandingStore.Assets.Contains(asset)) throw new PortalException(404, "Elemento non valido.");
        BrandingStore.Delete(asset);
        SetAssetFile(asset, null);
        await Audit(AuditEventId.BrandingChanged, AuditOutcome.Success, null, s, ip, "Rimosso " + asset).ConfigureAwait(false);
    }

    private void SetAssetFile(string asset, string? file)
    {
        var c = S;
        var b = asset switch
        {
            "logo" => c.Branding with { LogoFile = file },
            "favicon" => c.Branding with { FaviconFile = file },
            _ => c.Branding with { BackgroundFile = file },
        };
        _settings.Save(c with { Branding = b });
    }

    public async Task ResetOperatorTotp(SessionData s, string sid, string? ip)
    {
        RequireOperator(s, adminOnly: true);
        if (string.Equals(sid, s.UserSid, StringComparison.OrdinalIgnoreCase)) throw new PortalException(403, "Non e' possibile azzerare la propria app.");
        _totp.Remove(sid);
        await Audit(AuditEventId.AdminAction, AuditOutcome.Success, sid, s, ip, "Azzerata l'app di autenticazione di un operatore").ConfigureAwait(false);
    }
}
