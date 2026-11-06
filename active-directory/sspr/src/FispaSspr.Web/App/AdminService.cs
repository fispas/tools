using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FispaSspr.Core.Abstractions;
using FispaSspr.Core.Crypto;
using FispaSspr.Core.Model;
using FispaSspr.Core.Otp;
using FispaSspr.Core.Policy;
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

    public AdminService(SettingsStore settings, AdDirectory ad, PortalService portal, AuditLog audit, AdminTotpStore totp, KeyStore keys, SmtpChannel mail, SmsChannel sms, TimeProvider time)
    {
        _settings = settings; _ad = ad; _portal = portal; _audit = audit; _totp = totp; _keys = keys; _mail = mail; _sms = sms; _time = time;
    }

    private SsprSettings S => _settings.Current;

    private Task Audit(AuditEventId id, AuditOutcome o, string? target, SessionData s, string? ip, string message) =>
        _audit.WriteAsync(new AuditEntry(id, o, target, s.UserName, ip, message));

    // ------------------------------------------------------------------ accesso e secondo fattore

    public void RequireOperator(SessionData s, bool adminOnly = false)
    {
        if (!s.Authenticated || !s.IsOperator || s.AuthMethod != "windows") throw new PortalException(403, "Accesso al pannello riservato agli operatori autenticati con Windows.");
        if (S.Admin.RequireTotpForAdmins && !s.AdminSecondFactor) throw new PortalException(403, "Completare la verifica con l'app di autenticazione.");
        if (adminOnly && !s.IsAdmin) throw new PortalException(403, "Operazione riservata agli amministratori.");
    }

    public object SecondFactorStatus(SessionData s) => new
    {
        operatorSession = s.IsOperator && s.AuthMethod == "windows",
        enrolled = s.UserSid is not null && _totp.IsEnrolled(s.UserSid),
        verified = s.AdminSecondFactor,
        isAdmin = s.IsAdmin,
        isHelpdesk = s.IsHelpdesk,
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
                await Audit(AuditEventId.AdminDenied, AuditOutcome.Failure, s.UserName, s, ip, "Secondo fattore errato").ConfigureAwait(false);
                throw new PortalException(400, "Codice non valido.");
            }
            _totp.Set(s.UserSid, stored.Value.Secret, step.Value);
        }
        s.AdminSecondFactor = true;
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

    public async Task Unlock(SessionData s, string sid, string? reason, string? ip)
    {
        RequireOperator(s);
        var why = Reason(reason);
        var u = await Target(s, sid).ConfigureAwait(false);
        var r = await _ad.UnlockAsync(u).ConfigureAwait(false);
        if (r != PasswordOperationResult.Ok) throw new PortalException(500, "Sblocco non riuscito: " + r);
        await Audit(AuditEventId.AdminAction, AuditOutcome.Success, u.SamAccountName, s, ip, "Sblocco dal pannello. Motivo: " + why).ConfigureAwait(false);
    }

    public async Task ClearEnrollment(SessionData s, string sid, string? reason, string? ip)
    {
        RequireOperator(s);
        var why = Reason(reason);
        var u = await Target(s, sid).ConfigureAwait(false);
        await _ad.WriteAsync(u, SsprAttributes.All.ToDictionary(a => a, _ => (string?)null)).ConfigureAwait(false);
        await Audit(AuditEventId.EnrollmentResetByAdmin, AuditOutcome.Success, u.SamAccountName, s, ip, "Metodi di verifica azzerati. Motivo: " + why).ConfigureAwait(false);
    }

    public async Task Invite(SessionData s, string sid, string? ip)
    {
        RequireOperator(s);
        var u = await Target(s, sid).ConfigureAwait(false);
        var mail = await _ad.GetMailAsync(u).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(mail)) throw new PortalException(400, "L'utente non ha un indirizzo email aziendale (attributo mail).");
        if (!_mail.Configured) throw new PortalException(400, "SMTP non configurato.");
        var url = string.IsNullOrWhiteSpace(S.General.PortalUrl) ? "il portale password aziendale" : S.General.PortalUrl;
        await _mail.SendAsync(mail, "Registrati al portale password",
            $"Ciao {u.DisplayName ?? u.SamAccountName},\n\nregistra i tuoi metodi di verifica su {url}: ti serviranno per reimpostare la password o sbloccare l'account in autonomia, senza chiamare l'help desk.\n\nL'operazione richiede pochi minuti dal PC aziendale.").ConfigureAwait(false);
        await Audit(AuditEventId.AdminAction, AuditOutcome.Success, u.SamAccountName, s, ip, "Invito a registrarsi inviato").ConfigureAwait(false);
    }

    public async Task<object> TemporaryReset(SessionData s, string sid, string? reason, string? ip)
    {
        RequireOperator(s, adminOnly: true);
        var why = Reason(reason);
        var u = await Target(s, sid).ConfigureAwait(false);
        var rules = await _ad.GetPasswordRulesAsync(u).ConfigureAwait(false);
        var pwd = GeneratePassword(Math.Max(16, rules.MinLength));
        var r = await _ad.ResetPasswordAsync(u, pwd, mustChangeAtNextLogon: true).ConfigureAwait(false);
        if (r != PasswordOperationResult.Ok) throw new PortalException(500, "Reset non riuscito: " + r);
        await Audit(AuditEventId.AdminAction, AuditOutcome.Success, u.SamAccountName, s, ip, "Reset con password temporanea e cambio obbligatorio. Motivo: " + why).ConfigureAwait(false);
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

    public sealed record SettingsUpdate(SsprSettings Settings, string? SmtpPassword, string? SmsPassword);

    public async Task SaveSettings(SessionData s, SettingsUpdate update, string? ip)
    {
        RequireOperator(s, adminOnly: true);
        var cur = S;
        var n = update.Settings ?? throw new PortalException(400, "Configurazione mancante.");
        if (n.Verification.MinimumEnrolledMethods < 1 || n.Verification.ResetVerifications < 1 || n.Verification.CodeLifetimeMinutes is < 1 or > 30 || n.Verification.CodeMaxAttempts is < 1 or > 10)
            throw new PortalException(400, "Valori di verifica non validi.");
        var key = _keys.Current;
        var smtpEnv = update.SmtpPassword is null ? cur.Smtp.PasswordEnvelope : SettingsStore.Encrypt(update.SmtpPassword, key, "smtp");
        var smsEnv = update.SmsPassword is null ? cur.Sms.PasswordEnvelope : SettingsStore.Encrypt(update.SmsPassword, key, "sms");
        // Hosting e gruppi degli operatori si cambiano solo dall'installer
        var admin = n.Admin with { AdminGroupSid = cur.Admin.AdminGroupSid, HelpdeskGroupSid = cur.Admin.HelpdeskGroupSid };
        var smtp = n.Smtp with { PasswordEnvelope = smtpEnv };
        var sms = n.Sms with { PasswordEnvelope = smsEnv };
        var merged = n with { ConfigVersion = cur.ConfigVersion, Hosting = cur.Hosting, Admin = admin, Smtp = smtp, Sms = sms };
        _settings.Save(merged);
        await Audit(AuditEventId.ConfigurationChanged, AuditOutcome.Success, null, s, ip, "Configurazione modificata dal pannello").ConfigureAwait(false);
    }

    public async Task ResetOperatorTotp(SessionData s, string sid, string? ip)
    {
        RequireOperator(s, adminOnly: true);
        if (string.Equals(sid, s.UserSid, StringComparison.OrdinalIgnoreCase)) throw new PortalException(403, "Non e' possibile azzerare la propria app.");
        _totp.Remove(sid);
        await Audit(AuditEventId.AdminAction, AuditOutcome.Success, sid, s, ip, "Azzerata l'app di autenticazione di un operatore").ConfigureAwait(false);
    }
}
