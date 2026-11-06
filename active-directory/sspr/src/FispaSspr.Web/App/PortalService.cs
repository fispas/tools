using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using FispaSspr.Core.Abstractions;
using FispaSspr.Core.Crypto;
using FispaSspr.Core.Model;
using FispaSspr.Core.Otp;
using FispaSspr.Core.Passwords;
using FispaSspr.Core.Policy;
using FispaSspr.Core.Security;
using FispaSspr.Core.Settings;
using FispaSspr.Web.Infrastructure;

namespace FispaSspr.Web.App;

/// <summary>Errore da mostrare all'utente (messaggio gia' in italiano).</summary>
public sealed class PortalException : Exception
{
    public PortalException(int status, string message, IReadOnlyList<string>? errors = null, TimeSpan? retryAfter = null) : base(message)
    {
        Status = status;
        Errors = errors ?? Array.Empty<string>();
        RetryAfter = retryAfter;
    }

    public int Status { get; }
    public IReadOnlyList<string> Errors { get; }
    public TimeSpan? RetryAfter { get; }
}

public sealed class FlowMethod
{
    public required string Id { get; init; }
    public required VerificationMethod Method { get; init; }
    public required string Masked { get; init; }
    public string? Destination { get; init; }
    public bool Used { get; set; }
}

public sealed class Flow
{
    public required string Id { get; init; }
    public required string SessionId { get; init; }
    public required string Purpose { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public required int Required { get; init; }
    public required List<FlowMethod> Methods { get; init; }
    public string? UserSid { get; init; }
    public string? UserName { get; init; }
    public bool Fake { get; init; }
    public string? CurrentMethodId { get; set; }
    public string? CurrentChallengeId { get; set; }
    public DateTimeOffset? CurrentChallengeExpires { get; set; }
    public int Failures { get; set; }
    public int Done => Methods.Count(m => m.Used);
    public bool Ready => !Fake && Done >= Required;
}

/// <summary>Logica del portale: registrazione, cambio, reset e sblocco.</summary>
public sealed class PortalService
{
    private static readonly TimeSpan MinResponse = TimeSpan.FromMilliseconds(600);

    private readonly SettingsStore _settings;
    private readonly AdDirectory _ad;
    private readonly IMasterKeyProvider _keys;
    private readonly EnrollmentCodec _codec;
    private readonly SmtpChannel _mail;
    private readonly SmsChannel _sms;
    private readonly IAuditLog _audit;
    private readonly IBreachedPasswordChecker _breach;
    private readonly OtpChallengeStore _otp;
    private readonly SlidingWindowRateLimiter _limiter;
    private readonly TimeProvider _time;
    private readonly ILogger<PortalService> _log;
    private readonly ConcurrentDictionary<string, Flow> _flows = new(StringComparer.Ordinal);
    private readonly byte[] _fakeKey = RandomNumberGenerator.GetBytes(32);

    public PortalService(SettingsStore settings, AdDirectory ad, IMasterKeyProvider keys, SmtpChannel mail, SmsChannel sms, IAuditLog audit,
        IBreachedPasswordChecker breach, OtpChallengeStore otp, SlidingWindowRateLimiter limiter, TimeProvider time, ILogger<PortalService> log)
    {
        _settings = settings; _ad = ad; _keys = keys; _codec = new EnrollmentCodec(keys); _mail = mail; _sms = sms; _audit = audit;
        _breach = breach; _otp = otp; _limiter = limiter; _time = time; _log = log;
    }

    private SsprSettings S => _settings.Current;
    private DateTimeOffset Now => _time.GetUtcNow();

    public ScopeSettings Scope => new() { AllowedOus = S.Directory.AllowedOus, ExcludedGroupSids = S.Directory.ExcludedGroupSids };

    public IReadOnlyList<VerificationMethod> AvailableMethods()
    {
        var l = new List<VerificationMethod>();
        if (S.Verification.TotpEnabled) l.Add(VerificationMethod.Totp);
        if (S.Verification.SmsEnabled && _sms.Configured) l.Add(VerificationMethod.Sms);
        if (S.Verification.EmailEnabled && _mail.Configured) l.Add(VerificationMethod.Email);
        return l;
    }

    private Task Audit(AuditEventId id, AuditOutcome outcome, string? user, string? actor, string? ip, string message) =>
        _audit.WriteAsync(new AuditEntry(id, outcome, user, actor, ip, message));

    private void Limit(string key, int limit, TimeSpan window, string? user, string? ip)
    {
        if (_limiter.TryAcquire(key, limit, window)) return;
        _ = Audit(AuditEventId.RateLimitTriggered, AuditOutcome.Blocked, user, null, ip, "Limite di tentativi raggiunto: " + key.Split(':')[0]);
        throw new PortalException(429, "Troppi tentativi. Riprovare piu' tardi.", retryAfter: _limiter.RetryAfter(key, limit, window));
    }

    public void LimitGlobal(string? ip)
    {
        Limit("global", S.RateLimits.GlobalPerMinute, TimeSpan.FromMinutes(1), null, ip);
        if (!string.IsNullOrEmpty(ip)) Limit("ip:" + ip, S.RateLimits.PerIpPerHour, TimeSpan.FromHours(1), null, ip);
    }

    // ------------------------------------------------------------------ utente della sessione

    public async Task<DirectoryUser> RequireManageableUser(SessionData s, CancellationToken ct)
    {
        if (!s.Authenticated) throw new PortalException(401, "Accesso richiesto.");
        var u = await _ad.FindUserBySidAsync(s.UserSid!, ct).ConfigureAwait(false) ?? throw new PortalException(401, "Account non trovato.");
        var p = AccountProtection.Evaluate(u, Scope);
        if (!p.Manageable) throw new PortalException(403, "Questo account non puo' usare il portale: rivolgersi all'help desk.");
        if (!u.Enabled) throw new PortalException(403, "L'account e' disabilitato.");
        return u;
    }

    public async Task<(Enrollment Enrollment, IReadOnlyList<string> Invalid)> LoadEnrollment(DirectoryUser u, CancellationToken ct)
    {
        var values = await _ad.ReadAsync(u, ct).ConfigureAwait(false);
        var e = _codec.Decode(values, u.Sid, out var invalid);
        if (invalid.Count > 0)
            await Audit(AuditEventId.EnrollmentInvalidData, AuditOutcome.Failure, u.SamAccountName, null, null, "Dati di registrazione non decifrabili: " + string.Join(", ", invalid)).ConfigureAwait(false);
        return (e, invalid);
    }

    private Task SaveEnrollment(DirectoryUser u, Enrollment e, CancellationToken ct) => _ad.WriteAsync(u, _codec.Encode(e, u.Sid), ct);

    public object EnrollmentStatus(Enrollment e)
    {
        var methods = new List<object>();
        if (e.Methods.Contains(VerificationMethod.Totp)) methods.Add(new { method = "totp", destinationMasked = "App di autenticazione", verifiedAt = e.State.TotpVerifiedAt });
        if (e.Methods.Contains(VerificationMethod.Sms)) methods.Add(new { method = "sms", destinationMasked = Masking.Phone(e.Mobile), verifiedAt = e.State.MobileVerifiedAt });
        if (e.Methods.Contains(VerificationMethod.Email)) methods.Add(new { method = "email", destinationMasked = Masking.Email(e.Email), verifiedAt = e.State.EmailVerifiedAt });
        return new
        {
            minimumMethods = S.Verification.MinimumEnrolledMethods,
            enrolled = e.IsEnrolled(S.Verification.MinimumEnrolledMethods),
            methods,
            availableMethods = AvailableMethods().Select(Name).ToArray(),
        };
    }

    public static string Name(VerificationMethod m) => m switch { VerificationMethod.Totp => "totp", VerificationMethod.Sms => "sms", _ => "email" };

    public static VerificationMethod ParseMethod(string? m) => m?.ToLowerInvariant() switch
    {
        "totp" => VerificationMethod.Totp,
        "sms" => VerificationMethod.Sms,
        "email" => VerificationMethod.Email,
        _ => throw new PortalException(400, "Metodo non valido."),
    };

    private IMessageChannel Channel(VerificationMethod m) => m == VerificationMethod.Sms ? _sms : _mail;

    private string Company => string.IsNullOrWhiteSpace(S.General.CompanyName) ? "il portale password" : S.General.CompanyName;

    /// <summary>Notifica su tutti i metodi verificati (escluso eventualmente il nuovo). Gli errori di invio non bloccano.</summary>
    private async Task Notify(Enrollment e, string subject, string text, CancellationToken ct)
    {
        var tasks = new List<Task>();
        if (e.Methods.Contains(VerificationMethod.Email) && _mail.Configured) tasks.Add(_mail.SendAsync(e.Email!, subject, text, ct));
        if (e.Methods.Contains(VerificationMethod.Sms) && _sms.Configured) tasks.Add(_sms.SendAsync(e.Mobile!, subject, subject + ": " + text, ct));
        foreach (var t in tasks)
        {
            try { await t.ConfigureAwait(false); }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "Notifica non inviata"); }
        }
    }

    // ------------------------------------------------------------------ registrazione

    public async Task<object> TotpStart(SessionData s, CancellationToken ct)
    {
        var u = await RequireManageableUser(s, ct).ConfigureAwait(false);
        if (!S.Verification.TotpEnabled) throw new PortalException(400, "Metodo non disponibile.");
        s.PendingTotp = Totp.NewSecret();
        var account = u.UserPrincipalName ?? u.SamAccountName;
        var uri = Totp.ProvisioningUri(s.PendingTotp, S.Verification.TotpIssuer, account);
        return new { qrCodeSvg = QrSvg(uri), manualKey = Base32.Encode(s.PendingTotp), issuer = S.Verification.TotpIssuer, account };
    }

    public static string QrSvg(string text)
    {
        using var gen = new QRCoder.QRCodeGenerator();
        using var data = gen.CreateQrCode(text, QRCoder.QRCodeGenerator.ECCLevel.M);
        return new QRCoder.SvgQRCode(data).GetGraphic(5);
    }

    public async Task<object> TotpConfirm(SessionData s, string? code, string? ip, CancellationToken ct)
    {
        var u = await RequireManageableUser(s, ct).ConfigureAwait(false);
        if (s.PendingTotp is null) throw new PortalException(400, "Avviare prima la configurazione dell'app.");
        Limit("verify:" + u.Sid, S.RateLimits.PerUserPerHour * 3, TimeSpan.FromHours(1), u.SamAccountName, ip);
        var step = Totp.Verify(s.PendingTotp, code, Now, 0, S.Verification.TotpWindowSteps);
        if (step is null) throw new PortalException(400, "Codice non valido: controllare l'ora del telefono e riprovare.");
        var (e, _) = await LoadEnrollment(u, ct).ConfigureAwait(false);
        var updated = e with { TotpSecret = s.PendingTotp, State = e.State with { TotpVerifiedAt = Now, LastTotpStep = step.Value, EnrolledAt = e.State.EnrolledAt ?? Now } };
        await SaveEnrollment(u, updated, ct).ConfigureAwait(false);
        s.PendingTotp = null;
        await Audit(AuditEventId.EnrollmentMethodAdded, AuditOutcome.Success, u.SamAccountName, null, ip, "Registrata l'app di autenticazione").ConfigureAwait(false);
        await Notify(e, "Metodo di verifica aggiunto", $"Sul tuo account e' stata registrata un'app di autenticazione per {Company}. Se non sei stato tu, contatta subito l'help desk.", ct).ConfigureAwait(false);
        return EnrollmentStatus(updated);
    }

    public async Task<object> DestinationStart(SessionData s, VerificationMethod m, string? destination, string? ip, CancellationToken ct)
    {
        var u = await RequireManageableUser(s, ct).ConfigureAwait(false);
        if (!AvailableMethods().Contains(m) || m == VerificationMethod.Totp) throw new PortalException(400, "Metodo non disponibile.");
        var normalized = m == VerificationMethod.Sms ? Normalization.Phone(destination, S.General.DefaultCountryCode) : Normalization.Email(destination);
        if (normalized is null) throw new PortalException(400, m == VerificationMethod.Sms ? "Numero di cellulare non valido." : "Indirizzo email non valido.");
        if (m == VerificationMethod.Email && u.UserPrincipalName is not null && normalized.Equals(u.UserPrincipalName, StringComparison.OrdinalIgnoreCase))
            throw new PortalException(400, "Indicare un indirizzo email personale, diverso da quello aziendale.");
        Limit("codes:" + u.Sid, S.RateLimits.CodesPerUserPerHour, TimeSpan.FromHours(1), u.SamAccountName, ip);
        var ch = _otp.Create(s.Id + "|" + u.Sid + "|enroll", Name(m), TimeSpan.FromMinutes(S.Verification.CodeLifetimeMinutes));
        s.PendingChallengeId = ch.Id; s.PendingMethod = m; s.PendingDestination = normalized;
        await SendCode(m, normalized, ch.Code, "registrazione", ct).ConfigureAwait(false);
        return new { challengeId = ch.Id, destinationMasked = m == VerificationMethod.Sms ? Masking.Phone(normalized) : Masking.Email(normalized), expiresAt = ch.ExpiresAt };
    }

    private async Task SendCode(VerificationMethod m, string destination, string code, string purpose, CancellationToken ct)
    {
        var minutes = S.Verification.CodeLifetimeMinutes;
        var text = $"Codice {Company} per {purpose}: {code}. Valido {minutes} minuti. Non comunicarlo a nessuno.";
        try { await Channel(m).SendAsync(destination, $"Codice di verifica - {Company}", text, ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "Invio codice non riuscito");
            await Audit(AuditEventId.Error, AuditOutcome.Failure, null, null, null, "Invio del codice non riuscito via " + Name(m)).ConfigureAwait(false);
            throw new PortalException(502, "Invio del codice non riuscito. Riprovare o usare un altro metodo.");
        }
    }

    public async Task<object> DestinationConfirm(SessionData s, VerificationMethod m, string? challengeId, string? code, string? ip, CancellationToken ct)
    {
        var u = await RequireManageableUser(s, ct).ConfigureAwait(false);
        if (s.PendingChallengeId is null || s.PendingChallengeId != challengeId || s.PendingMethod != m || s.PendingDestination is null)
            throw new PortalException(400, "Richiedere un nuovo codice.");
        var r = _otp.Verify(challengeId, s.Id + "|" + u.Sid + "|enroll", code);
        if (r != OtpVerifyResult.Ok)
        {
            if (r != OtpVerifyResult.Invalid) { s.PendingChallengeId = null; s.PendingDestination = null; }
            throw new PortalException(400, r == OtpVerifyResult.Invalid ? "Codice non valido." : "Codice scaduto o troppi tentativi: richiederne uno nuovo.");
        }
        var (e, _) = await LoadEnrollment(u, ct).ConfigureAwait(false);
        var dest = s.PendingDestination;
        var updated = m == VerificationMethod.Sms
            ? e with { Mobile = dest, State = e.State with { MobileVerifiedAt = Now, EnrolledAt = e.State.EnrolledAt ?? Now } }
            : e with { Email = dest, State = e.State with { EmailVerifiedAt = Now, EnrolledAt = e.State.EnrolledAt ?? Now } };
        await SaveEnrollment(u, updated, ct).ConfigureAwait(false);
        s.PendingChallengeId = null; s.PendingDestination = null; s.PendingMethod = null;
        var label = m == VerificationMethod.Sms ? "cellulare " + Masking.Phone(dest) : "email " + Masking.Email(dest);
        await Audit(AuditEventId.EnrollmentMethodAdded, AuditOutcome.Success, u.SamAccountName, null, ip, "Registrato " + label).ConfigureAwait(false);
        await Notify(e, "Metodo di verifica aggiunto", $"Sul tuo account e' stato registrato il {label} per {Company}. Se non sei stato tu, contatta subito l'help desk.", ct).ConfigureAwait(false);
        return EnrollmentStatus(updated);
    }

    public async Task<object> RemoveMethod(SessionData s, VerificationMethod m, string? ip, CancellationToken ct)
    {
        var u = await RequireManageableUser(s, ct).ConfigureAwait(false);
        var (e, _) = await LoadEnrollment(u, ct).ConfigureAwait(false);
        if (!e.Methods.Contains(m)) return EnrollmentStatus(e);
        if (e.Methods.Count - 1 < S.Verification.MinimumEnrolledMethods)
            throw new PortalException(409, $"Servono almeno {S.Verification.MinimumEnrolledMethods} metodi: aggiungerne un altro prima di rimuovere questo.");
        var updated = m switch
        {
            VerificationMethod.Totp => e with { TotpSecret = null, State = e.State with { TotpVerifiedAt = null } },
            VerificationMethod.Sms => e with { Mobile = null, State = e.State with { MobileVerifiedAt = null } },
            _ => e with { Email = null, State = e.State with { EmailVerifiedAt = null } },
        };
        await SaveEnrollment(u, updated, ct).ConfigureAwait(false);
        await Audit(AuditEventId.EnrollmentMethodRemoved, AuditOutcome.Success, u.SamAccountName, null, ip, "Rimosso il metodo " + Name(m)).ConfigureAwait(false);
        await Notify(e, "Metodo di verifica rimosso", $"Dal tuo account e' stato rimosso un metodo di verifica ({Name(m)}) di {Company}. Se non sei stato tu, contatta subito l'help desk.", ct).ConfigureAwait(false);
        return EnrollmentStatus(updated);
    }

    // ------------------------------------------------------------------ password

    public async Task<IReadOnlyList<string>> CheckPassword(DirectoryUser u, string? password, CancellationToken ct)
    {
        var rules = await _ad.GetPasswordRulesAsync(u, ct).ConfigureAwait(false);
        var errors = PasswordPolicy.Validate(password, rules, new PasswordContext(u.SamAccountName, u.DisplayName)).ToList();
        if (errors.Count == 0 && password is not null && S.Passwords.BreachedCheck != BreachedCheckMode.Off)
        {
            var r = await _breach.CheckAsync(password, ct).ConfigureAwait(false);
            if (r == BreachCheckResult.Breached) errors.Add("Questa password compare in elenchi di password rubate: sceglierne un'altra.");
            if (r == BreachCheckResult.Unknown && S.Passwords.BlockWhenBreachCheckUnavailable) errors.Add("Verifica delle password compromesse non disponibile: riprovare piu' tardi.");
        }
        return errors;
    }

    public async Task<object> CheckPasswordForSession(SessionData s, Flow? flow, string? password, CancellationToken ct)
    {
        DirectoryUser? u = null;
        if (flow is not null && !flow.Fake && flow.UserSid is not null) u = await _ad.FindUserBySidAsync(flow.UserSid, ct).ConfigureAwait(false);
        else if (s.Authenticated) u = await _ad.FindUserBySidAsync(s.UserSid!, ct).ConfigureAwait(false);
        if (u is null)
        {
            var errs = PasswordPolicy.Validate(password, new PasswordRules { MinLength = S.Passwords.MinLength, BannedWords = S.Passwords.BannedWords }, new PasswordContext(null, null));
            return new { valid = errs.Count == 0, errors = errs, minLength = S.Passwords.MinLength };
        }
        var e2 = await CheckPassword(u, password, ct).ConfigureAwait(false);
        var rules = await _ad.GetPasswordRulesAsync(u, ct).ConfigureAwait(false);
        return new { valid = e2.Count == 0, errors = e2, minLength = rules.MinLength };
    }

    /// <summary>Codice per confermare il cambio password su un metodo registrato.</summary>
    public async Task<object> ChangeChallenge(SessionData s, VerificationMethod m, string? ip, CancellationToken ct)
    {
        var u = await RequireManageableUser(s, ct).ConfigureAwait(false);
        var (e, _) = await LoadEnrollment(u, ct).ConfigureAwait(false);
        if (!e.Methods.Contains(m) || m == VerificationMethod.Totp) throw new PortalException(400, "Metodo non disponibile.");
        Limit("codes:" + u.Sid, S.RateLimits.CodesPerUserPerHour, TimeSpan.FromHours(1), u.SamAccountName, ip);
        var dest = m == VerificationMethod.Sms ? e.Mobile! : e.Email!;
        var ch = _otp.Create(s.Id + "|" + u.Sid + "|change", Name(m), TimeSpan.FromMinutes(S.Verification.CodeLifetimeMinutes));
        await SendCode(m, dest, ch.Code, "il cambio password", ct).ConfigureAwait(false);
        return new { challengeId = ch.Id, destinationMasked = m == VerificationMethod.Sms ? Masking.Phone(dest) : Masking.Email(dest), expiresAt = ch.ExpiresAt };
    }

    public async Task ChangePassword(SessionData s, string? current, string? newPassword, string? challengeId, string? code, string? ip, CancellationToken ct)
    {
        var u = await RequireManageableUser(s, ct).ConfigureAwait(false);
        Limit("change:" + u.Sid, S.RateLimits.PerUserPerHour, TimeSpan.FromHours(1), u.SamAccountName, ip);
        if (string.IsNullOrEmpty(current) || string.IsNullOrEmpty(newPassword)) throw new PortalException(400, "Compilare tutti i campi.");
        var (e, _) = await LoadEnrollment(u, ct).ConfigureAwait(false);
        if (S.Verification.ChangeRequiresVerification && e.Methods.Count > 0)
        {
            var ok = false;
            if (string.Equals(challengeId, "totp", StringComparison.OrdinalIgnoreCase) && e.Methods.Contains(VerificationMethod.Totp))
            {
                var step = Totp.Verify(e.TotpSecret!, code, Now, e.State.LastTotpStep, S.Verification.TotpWindowSteps);
                if (step is not null) { ok = true; e = e with { State = e.State with { LastTotpStep = step.Value } }; await SaveEnrollment(u, e, ct).ConfigureAwait(false); }
            }
            else if (!string.IsNullOrEmpty(challengeId))
            {
                ok = _otp.Verify(challengeId, s.Id + "|" + u.Sid + "|change", code) == OtpVerifyResult.Ok;
            }
            if (!ok) throw new PortalException(400, "Codice di verifica non valido.");
        }
        var errors = await CheckPassword(u, newPassword, ct).ConfigureAwait(false);
        if (errors.Count > 0) throw new PortalException(400, "La nuova password non rispetta i requisiti.", errors);
        var r = await _ad.ChangePasswordAsync(u, current, newPassword, ct).ConfigureAwait(false);
        if (r != PasswordOperationResult.Ok)
        {
            await Audit(AuditEventId.PasswordChangeFailed, AuditOutcome.Failure, u.SamAccountName, null, ip, "Cambio password non riuscito: " + r).ConfigureAwait(false);
            throw r switch
            {
                PasswordOperationResult.WrongCurrentPassword => new PortalException(400, "La password attuale non e' corretta."),
                PasswordOperationResult.PolicyViolation => new PortalException(400, "Active Directory ha rifiutato la password: potrebbe essere gia' stata usata di recente o essere stata cambiata da troppo poco tempo."),
                PasswordOperationResult.AccountLocked => new PortalException(400, "L'account e' bloccato: usare la funzione di sblocco."),
                _ => new PortalException(500, "Cambio password non riuscito. Riprovare o contattare l'help desk."),
            };
        }
        await Audit(AuditEventId.PasswordChanged, AuditOutcome.Success, u.SamAccountName, null, ip, "Password cambiata").ConfigureAwait(false);
        await Notify(e, "Password cambiata", $"La password del tuo account ({u.SamAccountName}) e' stata cambiata dal portale {Company}. Se non sei stato tu, contatta subito l'help desk.", ct).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ reset e sblocco

    public static async Task ConstantTime(DateTimeOffset start, TimeProvider time)
    {
        var elapsed = time.GetUtcNow() - start;
        var jitter = TimeSpan.FromMilliseconds(RandomNumberGenerator.GetInt32(0, 200));
        if (elapsed < MinResponse + jitter) await Task.Delay(MinResponse + jitter - elapsed).ConfigureAwait(false);
    }

    private static string NewId() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(18)).Replace('+', '-').Replace('/', '_');

    public object FlowDto(Flow f) => new
    {
        flowId = f.Id,
        purpose = f.Purpose,
        expiresAt = f.ExpiresAt,
        verificationsRequired = f.Required,
        verificationsDone = f.Fake ? Math.Min(f.Done, Math.Max(0, f.Required - 1)) : f.Done,
        methods = f.Methods.Select(m => new { methodId = m.Id, method = Name(m.Method), destinationMasked = m.Masked, used = m.Used }).ToArray(),
        currentChallenge = f.CurrentChallengeId is null ? null : new { challengeId = f.CurrentChallengeId, destinationMasked = f.Methods.First(m => m.Id == f.CurrentMethodId).Masked, expiresAt = f.CurrentChallengeExpires },
        readyToComplete = f.Ready,
    };

    public Flow GetFlow(SessionData s, string flowId)
    {
        if (!_flows.TryGetValue(flowId, out var f) || f.SessionId != s.Id || Now >= f.ExpiresAt)
            throw new PortalException(400, "Sessione scaduta: ricominciare.");
        return f;
    }

    public void PurgeFlows()
    {
        foreach (var kv in _flows) if (Now >= kv.Value.ExpiresAt) _flows.TryRemove(kv.Key, out _);
    }

    public async Task<object> StartFlow(SessionData s, string? userName, string? purpose, string? ip, CancellationToken ct)
    {
        var start = Now;
        try
        {
            if (purpose is not ("reset" or "unlock")) throw new PortalException(400, "Operazione non valida.");
            var name = Normalization.UserName(userName);
            if (name is null) throw new PortalException(400, "Inserire il nome utente.");
            Limit("start:" + name.ToLowerInvariant(), S.RateLimits.PerUserPerHour, TimeSpan.FromHours(1), name, ip);

            DirectoryUser? u = null;
            try { u = await _ad.FindUserAsync(name, ct).ConfigureAwait(false); }
            catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or InvalidOperationException) { _log.LogError(ex, "Ricerca utente non riuscita"); }

            Enrollment? e = null;
            var reason = "utente non trovato";
            if (u is not null)
            {
                var p = AccountProtection.Evaluate(u, Scope);
                if (!p.Manageable)
                {
                    reason = p.Reason!;
                    await Audit(AuditEventId.ProtectedAccountAttempt, AuditOutcome.Blocked, u.SamAccountName, null, ip, $"Richiesta di {purpose} su account non gestibile: {p.Reason}").ConfigureAwait(false);
                }
                else if (!u.Enabled) reason = "account disabilitato";
                else
                {
                    var (en, _) = await LoadEnrollment(u, ct).ConfigureAwait(false);
                    var required = purpose == "reset" ? S.Verification.ResetVerifications : S.Verification.UnlockVerifications;
                    if (en.Methods.Count >= Math.Max(1, required)) e = en;
                    else reason = "non registrato";
                }
            }

            var verifications = purpose == "reset" ? S.Verification.ResetVerifications : S.Verification.UnlockVerifications;
            Flow f;
            if (e is not null && u is not null)
            {
                var methods = new List<FlowMethod>();
                foreach (var m in e.Methods)
                {
                    methods.Add(new FlowMethod
                    {
                        Id = NewId(), Method = m,
                        Masked = m switch { VerificationMethod.Totp => "App di autenticazione", VerificationMethod.Sms => Masking.Phone(e.Mobile), _ => Masking.Email(e.Email) },
                        Destination = m switch { VerificationMethod.Sms => e.Mobile, VerificationMethod.Email => e.Email, _ => null },
                    });
                }
                f = new Flow { Id = NewId(), SessionId = s.Id, Purpose = purpose, ExpiresAt = Now.AddMinutes(S.Verification.FlowSessionMinutes), Required = Math.Max(1, verifications), Methods = methods, UserSid = u.Sid, UserName = u.SamAccountName };
                await Audit(AuditEventId.ResetRequested, AuditOutcome.Success, u.SamAccountName, null, ip, $"Richiesta di {purpose}").ConfigureAwait(false);
            }
            else
            {
                f = FakeFlow(s, name, purpose, verifications);
                await Audit(AuditEventId.ResetRequested, AuditOutcome.Blocked, name, null, ip, $"Richiesta di {purpose} non eseguibile ({reason})").ConfigureAwait(false);
            }
            _flows[f.Id] = f;
            return FlowDto(f);
        }
        finally { await ConstantTime(start, _time).ConfigureAwait(false); }
    }

    /// <summary>Flusso indistinguibile da uno reale (metodi mascherati stabili per lo stesso nome), che non puo' mai completarsi.</summary>
    private Flow FakeFlow(SessionData s, string name, string purpose, int verifications)
    {
        var h = HMACSHA256.HashData(_fakeKey, Encoding.UTF8.GetBytes(name.ToLowerInvariant()));
        var methods = new List<FlowMethod>();
        if ((h[0] & 1) == 0 && S.Verification.TotpEnabled) methods.Add(new FlowMethod { Id = NewId(), Method = VerificationMethod.Totp, Masked = "App di autenticazione" });
        if (S.Verification.SmsEnabled) methods.Add(new FlowMethod { Id = NewId(), Method = VerificationMethod.Sms, Masked = $"+{S.General.DefaultCountryCode} *** *** {h[1] % 10}{h[2] % 10}{h[3] % 10}" });
        if (S.Verification.EmailEnabled)
        {
            var domains = new[] { "g***.com", "h***.it", "l***.it", "o***.com", "y***.com", "i***.it" };
            methods.Add(new FlowMethod { Id = NewId(), Method = VerificationMethod.Email, Masked = $"{(char)('a' + h[4] % 26)}***@{domains[h[5] % domains.Length]}" });
        }
        return new Flow { Id = NewId(), SessionId = s.Id, Purpose = purpose, ExpiresAt = Now.AddMinutes(S.Verification.FlowSessionMinutes), Required = Math.Max(1, Math.Min(verifications, methods.Count)), Methods = methods, Fake = true, UserName = name };
    }

    public async Task<object> FlowChallenge(SessionData s, string flowId, string? methodId, string? ip, CancellationToken ct)
    {
        var start = Now;
        try
        {
            var f = GetFlow(s, flowId);
            var m = f.Methods.FirstOrDefault(x => x.Id == methodId && !x.Used) ?? throw new PortalException(400, "Metodo non valido.");
            Limit("codes:" + (f.UserSid ?? f.UserName), S.RateLimits.CodesPerUserPerHour, TimeSpan.FromHours(1), f.UserName, ip);
            f.CurrentMethodId = m.Id;
            if (m.Method == VerificationMethod.Totp)
            {
                f.CurrentChallengeId = "totp";
                f.CurrentChallengeExpires = f.ExpiresAt;
            }
            else
            {
                var ch = _otp.Create(s.Id + "|" + f.Id + "|" + m.Id, Name(m.Method), TimeSpan.FromMinutes(S.Verification.CodeLifetimeMinutes));
                f.CurrentChallengeId = ch.Id;
                f.CurrentChallengeExpires = ch.ExpiresAt;
                if (!f.Fake) await SendCode(m.Method, m.Destination!, ch.Code, f.Purpose == "reset" ? "il reset della password" : "lo sblocco dell'account", ct).ConfigureAwait(false);
            }
            return FlowDto(f);
        }
        finally { await ConstantTime(start, _time).ConfigureAwait(false); }
    }

    public async Task<object> FlowVerify(SessionData s, string flowId, string? code, string? ip, CancellationToken ct)
    {
        var start = Now;
        try
        {
            var f = GetFlow(s, flowId);
            var m = f.Methods.FirstOrDefault(x => x.Id == f.CurrentMethodId) ?? throw new PortalException(400, "Scegliere prima un metodo.");
            Limit("verify:" + (f.UserSid ?? f.UserName), S.RateLimits.PerUserPerHour * 3, TimeSpan.FromHours(1), f.UserName, ip);
            var ok = false;
            if (!f.Fake)
            {
                if (m.Method == VerificationMethod.Totp)
                {
                    var u = await _ad.FindUserBySidAsync(f.UserSid!, ct).ConfigureAwait(false) ?? throw new PortalException(400, "Sessione scaduta: ricominciare.");
                    var (e, _) = await LoadEnrollment(u, ct).ConfigureAwait(false);
                    if (e.TotpSecret is not null)
                    {
                        var step = Totp.Verify(e.TotpSecret, code, Now, e.State.LastTotpStep, S.Verification.TotpWindowSteps);
                        if (step is not null)
                        {
                            ok = true;
                            await SaveEnrollment(u, e with { State = e.State with { LastTotpStep = step.Value } }, ct).ConfigureAwait(false);
                        }
                    }
                }
                else ok = _otp.Verify(f.CurrentChallengeId!, s.Id + "|" + f.Id + "|" + m.Id, code) == OtpVerifyResult.Ok;
            }
            if (!ok)
            {
                f.Failures++;
                await Audit(AuditEventId.ResetVerificationFailed, AuditOutcome.Failure, f.UserName, null, ip, $"Verifica fallita ({Name(m.Method)}) durante {f.Purpose}").ConfigureAwait(false);
                if (f.Failures >= S.Verification.CodeMaxAttempts)
                {
                    _flows.TryRemove(f.Id, out _);
                    throw new PortalException(400, "Troppi codici errati: ricominciare.");
                }
                throw new PortalException(400, "Codice non valido.");
            }
            m.Used = true;
            f.CurrentMethodId = null;
            f.CurrentChallengeId = null;
            return FlowDto(f);
        }
        finally { await ConstantTime(start, _time).ConfigureAwait(false); }
    }

    public async Task FlowComplete(SessionData s, string flowId, string? newPassword, string? ip, CancellationToken ct)
    {
        var f = GetFlow(s, flowId);
        if (!f.Ready) throw new PortalException(403, "Verifica dell'identita' non completata.");
        var u = await _ad.FindUserBySidAsync(f.UserSid!, ct).ConfigureAwait(false) ?? throw new PortalException(400, "Sessione scaduta: ricominciare.");
        if (!AccountProtection.Evaluate(u, Scope).Manageable) throw new PortalException(403, "Operazione non consentita.");
        var (e, _) = await LoadEnrollment(u, ct).ConfigureAwait(false);
        if (f.Purpose == "reset")
        {
            var errors = await CheckPassword(u, newPassword, ct).ConfigureAwait(false);
            if (errors.Count > 0) throw new PortalException(400, "La nuova password non rispetta i requisiti.", errors);
            var r = await _ad.ResetPasswordAsync(u, newPassword!, false, ct).ConfigureAwait(false);
            if (r != PasswordOperationResult.Ok)
            {
                await Audit(AuditEventId.Error, AuditOutcome.Failure, u.SamAccountName, null, ip, "Reset non riuscito: " + r).ConfigureAwait(false);
                throw r == PasswordOperationResult.PolicyViolation
                    ? new PortalException(400, "Active Directory ha rifiutato la password (cronologia o requisiti): sceglierne un'altra.")
                    : new PortalException(500, "Reset non riuscito. Contattare l'help desk.");
            }
            await SaveEnrollment(u, e with { State = e.State with { LastResetAt = Now } }, ct).ConfigureAwait(false);
            _flows.TryRemove(f.Id, out _);
            await Audit(AuditEventId.PasswordReset, AuditOutcome.Success, u.SamAccountName, null, ip, $"Password reimpostata con {f.Done} verifiche").ConfigureAwait(false);
            await Notify(e, "Password reimpostata", $"La password del tuo account ({u.SamAccountName}) e' stata reimpostata dal portale {Company}. Se non sei stato tu, contatta subito l'help desk.", ct).ConfigureAwait(false);
        }
        else
        {
            var r = await _ad.UnlockAsync(u, ct).ConfigureAwait(false);
            if (r != PasswordOperationResult.Ok)
            {
                await Audit(AuditEventId.UnlockFailed, AuditOutcome.Failure, u.SamAccountName, null, ip, "Sblocco non riuscito: " + r).ConfigureAwait(false);
                throw new PortalException(500, "Sblocco non riuscito. Contattare l'help desk.");
            }
            _flows.TryRemove(f.Id, out _);
            await Audit(AuditEventId.AccountUnlocked, AuditOutcome.Success, u.SamAccountName, null, ip, "Account sbloccato dall'utente").ConfigureAwait(false);
            await Notify(e, "Account sbloccato", $"Il tuo account ({u.SamAccountName}) e' stato sbloccato dal portale {Company}. Se non sei stato tu, contatta subito l'help desk.", ct).ConfigureAwait(false);
        }
    }
}
