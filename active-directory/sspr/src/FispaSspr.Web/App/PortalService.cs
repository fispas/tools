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

/// <summary>Errore da mostrare all'utente (messaggio gia' tradotto). Code e' un identificativo stabile per l'interfaccia.</summary>
public sealed class PortalException : Exception
{
    public PortalException(int status, string message, IReadOnlyList<string>? errors = null, TimeSpan? retryAfter = null, string? code = null) : base(message)
    {
        Status = status;
        Errors = errors ?? Array.Empty<string>();
        RetryAfter = retryAfter;
        Code = code;
    }

    public int Status { get; }
    public IReadOnlyList<string> Errors { get; }
    public TimeSpan? RetryAfter { get; }
    public string? Code { get; }
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

/// <summary>Logica del portale: registrazione, conferma d'identita', cambio, reset e sblocco.</summary>
public sealed class PortalService
{
    private readonly SettingsStore _settings;
    private readonly AdDirectory _ad;
    private readonly EnrollmentCodec _codec;
    private readonly SmtpChannel _mail;
    private readonly SmsChannel _sms;
    private readonly IAuditLog _audit;
    private readonly IBreachedPasswordChecker _breach;
    private readonly OtpChallengeStore _otp;
    private readonly SlidingWindowRateLimiter _limiter;
    private readonly TimeProvider _time;
    private readonly ILogger<PortalService> _log;
    private readonly TextCatalog _t;
    private readonly ConcurrentDictionary<string, Flow> _flows = new(StringComparer.Ordinal);
    private readonly byte[] _fakeKey = RandomNumberGenerator.GetBytes(32);

    public PortalService(SettingsStore settings, AdDirectory ad, IMasterKeyProvider keys, SmtpChannel mail, SmsChannel sms, IAuditLog audit,
        IBreachedPasswordChecker breach, OtpChallengeStore otp, SlidingWindowRateLimiter limiter, TimeProvider time, ILogger<PortalService> log, TextCatalog texts)
    {
        _settings = settings; _ad = ad; _codec = new EnrollmentCodec(keys); _mail = mail; _sms = sms; _audit = audit;
        _breach = breach; _otp = otp; _limiter = limiter; _time = time; _log = log; _t = texts;
    }

    private SsprSettings S => _settings.Current;
    private FeatureSettings F => _settings.Current.Features;
    private DateTimeOffset Now => _time.GetUtcNow();
    public TextCatalog Texts => _t;

    private PortalException Err(int status, string key, params (string, object?)[] vars) => new(status, _t.Get(key, vars), code: key);

    public ScopeSettings Scope => new() { AllowedOus = S.Directory.AllowedOus, ExcludedGroupSids = S.Directory.ExcludedGroupSids };

    public IReadOnlyList<VerificationMethod> AvailableMethods()
    {
        var l = new List<VerificationMethod>();
        if (S.Verification.TotpEnabled) l.Add(VerificationMethod.Totp);
        if (S.Verification.SmsEnabled && _sms.Configured) l.Add(VerificationMethod.Sms);
        if (S.Verification.EmailEnabled && _mail.Configured) l.Add(VerificationMethod.Email);
        return l;
    }

    /// <summary>Metodi registrati che si possono ancora usare (metodo disattivato o canale non configurato = non usabile).</summary>
    private IReadOnlyList<VerificationMethod> Usable(Enrollment e) => e.Methods.Where(AvailableMethods().Contains).ToList();

    private Task Audit(AuditEventId id, AuditOutcome outcome, string? user, string? actor, string? ip, string message) =>
        _audit.WriteAsync(new AuditEntry(id, outcome, user, actor, ip, message));

    private void Limit(string key, int limit, TimeSpan window, string? user, string? ip)
    {
        if (_limiter.TryAcquire(key, Math.Max(1, limit), window)) return;
        _ = Audit(AuditEventId.RateLimitTriggered, AuditOutcome.Blocked, user, null, ip, "Limite di tentativi raggiunto: " + key.Split(':')[0]);
        throw new PortalException(429, _t.Get("err.rateLimit"), retryAfter: _limiter.RetryAfter(key, Math.Max(1, limit), window), code: "err.rateLimit");
    }

    public void LimitGlobal(string? ip)
    {
        Limit("global", S.RateLimits.GlobalPerMinute, TimeSpan.FromMinutes(1), null, ip);
        if (!string.IsNullOrEmpty(ip)) Limit("ip:" + ip, S.RateLimits.PerIpPerHour, TimeSpan.FromHours(1), null, ip);
    }

    public void LimitLogin(string? name, string? ip)
    {
        LimitGlobal(ip);
        if (!string.IsNullOrEmpty(name)) Limit("login:" + name.ToLowerInvariant(), S.RateLimits.PerUserPerHour, TimeSpan.FromHours(1), name, ip);
    }

    public void RequireFeature(bool enabled)
    {
        if (!enabled) throw Err(403, "err.featureDisabled");
    }

    public async Task ConstantTime(DateTimeOffset start)
    {
        var min = TimeSpan.FromMilliseconds(Math.Clamp(S.Sessions.MinResponseMilliseconds, 200, 5000));
        var jitter = TimeSpan.FromMilliseconds(RandomNumberGenerator.GetInt32(0, 250));
        var elapsed = _time.GetUtcNow() - start;
        if (elapsed < min + jitter) await Task.Delay(min + jitter - elapsed).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ utente della sessione

    public async Task<DirectoryUser> RequireManageableUser(SessionData s, CancellationToken ct)
    {
        if (!s.Authenticated) throw Err(401, "err.loginRequired");
        var u = await _ad.FindUserBySidAsync(s.UserSid!, ct).ConfigureAwait(false) ?? throw Err(401, "err.loginRequired");
        if (!AccountProtection.Evaluate(u, Scope).Manageable) throw Err(403, "err.notManageable");
        if (!u.Enabled) throw Err(403, "err.disabled");
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

    public object EnrollmentStatus(Enrollment e, SessionData? s = null)
    {
        var methods = new List<object>();
        if (e.Methods.Contains(VerificationMethod.Totp)) methods.Add(new { method = "totp", destinationMasked = _t.Get("method.totp"), verifiedAt = e.State.TotpVerifiedAt });
        if (e.Methods.Contains(VerificationMethod.Sms)) methods.Add(new { method = "sms", destinationMasked = Masking.Phone(e.Mobile), verifiedAt = e.State.MobileVerifiedAt });
        if (e.Methods.Contains(VerificationMethod.Email)) methods.Add(new { method = "email", destinationMasked = Masking.Email(e.Email), verifiedAt = e.State.EmailVerifiedAt });
        return new
        {
            minimumMethods = S.Verification.MinimumEnrolledMethods,
            enrolled = e.IsEnrolled(S.Verification.MinimumEnrolledMethods),
            methods,
            availableMethods = F.EnrollmentEnabled ? AvailableMethods().Select(Name).ToArray() : Array.Empty<string>(),
            canRemove = F.EnrollmentEnabled && F.AllowMethodRemoval,
            stepUpRequired = s is not null && StepUpNeeded(s, e),
            firstEnrollmentBlocked = s is not null && e.Methods.Count == 0 && F.FirstEnrollmentRequiresWindowsLogin && !s.IsWindows,
            changeEnabled = F.ChangeEnabled,
        };
    }

    public static string Name(VerificationMethod m) => m switch { VerificationMethod.Totp => "totp", VerificationMethod.Sms => "sms", _ => "email" };

    public VerificationMethod ParseMethod(string? m) => m?.ToLowerInvariant() switch
    {
        "totp" => VerificationMethod.Totp,
        "sms" => VerificationMethod.Sms,
        "email" => VerificationMethod.Email,
        _ => throw Err(400, "err.methodInvalid"),
    };

    private IMessageChannel Channel(VerificationMethod m) => m == VerificationMethod.Sms ? _sms : _mail;

    private string MethodLabel(VerificationMethod m, Enrollment? e = null, string? dest = null) => m switch
    {
        VerificationMethod.Totp => _t.Get("method.totp"),
        VerificationMethod.Sms => _t.Get("method.sms") + " " + Masking.Phone(dest ?? e?.Mobile),
        _ => _t.Get("method.email") + " " + Masking.Email(dest ?? e?.Email),
    };

    private bool NotificationEnabled(string name) => name switch
    {
        "methodAdded" => S.Notifications.MethodAdded,
        "methodRemoved" => S.Notifications.MethodRemoved,
        "passwordChanged" => S.Notifications.PasswordChanged,
        "passwordReset" => S.Notifications.PasswordReset,
        "accountUnlocked" => S.Notifications.AccountUnlocked,
        "adminUnlock" => S.Notifications.AdminUnlock,
        "adminClearEnrollment" => S.Notifications.AdminClearEnrollment,
        "adminTemporaryReset" => S.Notifications.AdminTemporaryReset,
        _ => true,
    };

    /// <summary>Notifica all'utente sui canali configurati. Gli errori di invio non bloccano l'operazione.</summary>
    public async Task Notify(DirectoryUser u, Enrollment e, string name, CancellationToken ct, params (string, object?)[] extra)
    {
        if (!NotificationEnabled(name)) return;
        var vars = new List<(string, object?)>
        {
            ("user", u.SamAccountName), ("displayName", u.DisplayName ?? u.SamAccountName),
            ("time", Now.ToLocalTime().ToString("dd/MM/yyyy HH:mm", System.Globalization.CultureInfo.InvariantCulture)),
        };
        vars.AddRange(extra);
        var (subject, body, sms) = _t.Notification(name, vars.ToArray());
        var n = S.Notifications;
        var targets = new List<(IMessageChannel Ch, string To, string Text)>();
        if (n.ViaPersonalEmail && e.Methods.Contains(VerificationMethod.Email) && _mail.Configured) targets.Add((_mail, e.Email!, body));
        if (n.ViaSms && e.Methods.Contains(VerificationMethod.Sms) && _sms.Configured) targets.Add((_sms, e.Mobile!, sms));
        if (n.ViaCorporateEmail && _mail.Configured)
        {
            try
            {
                var corp = await _ad.GetMailAsync(u, ct).ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(corp) && !targets.Any(t => string.Equals(t.To, corp, StringComparison.OrdinalIgnoreCase))) targets.Add((_mail, corp, body));
            }
            catch (System.Runtime.InteropServices.COMException ex) { _log.LogWarning(ex, "Email aziendale non leggibile"); }
        }
        foreach (var (ch, to, text) in targets)
        {
            try { await ch.SendAsync(to, subject, text, ct).ConfigureAwait(false); }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "Notifica {Name} non inviata", name); }
        }
    }

    private async Task SendCode(VerificationMethod m, string destination, string code, string purpose, CancellationToken ct)
    {
        var (subject, body, sms) = _t.Notification("code", ("code", code), ("minutes", S.Verification.CodeLifetimeMinutes), ("purpose", _t.Get("notify.purpose." + purpose)));
        try { await Channel(m).SendAsync(destination, subject, m == VerificationMethod.Sms ? sms : body, ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "Invio codice non riuscito");
            await Audit(AuditEventId.Error, AuditOutcome.Failure, null, null, null, "Invio del codice non riuscito via " + Name(m)).ConfigureAwait(false);
            throw Err(502, "err.sendFailed");
        }
    }

    /// <summary>Invio in background: la risposta non dipende dai tempi del gateway (reset/sblocco, anti-enumerazione).</summary>
    private void SendCodeInBackground(VerificationMethod m, string destination, string code, string purpose, string? user)
    {
        _ = Task.Run(async () =>
        {
            try { await SendCode(m, destination, code, purpose, CancellationToken.None).ConfigureAwait(false); }
            catch (PortalException) { _log.LogWarning("Codice di {Purpose} non recapitato a {User}", purpose, user); }
        });
    }

    // ------------------------------------------------------------------ conferma dell'identita' (step-up)

    private bool StepUpNeeded(SessionData s, Enrollment e) =>
        Usable(e).Count > 0 && !(s.StepUpUntil is { } until && until > Now);

    private void RequireStepUp(SessionData s, Enrollment e)
    {
        if (StepUpNeeded(s, e)) throw Err(403, "err.stepUpRequired");
    }

    public async Task<object> StepUpChallenge(SessionData s, VerificationMethod m, string? ip, CancellationToken ct)
    {
        var u = await RequireManageableUser(s, ct).ConfigureAwait(false);
        var (e, _) = await LoadEnrollment(u, ct).ConfigureAwait(false);
        if (!Usable(e).Contains(m)) throw Err(400, "err.methodUnavailable");
        if (m == VerificationMethod.Totp)
        {
            s.StepUpChallengeId = "totp";
            return new { challengeId = "totp", method = "totp", destinationMasked = _t.Get("method.totp") };
        }
        Limit("codes:" + u.Sid, S.RateLimits.CodesPerUserPerHour, TimeSpan.FromHours(1), u.SamAccountName, ip);
        var dest = m == VerificationMethod.Sms ? e.Mobile! : e.Email!;
        var ch = _otp.Create(s.Id + "|" + u.Sid + "|stepup", Name(m), TimeSpan.FromMinutes(S.Verification.CodeLifetimeMinutes));
        s.StepUpChallengeId = ch.Id;
        await SendCode(m, dest, ch.Code, "stepup", ct).ConfigureAwait(false);
        return new { challengeId = ch.Id, method = Name(m), destinationMasked = m == VerificationMethod.Sms ? Masking.Phone(dest) : Masking.Email(dest), expiresAt = ch.ExpiresAt };
    }

    public async Task<object> StepUpVerify(SessionData s, string? challengeId, string? code, string? ip, CancellationToken ct)
    {
        var u = await RequireManageableUser(s, ct).ConfigureAwait(false);
        Limit("verify:" + u.Sid, S.RateLimits.PerUserPerHour * 3, TimeSpan.FromHours(1), u.SamAccountName, ip);
        if (string.IsNullOrEmpty(challengeId) || s.StepUpChallengeId != challengeId) throw Err(400, "err.codeRequestNew");
        var (e, _) = await LoadEnrollment(u, ct).ConfigureAwait(false);
        var ok = false;
        if (challengeId == "totp")
        {
            if (Usable(e).Contains(VerificationMethod.Totp))
            {
                var step = Totp.Verify(e.TotpSecret!, code, Now, e.State.LastTotpStep, S.Verification.TotpWindowSteps);
                if (step is not null) { ok = true; await SaveEnrollment(u, e with { State = e.State with { LastTotpStep = step.Value } }, ct).ConfigureAwait(false); }
            }
        }
        else
        {
            var r = _otp.Verify(challengeId, s.Id + "|" + u.Sid + "|stepup", code);
            ok = r == OtpVerifyResult.Ok;
            if (r is OtpVerifyResult.Expired or OtpVerifyResult.TooManyAttempts or OtpVerifyResult.NotFound) s.StepUpChallengeId = null;
        }
        if (!ok)
        {
            await Audit(AuditEventId.StepUpFailed, AuditOutcome.Failure, u.SamAccountName, null, ip, "Conferma dell'identita' non riuscita").ConfigureAwait(false);
            throw Err(400, "err.codeInvalid");
        }
        s.StepUpChallengeId = null;
        s.StepUpUntil = Now.AddMinutes(Math.Clamp(S.Sessions.StepUpMinutes, 1, 30));
        await Audit(AuditEventId.StepUpVerified, AuditOutcome.Success, u.SamAccountName, null, ip, "Identita' confermata").ConfigureAwait(false);
        return EnrollmentStatus(e, s);
    }

    // ------------------------------------------------------------------ registrazione

    private async Task<(DirectoryUser U, Enrollment E)> BeginEnrollmentChange(SessionData s, CancellationToken ct)
    {
        RequireFeature(F.EnrollmentEnabled);
        var u = await RequireManageableUser(s, ct).ConfigureAwait(false);
        var (e, _) = await LoadEnrollment(u, ct).ConfigureAwait(false);
        if (e.Methods.Count == 0 && F.FirstEnrollmentRequiresWindowsLogin && !s.IsWindows) throw Err(403, "err.windowsRequired");
        if (F.StepUpForEnrollmentChanges) RequireStepUp(s, e);
        return (u, e);
    }

    public async Task<object> TotpStart(SessionData s, CancellationToken ct)
    {
        var (u, _) = await BeginEnrollmentChange(s, ct).ConfigureAwait(false);
        if (!S.Verification.TotpEnabled) throw Err(400, "err.methodUnavailable");
        s.PendingTotp = Totp.NewSecret();
        var account = u.UserPrincipalName ?? u.SamAccountName;
        var issuer = string.IsNullOrWhiteSpace(S.Verification.TotpIssuer) ? _t.Company : S.Verification.TotpIssuer;
        var uri = Totp.ProvisioningUri(s.PendingTotp, issuer, account);
        return new { qrCodeSvg = QrSvg(uri), manualKey = Base32.Encode(s.PendingTotp), issuer, account };
    }

    public static string QrSvg(string text)
    {
        using var gen = new QRCoder.QRCodeGenerator();
        using var data = gen.CreateQrCode(text, QRCoder.QRCodeGenerator.ECCLevel.M);
        return new QRCoder.SvgQRCode(data).GetGraphic(5);
    }

    public async Task<object> TotpConfirm(SessionData s, string? code, string? ip, CancellationToken ct)
    {
        var (u, e) = await BeginEnrollmentChange(s, ct).ConfigureAwait(false);
        if (s.PendingTotp is null) throw Err(400, "err.totpStartFirst");
        Limit("verify:" + u.Sid, S.RateLimits.PerUserPerHour * 3, TimeSpan.FromHours(1), u.SamAccountName, ip);
        var step = Totp.Verify(s.PendingTotp, code, Now, 0, S.Verification.TotpWindowSteps) ?? throw Err(400, "err.totpInvalid");
        var updated = e with { TotpSecret = s.PendingTotp, State = e.State with { TotpVerifiedAt = Now, LastTotpStep = step, EnrolledAt = e.State.EnrolledAt ?? Now } };
        await SaveEnrollment(u, updated, ct).ConfigureAwait(false);
        s.PendingTotp = null;
        await Audit(AuditEventId.EnrollmentMethodAdded, AuditOutcome.Success, u.SamAccountName, null, ip, "Registrata l'app di autenticazione").ConfigureAwait(false);
        await Notify(u, e, "methodAdded", ct, ("method", _t.Get("method.totp"))).ConfigureAwait(false);
        return EnrollmentStatus(updated, s);
    }

    public async Task<object> DestinationStart(SessionData s, VerificationMethod m, string? destination, string? ip, CancellationToken ct)
    {
        var (u, _) = await BeginEnrollmentChange(s, ct).ConfigureAwait(false);
        if (!AvailableMethods().Contains(m) || m == VerificationMethod.Totp) throw Err(400, "err.methodUnavailable");
        var normalized = m == VerificationMethod.Sms ? Normalization.Phone(destination, S.General.DefaultCountryCode) : Normalization.Email(destination);
        if (normalized is null) throw Err(400, m == VerificationMethod.Sms ? "err.phoneInvalid" : "err.emailInvalid");
        if (m == VerificationMethod.Email)
        {
            var corp = await _ad.GetMailAsync(u, ct).ConfigureAwait(false);
            if ((u.UserPrincipalName is not null && normalized.Equals(u.UserPrincipalName, StringComparison.OrdinalIgnoreCase)) ||
                (corp is not null && normalized.Equals(corp, StringComparison.OrdinalIgnoreCase)))
                throw Err(400, "err.emailCorporate");
        }
        Limit("codes:" + u.Sid, S.RateLimits.CodesPerUserPerHour, TimeSpan.FromHours(1), u.SamAccountName, ip);
        var ch = _otp.Create(s.Id + "|" + u.Sid + "|enroll|" + Name(m), Name(m), TimeSpan.FromMinutes(S.Verification.CodeLifetimeMinutes));
        s.PendingChallengeId = ch.Id; s.PendingMethod = m; s.PendingDestination = normalized;
        await SendCode(m, normalized, ch.Code, "enroll", ct).ConfigureAwait(false);
        return new { challengeId = ch.Id, destinationMasked = m == VerificationMethod.Sms ? Masking.Phone(normalized) : Masking.Email(normalized), expiresAt = ch.ExpiresAt };
    }

    public async Task<object> DestinationConfirm(SessionData s, VerificationMethod m, string? challengeId, string? code, string? ip, CancellationToken ct)
    {
        var (u, e) = await BeginEnrollmentChange(s, ct).ConfigureAwait(false);
        if (s.PendingChallengeId is null || s.PendingChallengeId != challengeId || s.PendingMethod != m || s.PendingDestination is null)
            throw Err(400, "err.codeRequestNew");
        Limit("verify:" + u.Sid, S.RateLimits.PerUserPerHour * 3, TimeSpan.FromHours(1), u.SamAccountName, ip);
        var r = _otp.Verify(challengeId, s.Id + "|" + u.Sid + "|enroll|" + Name(m), code);
        if (r != OtpVerifyResult.Ok)
        {
            if (r != OtpVerifyResult.Invalid) { s.PendingChallengeId = null; s.PendingDestination = null; }
            throw Err(400, r == OtpVerifyResult.Invalid ? "err.codeInvalid" : "err.codeExpired");
        }
        var dest = s.PendingDestination;
        var updated = m == VerificationMethod.Sms
            ? e with { Mobile = dest, State = e.State with { MobileVerifiedAt = Now, EnrolledAt = e.State.EnrolledAt ?? Now } }
            : e with { Email = dest, State = e.State with { EmailVerifiedAt = Now, EnrolledAt = e.State.EnrolledAt ?? Now } };
        await SaveEnrollment(u, updated, ct).ConfigureAwait(false);
        s.PendingChallengeId = null; s.PendingDestination = null; s.PendingMethod = null;
        var label = MethodLabel(m, dest: dest);
        await Audit(AuditEventId.EnrollmentMethodAdded, AuditOutcome.Success, u.SamAccountName, null, ip, "Registrato " + label).ConfigureAwait(false);
        // notifica sui metodi gia' presenti (il vecchio recapito, se sostituito, viene avvisato)
        await Notify(u, e, "methodAdded", ct, ("method", label)).ConfigureAwait(false);
        return EnrollmentStatus(updated, s);
    }

    public async Task<object> RemoveMethod(SessionData s, VerificationMethod m, string? ip, CancellationToken ct)
    {
        var (u, e) = await BeginEnrollmentChange(s, ct).ConfigureAwait(false);
        if (!F.AllowMethodRemoval) throw Err(403, "err.removalDisabled");
        if (!e.Methods.Contains(m)) return EnrollmentStatus(e, s);
        if (e.Methods.Count - 1 < S.Verification.MinimumEnrolledMethods) throw Err(409, "err.minMethods", ("min", S.Verification.MinimumEnrolledMethods));
        var updated = m switch
        {
            VerificationMethod.Totp => e with { TotpSecret = null, State = e.State with { TotpVerifiedAt = null } },
            VerificationMethod.Sms => e with { Mobile = null, State = e.State with { MobileVerifiedAt = null } },
            _ => e with { Email = null, State = e.State with { EmailVerifiedAt = null } },
        };
        await SaveEnrollment(u, updated, ct).ConfigureAwait(false);
        await Audit(AuditEventId.EnrollmentMethodRemoved, AuditOutcome.Success, u.SamAccountName, null, ip, "Rimosso il metodo " + Name(m)).ConfigureAwait(false);
        await Notify(u, e, "methodRemoved", ct, ("method", MethodLabel(m, e))).ConfigureAwait(false);
        return EnrollmentStatus(updated, s);
    }

    // ------------------------------------------------------------------ password

    public async Task<IReadOnlyList<string>> CheckPassword(DirectoryUser u, string? password, CancellationToken ct)
    {
        var rules = await _ad.GetPasswordRulesAsync(u, ct).ConfigureAwait(false);
        var errors = PasswordPolicy.Validate(password, rules, new PasswordContext(u.SamAccountName, u.DisplayName)).ToList();
        if (errors.Count == 0 && password is not null && S.Passwords.BreachedCheck != BreachedCheckMode.Off)
        {
            var r = await _breach.CheckAsync(password, ct).ConfigureAwait(false);
            if (r == BreachCheckResult.Breached) errors.Add(_t.Get("err.pwdBreached"));
            if (r == BreachCheckResult.Unknown && S.Passwords.BlockWhenBreachCheckUnavailable) errors.Add(_t.Get("err.pwdBreachUnavailable"));
        }
        return errors;
    }

    /// <summary>
    /// Verifica dal vivo. Le regole del singolo utente (PSO) si usano solo per una sessione autenticata o per un flusso gia' verificato:
    /// prima della verifica la risposta e' identica per tutti (niente indizi sull'esistenza dell'account).
    /// </summary>
    public async Task<object> CheckPasswordForSession(SessionData s, string? flowId, string? password, string? ip, CancellationToken ct)
    {
        Limit("check:" + s.Id, 120, TimeSpan.FromHours(1), null, ip);
        if (password is { Length: > 256 }) password = password[..256];
        DirectoryUser? u = null;
        if (!string.IsNullOrEmpty(flowId))
        {
            var f = GetFlow(s, flowId);
            if (f.Ready) u = await _ad.FindUserBySidAsync(f.UserSid!, ct).ConfigureAwait(false);
        }
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

    public async Task ChangePassword(SessionData s, string? current, string? newPassword, string? ip, CancellationToken ct)
    {
        RequireFeature(F.ChangeEnabled);
        var u = await RequireManageableUser(s, ct).ConfigureAwait(false);
        Limit("change:" + u.Sid, S.RateLimits.PerUserPerHour, TimeSpan.FromHours(1), u.SamAccountName, ip);
        if (string.IsNullOrEmpty(current) || string.IsNullOrEmpty(newPassword)) throw Err(400, "err.fieldsRequired");
        var (e, _) = await LoadEnrollment(u, ct).ConfigureAwait(false);
        if (S.Verification.ChangeRequiresVerification) RequireStepUp(s, e);
        var errors = await CheckPassword(u, newPassword, ct).ConfigureAwait(false);
        if (errors.Count > 0) throw new PortalException(400, _t.Get("err.pwdRequirements"), errors, code: "err.pwdRequirements");
        var r = await _ad.ChangePasswordAsync(u, current, newPassword, ct).ConfigureAwait(false);
        if (r != PasswordOperationResult.Ok)
        {
            await Audit(AuditEventId.PasswordChangeFailed, AuditOutcome.Failure, u.SamAccountName, null, ip, "Cambio password non riuscito: " + r).ConfigureAwait(false);
            throw r switch
            {
                PasswordOperationResult.WrongCurrentPassword => Err(400, "err.wrongCurrent"),
                PasswordOperationResult.PolicyViolation => Err(400, "err.adRejectedChange"),
                PasswordOperationResult.AccountLocked => Err(400, "err.accountLocked"),
                _ => Err(500, "err.changeFailed"),
            };
        }
        s.StepUpUntil = null;
        await Audit(AuditEventId.PasswordChanged, AuditOutcome.Success, u.SamAccountName, null, ip, "Password cambiata").ConfigureAwait(false);
        await Notify(u, e, "passwordChanged", ct).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ reset e sblocco

    private static string NewId() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(18)).Replace('+', '-').Replace('/', '_');

    public object FlowDto(Flow f) => new
    {
        flowId = f.Id,
        purpose = f.Purpose,
        expiresAt = f.ExpiresAt,
        verificationsRequired = f.Required,
        verificationsDone = f.Fake ? Math.Min(f.Done, Math.Max(0, f.Required - 1)) : f.Done,
        methods = f.Methods.Select(m => new { methodId = m.Id, method = Name(m.Method), destinationMasked = m.Masked, used = m.Used }).ToArray(),
        currentChallenge = f.CurrentChallengeId is null ? null : new
        {
            challengeId = f.CurrentChallengeId,
            method = Name(f.Methods.First(m => m.Id == f.CurrentMethodId).Method),
            destinationMasked = f.Methods.First(m => m.Id == f.CurrentMethodId).Masked,
            expiresAt = f.CurrentChallengeExpires,
        },
        readyToComplete = f.Ready,
    };

    public Flow GetFlow(SessionData s, string flowId)
    {
        if (flowId.Length > 64 || !_flows.TryGetValue(flowId, out var f) || f.SessionId != s.Id || Now >= f.ExpiresAt)
            throw Err(400, "err.flowExpired");
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
            if (purpose is not ("reset" or "unlock")) throw Err(400, "err.operationInvalid");
            RequireFeature(purpose == "reset" ? F.ResetEnabled : F.UnlockEnabled);
            LimitGlobal(ip);
            var name = Normalization.UserName(userName);
            if (name is null) throw Err(400, "err.userRequired");
            Limit("start:" + name.ToLowerInvariant(), S.RateLimits.PerUserPerHour, TimeSpan.FromHours(1), name, ip);
            // un solo flusso attivo per sessione
            foreach (var kv in _flows) if (kv.Value.SessionId == s.Id) _flows.TryRemove(kv.Key, out _);

            DirectoryUser? u = null;
            try { u = await _ad.FindUserAsync(name, ct).ConfigureAwait(false); }
            catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or InvalidOperationException) { _log.LogError(ex, "Ricerca utente non riuscita"); }

            Enrollment? e = null;
            var reason = "utente non trovato";
            var verifications = Math.Max(1, purpose == "reset" ? S.Verification.ResetVerifications : S.Verification.UnlockVerifications);
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
                    if (Usable(en).Count >= verifications) e = en;
                    else reason = "metodi registrati insufficienti";
                }
            }

            Flow f;
            if (e is not null && u is not null)
            {
                var methods = Usable(e).Select(m => new FlowMethod
                {
                    Id = NewId(), Method = m,
                    Masked = m switch { VerificationMethod.Totp => _t.Get("method.totp"), VerificationMethod.Sms => Masking.Phone(e.Mobile), _ => Masking.Email(e.Email) },
                    Destination = m switch { VerificationMethod.Sms => e.Mobile, VerificationMethod.Email => e.Email, _ => null },
                }).ToList();
                f = new Flow { Id = NewId(), SessionId = s.Id, Purpose = purpose, ExpiresAt = Now.AddMinutes(S.Verification.FlowSessionMinutes), Required = verifications, Methods = methods, UserSid = u.Sid, UserName = u.SamAccountName };
                await Audit(AuditEventId.ResetRequested, AuditOutcome.Success, u.SamAccountName, null, ip, $"Richiesta di {purpose}").ConfigureAwait(false);
            }
            else
            {
                f = FakeFlow(s, name, purpose, verifications);
                await Audit(AuditEventId.ResetBlocked, AuditOutcome.Blocked, name, null, ip, $"Richiesta di {purpose} non eseguibile ({reason})").ConfigureAwait(false);
            }
            _flows[f.Id] = f;
            return FlowDto(f);
        }
        finally { await ConstantTime(start).ConfigureAwait(false); }
    }

    /// <summary>Flusso indistinguibile da uno reale (metodi mascherati stabili per lo stesso nome), che non puo' mai completarsi.</summary>
    private Flow FakeFlow(SessionData s, string name, string purpose, int verifications)
    {
        var h = HMACSHA256.HashData(_fakeKey, Encoding.UTF8.GetBytes(name.ToLowerInvariant()));
        var available = AvailableMethods();
        var methods = new List<FlowMethod>();
        if (available.Contains(VerificationMethod.Totp) && ((h[0] & 1) == 0 || available.Count <= verifications)) methods.Add(new FlowMethod { Id = NewId(), Method = VerificationMethod.Totp, Masked = _t.Get("method.totp") });
        if (available.Contains(VerificationMethod.Sms)) methods.Add(new FlowMethod { Id = NewId(), Method = VerificationMethod.Sms, Masked = $"+{S.General.DefaultCountryCode} *** *** {h[1] % 10}{h[2] % 10}{h[3] % 10}" });
        if (available.Contains(VerificationMethod.Email))
        {
            var domains = new[] { "g***.com", "h***.it", "l***.it", "o***.com", "y***.com", "i***.it" };
            methods.Add(new FlowMethod { Id = NewId(), Method = VerificationMethod.Email, Masked = $"{(char)('a' + h[4] % 26)}***@{domains[h[5] % domains.Length]}" });
        }
        return new Flow { Id = NewId(), SessionId = s.Id, Purpose = purpose, ExpiresAt = Now.AddMinutes(S.Verification.FlowSessionMinutes), Required = verifications, Methods = methods, Fake = true, UserName = name };
    }

    public async Task<object> FlowChallenge(SessionData s, string flowId, string? methodId, string? ip, CancellationToken ct)
    {
        var start = Now;
        try
        {
            var f = GetFlow(s, flowId);
            var m = f.Methods.FirstOrDefault(x => x.Id == methodId && !x.Used) ?? throw Err(400, "err.methodInvalid");
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
                if (!f.Fake)
                {
                    if (F.BackgroundCodeDelivery) SendCodeInBackground(m.Method, m.Destination!, ch.Code, f.Purpose, f.UserName);
                    else await SendCode(m.Method, m.Destination!, ch.Code, f.Purpose, ct).ConfigureAwait(false);
                }
            }
            return FlowDto(f);
        }
        finally { await ConstantTime(start).ConfigureAwait(false); }
    }

    public async Task<object> FlowVerify(SessionData s, string flowId, string? code, string? ip, CancellationToken ct)
    {
        var start = Now;
        try
        {
            var f = GetFlow(s, flowId);
            var m = f.Methods.FirstOrDefault(x => x.Id == f.CurrentMethodId) ?? throw Err(400, "err.chooseMethod");
            Limit("verify:" + (f.UserSid ?? f.UserName), S.RateLimits.PerUserPerHour * 3, TimeSpan.FromHours(1), f.UserName, ip);
            var ok = false;
            if (!f.Fake)
            {
                if (m.Method == VerificationMethod.Totp)
                {
                    var u = await _ad.FindUserBySidAsync(f.UserSid!, ct).ConfigureAwait(false) ?? throw Err(400, "err.flowExpired");
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
                    throw Err(400, "err.tooManyCodes");
                }
                throw Err(400, "err.codeInvalid");
            }
            m.Used = true;
            f.CurrentMethodId = null;
            f.CurrentChallengeId = null;
            return FlowDto(f);
        }
        finally { await ConstantTime(start).ConfigureAwait(false); }
    }

    public async Task FlowComplete(SessionData s, string flowId, string? newPassword, string? ip, CancellationToken ct)
    {
        var f = GetFlow(s, flowId);
        if (!f.Ready) throw Err(403, "err.notVerified");
        RequireFeature(f.Purpose == "reset" ? F.ResetEnabled : F.UnlockEnabled);
        var u = await _ad.FindUserBySidAsync(f.UserSid!, ct).ConfigureAwait(false) ?? throw Err(400, "err.flowExpired");
        if (!AccountProtection.Evaluate(u, Scope).Manageable || !u.Enabled) throw Err(403, "err.notAllowed");
        var (e, _) = await LoadEnrollment(u, ct).ConfigureAwait(false);
        if (f.Purpose == "reset")
        {
            Limit("complete:" + u.Sid, S.RateLimits.PerUserPerHour, TimeSpan.FromHours(1), u.SamAccountName, ip);
            var errors = await CheckPassword(u, newPassword, ct).ConfigureAwait(false);
            if (errors.Count > 0) throw new PortalException(400, _t.Get("err.pwdRequirements"), errors, code: "err.pwdRequirements");
            var target = F.ResetUnlocksAccount ? u : u with { LockedOut = false };
            var r = await _ad.ResetPasswordAsync(target, newPassword!, F.ResetForcesChangeAtNextLogon, ct).ConfigureAwait(false);
            if (r != PasswordOperationResult.Ok)
            {
                await Audit(AuditEventId.Error, AuditOutcome.Failure, u.SamAccountName, null, ip, "Reset non riuscito: " + r).ConfigureAwait(false);
                throw r == PasswordOperationResult.PolicyViolation ? Err(400, "err.adRejectedReset") : Err(500, "err.resetFailed");
            }
            await SaveEnrollment(u, e with { State = e.State with { LastResetAt = Now } }, ct).ConfigureAwait(false);
            _flows.TryRemove(f.Id, out _);
            await Audit(AuditEventId.PasswordReset, AuditOutcome.Success, u.SamAccountName, null, ip, $"Password reimpostata con {f.Done} verifiche").ConfigureAwait(false);
            await Notify(u, e, "passwordReset", ct).ConfigureAwait(false);
        }
        else
        {
            var r = await _ad.UnlockAsync(u, ct).ConfigureAwait(false);
            if (r != PasswordOperationResult.Ok)
            {
                await Audit(AuditEventId.UnlockFailed, AuditOutcome.Failure, u.SamAccountName, null, ip, "Sblocco non riuscito: " + r).ConfigureAwait(false);
                throw Err(500, "err.unlockFailed");
            }
            _flows.TryRemove(f.Id, out _);
            await Audit(AuditEventId.AccountUnlocked, AuditOutcome.Success, u.SamAccountName, null, ip, "Account sbloccato dall'utente").ConfigureAwait(false);
            await Notify(u, e, "accountUnlocked", ct).ConfigureAwait(false);
        }
    }
}
