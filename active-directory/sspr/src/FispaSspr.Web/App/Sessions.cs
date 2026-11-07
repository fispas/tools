using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using FispaSspr.Core.Model;
using FispaSspr.Web.Infrastructure;

namespace FispaSspr.Web.App;

/// <summary>Sessione lato server: nel browser c'e' solo un identificativo casuale in un cookie HttpOnly.</summary>
public sealed class SessionData
{
    public required string Id { get; init; }
    public required string Csrf { get; init; }
    public DateTimeOffset Created { get; init; }
    public DateTimeOffset LastSeen { get; set; }

    public string? UserSid { get; set; }
    public string? UserName { get; set; }
    public string? DisplayName { get; set; }
    public string? AuthMethod { get; set; }
    public DateTimeOffset? AuthAt { get; set; }

    public bool IsAdmin { get; set; }
    public bool IsHelpdesk { get; set; }
    public bool AdminSecondFactor { get; set; }
    public DateTimeOffset? AdminSecondFactorAt { get; set; }
    public byte[]? PendingAdminTotp { get; set; }

    public byte[]? PendingTotp { get; set; }
    public string? PendingChallengeId { get; set; }
    public VerificationMethod? PendingMethod { get; set; }
    public string? PendingDestination { get; set; }

    /// <summary>Conferma dell'identita' con un metodo gia' registrato (step-up), valida pochi minuti.</summary>
    public DateTimeOffset? StepUpUntil { get; set; }
    public string? StepUpChallengeId { get; set; }

    public bool Authenticated => UserSid is not null;
    public bool IsOperator => IsAdmin || IsHelpdesk;
    public bool IsWindows => AuthMethod == "windows";

    public void ClearPending()
    {
        PendingAdminTotp = PendingTotp = null;
        PendingChallengeId = PendingDestination = StepUpChallengeId = null;
        PendingMethod = null;
        StepUpUntil = null;
    }
}

public sealed class SessionStore
{
    public const string CookieName = "__Host-sspr";
    private const string ItemKey = "fispasspr.session";
    private readonly ConcurrentDictionary<string, SessionData> _sessions = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;
    private readonly SettingsStore _settings;

    public SessionStore(TimeProvider time, SettingsStore settings) { _time = time; _settings = settings; }

    private TimeSpan Idle => TimeSpan.FromMinutes(Math.Clamp(_settings.Current.Sessions.UserIdleMinutes, 2, 240));
    private TimeSpan Absolute => TimeSpan.FromMinutes(Math.Clamp(_settings.Current.Sessions.UserAbsoluteMinutes, 5, 1440));

    private static string NewId() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    private bool Alive(SessionData s, DateTimeOffset now) => now - s.LastSeen < Idle && now - s.Created < Absolute;

    /// <summary>Sessione della richiesta: una sola per richiesta (memorizzata in HttpContext.Items), creata se manca o e' scaduta.</summary>
    public SessionData Get(HttpContext ctx)
    {
        if (ctx.Items.TryGetValue(ItemKey, out var cached) && cached is SessionData c) return c;
        var now = _time.GetUtcNow();
        if (ctx.Request.Cookies.TryGetValue(CookieName, out var id) && id is not null && id.Length < 100 && _sessions.TryGetValue(id, out var s))
        {
            if (Alive(s, now))
            {
                s.LastSeen = now;
                ctx.Items[ItemKey] = s;
                return s;
            }
            _sessions.TryRemove(id, out _);
        }
        return Create(ctx, now);
    }

    private SessionData Create(HttpContext ctx, DateTimeOffset now)
    {
        if (_sessions.Count >= Math.Max(1000, _settings.Current.Sessions.MaxSessions))
        {
            Purge();
            if (_sessions.Count >= Math.Max(1000, _settings.Current.Sessions.MaxSessions))
                throw new PortalException(503, "Servizio momentaneamente occupato: riprovare tra poco.");
        }
        var created = new SessionData { Id = NewId(), Csrf = NewId(), Created = now, LastSeen = now };
        _sessions[created.Id] = created;
        ctx.Response.Cookies.Append(CookieName, created.Id, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = "/",
            IsEssential = true,
        });
        ctx.Items[ItemKey] = created;
        return created;
    }

    /// <summary>Nuovo identificativo e nuovo token CSRF dopo login o logout (contro il session fixation).</summary>
    public SessionData Rotate(HttpContext ctx, SessionData old, bool keepIdentity)
    {
        _sessions.TryRemove(old.Id, out _);
        ctx.Items.Remove(ItemKey);
        var fresh = Create(ctx, _time.GetUtcNow());
        if (keepIdentity)
        {
            fresh.UserSid = old.UserSid;
            fresh.UserName = old.UserName;
            fresh.DisplayName = old.DisplayName;
            fresh.AuthMethod = old.AuthMethod;
            fresh.AuthAt = old.AuthAt;
            fresh.IsAdmin = old.IsAdmin;
            fresh.IsHelpdesk = old.IsHelpdesk;
        }
        return fresh;
    }

    public void Purge()
    {
        var now = _time.GetUtcNow();
        foreach (var kv in _sessions)
            if (!Alive(kv.Value, now)) _sessions.TryRemove(kv.Key, out _);
    }

    public int Count => _sessions.Count;

    public static bool CsrfValid(SessionData s, string? header) =>
        !string.IsNullOrEmpty(header) && header.Length < 100 && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(s.Csrf), Encoding.ASCII.GetBytes(header));
}
