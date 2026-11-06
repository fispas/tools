using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using FispaSspr.Core.Model;

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
    public byte[]? PendingAdminTotp { get; set; }

    public byte[]? PendingTotp { get; set; }
    public string? PendingChallengeId { get; set; }
    public VerificationMethod? PendingMethod { get; set; }
    public string? PendingDestination { get; set; }

    /// <summary>Verifica aggiuntiva per il cambio password: valida per pochi minuti.</summary>
    public DateTimeOffset? ChangeVerifiedUntil { get; set; }

    public bool Authenticated => UserSid is not null;
    public bool IsOperator => IsAdmin || IsHelpdesk;

    public void SignOut()
    {
        UserSid = UserName = DisplayName = AuthMethod = null;
        AuthAt = null;
        IsAdmin = IsHelpdesk = AdminSecondFactor = false;
        PendingAdminTotp = PendingTotp = null;
        PendingChallengeId = PendingDestination = null;
        PendingMethod = null;
        ChangeVerifiedUntil = null;
    }
}

public sealed class SessionStore
{
    public const string CookieName = "__Host-sspr";
    private static readonly TimeSpan Idle = TimeSpan.FromMinutes(20);
    private readonly ConcurrentDictionary<string, SessionData> _sessions = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;

    public SessionStore(TimeProvider time) => _time = time;

    private static string NewId() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    public SessionData Get(HttpContext ctx)
    {
        var now = _time.GetUtcNow();
        if (ctx.Request.Cookies.TryGetValue(CookieName, out var id) && id is not null && _sessions.TryGetValue(id, out var s))
        {
            if (now - s.LastSeen < Idle)
            {
                s.LastSeen = now;
                return s;
            }
            _sessions.TryRemove(id, out _);
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
        return created;
    }

    /// <summary>Nuovo identificativo dopo l'autenticazione (contro il session fixation).</summary>
    public SessionData Rotate(HttpContext ctx, SessionData old)
    {
        _sessions.TryRemove(old.Id, out _);
        ctx.Request.Headers.Remove("Cookie");
        var fresh = Get(ctx);
        fresh.UserSid = old.UserSid;
        fresh.UserName = old.UserName;
        fresh.DisplayName = old.DisplayName;
        fresh.AuthMethod = old.AuthMethod;
        fresh.AuthAt = old.AuthAt;
        fresh.IsAdmin = old.IsAdmin;
        fresh.IsHelpdesk = old.IsHelpdesk;
        return fresh;
    }

    public void Purge()
    {
        var now = _time.GetUtcNow();
        foreach (var kv in _sessions)
            if (now - kv.Value.LastSeen >= Idle) _sessions.TryRemove(kv.Key, out _);
    }

    public static bool CsrfValid(SessionData s, string? header) =>
        !string.IsNullOrEmpty(header) && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(s.Csrf), Encoding.ASCII.GetBytes(header));
}
