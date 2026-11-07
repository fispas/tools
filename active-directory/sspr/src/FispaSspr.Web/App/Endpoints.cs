using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using FispaSspr.Core.Abstractions;
using FispaSspr.Core.Policy;
using FispaSspr.Web.Infrastructure;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace FispaSspr.Web.App;

public sealed record LoginRequest(string? UserName, string? Password);
public sealed record CodeRequest(string? Code);
public sealed record DestinationRequest(string? Destination);
public sealed record ChallengeAnswer(string? ChallengeId, string? Code);
public sealed record PasswordCheckRequest(string? Password, string? FlowId);
public sealed record StepUpRequest(string? Method);
public sealed record ChangeRequest(string? CurrentPassword, string? NewPassword);
public sealed record StartRequest(string? UserName, string? Purpose);
public sealed record MethodRequest(string? MethodId);
public sealed record CompleteRequest(string? NewPassword);
public sealed record ReasonRequest(string? Reason);
public sealed record TestRequest(string? Destination);

public static class Endpoints
{
    private static string? Ip(HttpContext c) => c.Connection.RemoteIpAddress?.ToString();
    private static SessionData Sess(HttpContext c) => c.RequestServices.GetRequiredService<SessionStore>().Get(c);

    private static async Task<object> SessionDto(HttpContext c, SessionData s)
    {
        var settings = c.RequestServices.GetRequiredService<SettingsStore>().Current;
        var portal = c.RequestServices.GetRequiredService<PortalService>();
        bool? enrolled = null;
        bool? manageable = null;
        if (s.Authenticated)
        {
            try
            {
                var ad = c.RequestServices.GetRequiredService<AdDirectory>();
                var u = await ad.FindUserBySidAsync(s.UserSid!).ConfigureAwait(false);
                if (u is not null)
                {
                    manageable = AccountProtection.Evaluate(u, portal.Scope).Manageable && u.Enabled;
                    if (manageable == true)
                    {
                        var (e, _) = await portal.LoadEnrollment(u, c.RequestAborted).ConfigureAwait(false);
                        enrolled = e.IsEnrolled(settings.Verification.MinimumEnrolledMethods);
                    }
                }
            }
            catch (System.Runtime.InteropServices.COMException) { }
        }
        return new
        {
            csrfToken = s.Csrf,
            authenticated = s.Authenticated,
            authMethod = s.AuthMethod,
            userName = s.UserName,
            displayName = s.DisplayName,
            manageable,
            enrolled,
            isAdmin = s.IsAdmin,
            isHelpdesk = s.IsHelpdesk,
            adminSecondFactorDone = s.AdminSecondFactor,
            availableMethods = portal.AvailableMethods().Select(PortalService.Name).ToArray(),
            minimumMethods = settings.Verification.MinimumEnrolledMethods,
        };
    }

    /// <summary>Configurazione pubblica dell'interfaccia: testi, aspetto e funzioni attive (nessun dato sensibile).</summary>
    private static object UiDto(SettingsStore st, TextCatalog t)
    {
        var c = st.Current;
        var b = c.Branding;
        var f = c.Features;
        return new
        {
            texts = t.ForClient(),
            branding = new
            {
                companyName = c.General.CompanyName,
                portalTitle = b.PortalTitle,
                tagline = b.Tagline,
                showCompanyName = b.ShowCompanyNameInHeader,
                helpdeskContact = t.Helpdesk,
                helpUrl = string.IsNullOrWhiteSpace(b.HelpUrl) ? null : b.HelpUrl,
                logoUrl = BrandingStore.PathOf(b.LogoFile) is null ? null : "/branding/logo?v=" + Version(b.LogoFile),
                faviconUrl = BrandingStore.PathOf(b.FaviconFile) is null ? null : "/branding/favicon?v=" + Version(b.FaviconFile),
                announcement = b.Announcement.Enabled && !string.IsNullOrWhiteSpace(b.Announcement.Text) ? new { level = b.Announcement.Level, text = b.Announcement.Text } : null,
                themeVersion = ThemeVersion(st),
            },
            features = new
            {
                reset = f.ResetEnabled, unlock = f.UnlockEnabled, change = f.ChangeEnabled, enrollment = f.EnrollmentEnabled,
                windowsLogin = f.WindowsLoginEnabled, passwordLogin = f.PasswordLoginEnabled, showPasswordRequirements = f.ShowPasswordRequirements,
                allowMethodRemoval = f.AllowMethodRemoval,
            },
        };
    }

    private static string Version(string? file)
    {
        var p = BrandingStore.PathOf(file);
        return p is null ? "0" : File.GetLastWriteTimeUtc(p).Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    private static string ThemeVersion(SettingsStore st)
    {
        var css = BrandingStore.ThemeCss(st.Current.Branding);
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(css)))[..12];
    }

    /// <summary>Contro la formula injection quando il CSV viene aperto in Excel.</summary>
    internal static string CsvCell(string? v)
    {
        var x = v ?? string.Empty;
        if (x.Length > 0 && "=+-@\t\r".Contains(x[0], StringComparison.Ordinal)) x = "'" + x;
        return "\"" + x.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }

    public static void Map(WebApplication app)
    {
        var api = app.MapGroup("/api/v1");

        // ------------------------------------------------------------ sessione
        api.MapGet("/session", async (HttpContext c) => Results.Ok(await SessionDto(c, Sess(c))));
        api.MapGet("/ui", (SettingsStore st, TextCatalog t) => Results.Ok(UiDto(st, t)));

        api.MapGet("/session/windows", [Authorize(AuthenticationSchemes = NegotiateDefaults.AuthenticationScheme)] async (HttpContext c, SessionStore store, AdDirectory ad, SettingsStore st, PortalService portal, IAuditLog audit) =>
        {
            var s = store.Get(c);
            var adminPanel = string.Equals(c.Request.Query["panel"], "admin", StringComparison.Ordinal);
            // l'accesso Windows resta sempre disponibile per il pannello degli operatori
            if (!adminPanel) portal.RequireFeature(st.Current.Features.WindowsLoginEnabled);
            var sid = c.User.FindFirst(ClaimTypes.PrimarySid)?.Value ?? (c.User.Identity as WindowsIdentity)?.User?.Value;
            if (sid is null) return Results.Unauthorized();
            var groups = new HashSet<string>(c.User.FindAll(ClaimTypes.GroupSid).Select(x => x.Value), StringComparer.OrdinalIgnoreCase);
            var u = await ad.FindUserBySidAsync(sid);
            s.UserSid = sid;
            s.UserName = u?.SamAccountName ?? c.User.Identity?.Name;
            s.DisplayName = u?.DisplayName;
            s.AuthMethod = "windows";
            s.AuthAt = DateTimeOffset.UtcNow;
            s.IsAdmin = !string.IsNullOrEmpty(st.Current.Admin.AdminGroupSid) && groups.Contains(st.Current.Admin.AdminGroupSid);
            s.IsHelpdesk = s.IsAdmin || (!string.IsNullOrEmpty(st.Current.Admin.HelpdeskGroupSid) && groups.Contains(st.Current.Admin.HelpdeskGroupSid));
            s.AdminSecondFactor = false;
            s.AdminSecondFactorAt = null;
            var fresh = store.Rotate(c, s, keepIdentity: true);
            await audit.WriteAsync(new AuditEntry(AuditEventId.UserSignIn, AuditOutcome.Success, fresh.UserName, null, Ip(c), adminPanel ? "Accesso Windows (pannello)" : "Accesso Windows"));
            return Results.Ok(await SessionDto(c, fresh));
        });

        api.MapPost("/session/login", async (HttpContext c, LoginRequest req, SessionStore store, AdDirectory ad, PortalService portal, SettingsStore st, IAuditLog audit) =>
        {
            var start = DateTimeOffset.UtcNow;
            var s = store.Get(c);
            try
            {
                portal.RequireFeature(st.Current.Features.PasswordLoginEnabled);
                var name = FispaSspr.Core.Security.Normalization.UserName(req.UserName);
                portal.LimitLogin(name, Ip(c));
                var failed = new PortalException(401, portal.Texts.Get("err.loginFailed"), code: "err.loginFailed");
                if (name is null || string.IsNullOrEmpty(req.Password) || req.Password.Length > 256) throw failed;
                var u = await ad.FindUserAsync(name);
                if (u is null || !u.Enabled || !AccountProtection.Evaluate(u, portal.Scope).Manageable || !await ad.ValidateCredentialsAsync(u, req.Password))
                {
                    await audit.WriteAsync(new AuditEntry(AuditEventId.UserSignInFailed, AuditOutcome.Failure, name, null, Ip(c), "Accesso con password non riuscito"));
                    throw failed;
                }
                s.UserSid = u.Sid; s.UserName = u.SamAccountName; s.DisplayName = u.DisplayName; s.AuthMethod = "password"; s.AuthAt = DateTimeOffset.UtcNow;
                s.IsAdmin = s.IsHelpdesk = false;
                var fresh = store.Rotate(c, s, keepIdentity: true);
                await audit.WriteAsync(new AuditEntry(AuditEventId.UserSignIn, AuditOutcome.Success, u.SamAccountName, null, Ip(c), "Accesso con password"));
                return Results.Ok(await SessionDto(c, fresh));
            }
            finally { await portal.ConstantTime(start); }
        });

        api.MapPost("/session/logout", async (HttpContext c, SessionStore store) =>
        {
            var fresh = store.Rotate(c, Sess(c), keepIdentity: false);
            return Results.Ok(await SessionDto(c, fresh));
        });

        // ------------------------------------------------------------ conferma dell'identita' (step-up)
        api.MapPost("/stepup/challenge", async (HttpContext c, StepUpRequest r, PortalService p) =>
            Results.Ok(await p.StepUpChallenge(Sess(c), p.ParseMethod(r.Method), Ip(c), c.RequestAborted)));
        api.MapPost("/stepup/verify", async (HttpContext c, ChallengeAnswer r, PortalService p) =>
            Results.Ok(await p.StepUpVerify(Sess(c), r.ChallengeId, r.Code, Ip(c), c.RequestAborted)));

        // ------------------------------------------------------------ registrazione
        api.MapGet("/enrollment", async (HttpContext c, PortalService p) =>
        {
            var u = await p.RequireManageableUser(Sess(c), c.RequestAborted);
            var (e, _) = await p.LoadEnrollment(u, c.RequestAborted);
            return Results.Ok(p.EnrollmentStatus(e, Sess(c)));
        });
        api.MapPost("/enrollment/totp/start", async (HttpContext c, PortalService p) => Results.Ok(await p.TotpStart(Sess(c), c.RequestAborted)));
        api.MapPost("/enrollment/totp/confirm", async (HttpContext c, CodeRequest r, PortalService p) => Results.Ok(await p.TotpConfirm(Sess(c), r.Code, Ip(c), c.RequestAborted)));
        api.MapPost("/enrollment/{method}/start", async (HttpContext c, string method, DestinationRequest r, PortalService p) =>
            Results.Ok(await p.DestinationStart(Sess(c), p.ParseMethod(method), r.Destination, Ip(c), c.RequestAborted)));
        api.MapPost("/enrollment/{method}/confirm", async (HttpContext c, string method, ChallengeAnswer r, PortalService p) =>
            Results.Ok(await p.DestinationConfirm(Sess(c), p.ParseMethod(method), r.ChallengeId, r.Code, Ip(c), c.RequestAborted)));
        api.MapDelete("/enrollment/{method}", async (HttpContext c, string method, PortalService p) =>
            Results.Ok(await p.RemoveMethod(Sess(c), p.ParseMethod(method), Ip(c), c.RequestAborted)));

        // ------------------------------------------------------------ password
        api.MapPost("/password/check", async (HttpContext c, PasswordCheckRequest r, PortalService p) =>
            Results.Ok(await p.CheckPasswordForSession(Sess(c), r.FlowId, r.Password, Ip(c), c.RequestAborted)));
        api.MapPost("/password/change", async (HttpContext c, ChangeRequest r, PortalService p) =>
        {
            await p.ChangePassword(Sess(c), r.CurrentPassword, r.NewPassword, Ip(c), c.RequestAborted);
            return Results.NoContent();
        });

        // ------------------------------------------------------------ reset e sblocco
        api.MapPost("/reset/start", async (HttpContext c, StartRequest r, PortalService p) =>
            Results.Ok(await p.StartFlow(Sess(c), r.UserName, r.Purpose, Ip(c), c.RequestAborted)));
        api.MapPost("/reset/{flowId}/challenge", async (HttpContext c, string flowId, MethodRequest r, PortalService p) =>
            Results.Ok(await p.FlowChallenge(Sess(c), flowId, r.MethodId, Ip(c), c.RequestAborted)));
        api.MapPost("/reset/{flowId}/verify", async (HttpContext c, string flowId, CodeRequest r, PortalService p) =>
            Results.Ok(await p.FlowVerify(Sess(c), flowId, r.Code, Ip(c), c.RequestAborted)));
        api.MapPost("/reset/{flowId}/complete", async (HttpContext c, string flowId, CompleteRequest r, PortalService p) =>
        {
            await p.FlowComplete(Sess(c), flowId, r.NewPassword, Ip(c), c.RequestAborted);
            return Results.NoContent();
        });

        // ------------------------------------------------------------ amministrazione
        var adm = api.MapGroup("/admin");
        adm.MapGet("/2fa", (HttpContext c, AdminService a) => Results.Ok(a.SecondFactorStatus(Sess(c))));
        adm.MapPost("/2fa/setup", (HttpContext c, AdminService a) => Results.Ok(a.SecondFactorSetup(Sess(c))));
        adm.MapPost("/2fa/verify", async (HttpContext c, CodeRequest r, AdminService a) => Results.Ok(await a.SecondFactorVerify(Sess(c), r.Code, Ip(c))));
        adm.MapGet("/dashboard", async (HttpContext c, AdminService a) => Results.Ok(await a.Dashboard(Sess(c))));
        adm.MapGet("/users", async (HttpContext c, [FromQuery] string? q, AdminService a) => Results.Ok(await a.Search(Sess(c), q)));
        adm.MapGet("/users/{sid}", async (HttpContext c, string sid, AdminService a) => Results.Ok(await a.Detail(Sess(c), sid)));
        adm.MapPost("/users/{sid}/unlock", async (HttpContext c, string sid, ReasonRequest r, AdminService a) => { await a.Unlock(Sess(c), sid, r.Reason, Ip(c)); return Results.NoContent(); });
        adm.MapPost("/users/{sid}/enrollment/clear", async (HttpContext c, string sid, ReasonRequest r, AdminService a) => { await a.ClearEnrollment(Sess(c), sid, r.Reason, Ip(c)); return Results.NoContent(); });
        adm.MapPost("/users/{sid}/invite", async (HttpContext c, string sid, AdminService a) => { await a.Invite(Sess(c), sid, Ip(c)); return Results.NoContent(); });
        adm.MapPost("/users/{sid}/reset", async (HttpContext c, string sid, ReasonRequest r, AdminService a) => Results.Ok(await a.TemporaryReset(Sess(c), sid, r.Reason, Ip(c))));
        adm.MapPost("/operators/{sid}/totp/clear", async (HttpContext c, string sid, AdminService a) => { await a.ResetOperatorTotp(Sess(c), sid, Ip(c)); return Results.NoContent(); });
        adm.MapGet("/audit", (HttpContext c, [FromQuery] DateTimeOffset? from, [FromQuery] DateTimeOffset? to, [FromQuery] string? user, [FromQuery] int? eventId, [FromQuery] string? format, AdminService a) =>
        {
            var rows = a.AuditQuery(Sess(c), from, to, user, eventId);
            if (!string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase)) return Results.Ok(rows);
            var sb = new StringBuilder("Data;ID;Evento;Esito;Utente;Operatore;IP;Messaggio\r\n");
            static string Q(string? v) => CsvCell(v);
            foreach (var r in rows)
                sb.Append(Q(r.Time.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture))).Append(';').Append(r.EventId).Append(';')
                  .Append(Q(r.Event)).Append(';').Append(Q(r.Outcome)).Append(';').Append(Q(r.TargetUser)).Append(';').Append(Q(r.Actor)).Append(';').Append(Q(r.ClientIp)).Append(';').Append(Q(r.Message)).Append("\r\n");
            return Results.File(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(sb.ToString())).ToArray(), "text/csv", "audit-sspr.csv");
        });
        adm.MapGet("/settings", (HttpContext c, AdminService a) => Results.Ok(a.GetSettings(Sess(c))));
        adm.MapGet("/texts", (HttpContext c, AdminService a) => Results.Ok(a.TextCatalogDto(Sess(c))));
        adm.MapPost("/branding/{asset}", async (HttpContext c, string asset, AdminService.AssetUpload r, AdminService a) => { await a.UploadAsset(Sess(c), asset, r, Ip(c)); return Results.NoContent(); })
           .WithMetadata(new RequestSizeLimitAttribute(BrandingStore.MaxBytes * 2));
        adm.MapDelete("/branding/{asset}", async (HttpContext c, string asset, AdminService a) => { await a.DeleteAsset(Sess(c), asset, Ip(c)); return Results.NoContent(); });
        adm.MapPut("/settings", async (HttpContext c, AdminService.SettingsUpdate r, AdminService a) => { await a.SaveSettings(Sess(c), r, Ip(c)); return Results.NoContent(); });
        adm.MapGet("/health", (HttpContext c, AdminService a) => Results.Ok(a.Health(Sess(c))));
        adm.MapPost("/test/{channel}", async (HttpContext c, string channel, TestRequest r, AdminService a) => { await a.TestChannel(Sess(c), channel, r.Destination, Ip(c)); return Results.NoContent(); });

        // aspetto: file caricati dal pannello e foglio di stile del tema
        app.MapGet("/branding/{asset}", (HttpContext c, string asset, SettingsStore st) =>
        {
            var b = st.Current.Branding;
            var file = asset switch { "logo" => b.LogoFile, "favicon" => b.FaviconFile, "background" => b.BackgroundFile, _ => null };
            var path = BrandingStore.PathOf(file);
            if (path is null) return Results.NotFound();
            c.Response.Headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; sandbox";
            c.Response.Headers.CacheControl = "public, max-age=86400";
            return Results.File(File.ReadAllBytes(path), BrandingStore.ContentType(path) ?? "application/octet-stream");
        });
        app.MapGet("/theme.css", (HttpContext c, SettingsStore st) =>
        {
            c.Response.Headers.CacheControl = "public, max-age=300";
            return Results.Text(BrandingStore.ThemeCss(st.Current.Branding), "text/css; charset=utf-8");
        });
    }
}
