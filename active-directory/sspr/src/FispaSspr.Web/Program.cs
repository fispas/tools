using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;
using FispaSspr.Core.Abstractions;
using FispaSspr.Core.Crypto;
using FispaSspr.Core.Otp;
using FispaSspr.Core.Passwords;
using FispaSspr.Core.Security;
using FispaSspr.Core.Settings;
using FispaSspr.Web;
using FispaSspr.Web.App;
using FispaSspr.Web.Infrastructure;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Server.Kestrel.Core;

if (args.Length > 0 && Cli.IsCommand(args[0])) return Cli.Run(args);

var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args, ContentRootPath = AppContext.BaseDirectory });
builder.Host.UseWindowsService(o => o.ServiceName = "FispaSSPR");
builder.Logging.AddEventLog(o => { o.SourceName = AuditLog.Source; o.LogName = AuditLog.LogName; });

var settings = new SettingsStore();
var keys = KeyStore.Load();
var dev = Environment.GetEnvironmentVariable("FISPASSPR_DEV") == "1";

builder.Services.AddSingleton(settings);
builder.Services.AddSingleton<TextCatalog>();
builder.Services.AddSingleton(keys);
builder.Services.AddSingleton<IMasterKeyProvider>(keys);
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(sp => new OtpChallengeStore(TimeProvider.System, () => settings.Current.Verification.CodeMaxAttempts));
builder.Services.AddSingleton<SlidingWindowRateLimiter>();
builder.Services.AddSingleton<SessionStore>();
builder.Services.AddSingleton<AdDirectory>();
builder.Services.AddSingleton<IDirectory>(sp => sp.GetRequiredService<AdDirectory>());
builder.Services.AddSingleton<SmtpChannel>();
builder.Services.AddSingleton<SmsChannel>();
builder.Services.AddSingleton<AuditLog>();
builder.Services.AddSingleton<IAuditLog>(sp => sp.GetRequiredService<AuditLog>());
builder.Services.AddSingleton<AdminTotpStore>();
builder.Services.AddSingleton<IBreachedPasswordChecker, SettingsBreachChecker>();
builder.Services.AddSingleton<PortalService>();
builder.Services.AddSingleton<AdminService>();
builder.Services.AddHttpClient("sms", c => c.Timeout = TimeSpan.FromSeconds(15));
builder.Services.AddHttpClient("webhook", c => c.Timeout = TimeSpan.FromSeconds(10));
builder.Services.AddSingleton<Jobs>();
builder.Services.AddHttpClient("hibp", c => { c.Timeout = TimeSpan.FromSeconds(5); c.DefaultRequestHeaders.UserAgent.ParseAdd("FispaSSPR"); });
builder.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();
builder.Services.AddAuthorization();
builder.Services.AddHsts(o => { o.MaxAge = TimeSpan.FromDays(365); o.IncludeSubDomains = false; });

builder.WebHost.ConfigureKestrel(k =>
{
    k.AddServerHeader = false;
    // 4 MB: configurazione con tutti i testi personalizzati e caricamento di logo/sfondo (max 1 MB in base64)
    k.Limits.MaxRequestBodySize = 4 * 1024 * 1024;
    k.Limits.MaxRequestHeadersTotalSize = 64 * 1024;
    if (dev)
    {
        k.ListenLocalhost(5080, l => l.Protocols = HttpProtocols.Http1);
        return;
    }
    var cert = LoadCertificate(settings.Current.Hosting.CertificateThumbprint)
        ?? throw new InvalidOperationException("Certificato HTTPS non trovato in LocalMachine\\My: rieseguire l'installazione.");
    // Negotiate (Kerberos/NTLM) non funziona su HTTP/2: solo HTTP/1.1
    k.ListenAnyIP(settings.Current.Hosting.Port, l =>
    {
        l.Protocols = HttpProtocols.Http1;
        l.UseHttps(cert, h => h.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13);
    });
});

var app = builder.Build();

if (!dev) app.UseHsts();

// header di sicurezza: niente script inline, niente frame, niente risorse esterne
app.Use(async (ctx, next) =>
{
    var h = ctx.Response.Headers;
    h["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
    h["X-Content-Type-Options"] = "nosniff";
    h["X-Frame-Options"] = "DENY";
    h["Referrer-Policy"] = "no-referrer";
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
    h["Cross-Origin-Opener-Policy"] = "same-origin";
    h["Cross-Origin-Resource-Policy"] = "same-origin";
    if (ctx.Request.Path.StartsWithSegments("/api")) h["Cache-Control"] = "no-store";
    await next();
});

// lingua della richiesta: intestazione X-Lang (impostata dall'interfaccia), parametro lang o Accept-Language.
// Prima della gestione degli errori, cosi' anche i messaggi di errore generici sono nella lingua dell'utente.
app.Use(async (ctx, next) =>
{
    string? lang = ctx.Request.Headers["X-Lang"];
    if (string.IsNullOrEmpty(lang)) lang = ctx.Request.Query["lang"];
    if (string.IsNullOrEmpty(lang))
    {
        var al = ctx.Request.Headers.AcceptLanguage.ToString();
        if (al.Length >= 2) lang = al[..2];
    }
    TextCatalog.Current = lang is { Length: >= 2 } && lang.Length <= 8 ? lang[..2].ToLowerInvariant() : null;
    await next();
});

// errori del portale come problem+json; nessun dettaglio interno verso il client
app.Use(async (ctx, next) =>
{
    try { await next(); }
    catch (PortalException ex)
    {
        ctx.Response.StatusCode = ex.Status;
        if (ex.RetryAfter is { } ra) ctx.Response.Headers.RetryAfter = ((int)Math.Ceiling(ra.TotalSeconds)).ToString(System.Globalization.CultureInfo.InvariantCulture);
        await ctx.Response.WriteAsJsonAsync(new { type = "about:blank", title = ex.Message, status = ex.Status, code = ex.Code, errors = ex.Errors }, (System.Text.Json.JsonSerializerOptions?)null, "application/problem+json");
    }
    catch (Exception ex) when (ex is not OperationCanceledException && !ctx.Response.HasStarted)
    {
        ctx.RequestServices.GetRequiredService<ILogger<Program>>().LogError(ex, "Errore non gestito su {Path}", ctx.Request.Path);
        await ctx.RequestServices.GetRequiredService<IAuditLog>().WriteAsync(new AuditEntry(AuditEventId.Error, AuditOutcome.Failure, null, null, ctx.Connection.RemoteIpAddress?.ToString(), "Errore imprevisto: " + ex.GetType().Name));
        ctx.Response.StatusCode = 500;
        var text = ctx.RequestServices.GetRequiredService<TextCatalog>().Get("err.unexpected");
        await ctx.Response.WriteAsJsonAsync(new { type = "about:blank", title = text, status = 500, code = "err.unexpected" }, (System.Text.Json.JsonSerializerOptions?)null, "application/problem+json");
    }
});

// CSRF: ogni richiesta che modifica qualcosa deve portare il token della sessione
app.Use(async (ctx, next) =>
{
    if (ctx.Request.Path.StartsWithSegments("/api") && !HttpMethods.IsGet(ctx.Request.Method) && !HttpMethods.IsHead(ctx.Request.Method))
    {
        // nessuna sessione nuova per richieste senza cookie valido: non possono comunque essere legittime
        var s = ctx.RequestServices.GetRequiredService<SessionStore>().TryGet(ctx);
        if (s is null || !SessionStore.CsrfValid(s, ctx.Request.Headers["X-CSRF-Token"]))
        {
            ctx.Response.StatusCode = 403;
            var text = ctx.RequestServices.GetRequiredService<TextCatalog>().Get("err.sessionExpired");
            await ctx.Response.WriteAsJsonAsync(new { type = "about:blank", title = text, status = 403, code = "err.sessionExpired" }, (System.Text.Json.JsonSerializerOptions?)null, "application/problem+json");
            return;
        }
    }
    await next();
});

app.UseDefaultFiles();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
Endpoints.Map(app);

// pulizia periodica di sessioni, flussi e contatori
app.Lifetime.ApplicationStarted.Register(() =>
{
    var services = app.Services;
    _ = services.GetRequiredService<IAuditLog>().WriteAsync(new AuditEntry(AuditEventId.ServiceStarted, AuditOutcome.Success, null, null, null,
        keys.HasKey ? $"Servizio avviato, chiave {keys.Current.Id}" : "Servizio avviato SENZA chiave master: " + keys.LoadError));
    _ = Task.Run(async () =>
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        var tick = 0;
        while (await timer.WaitForNextTickAsync(app.Lifetime.ApplicationStopping).ConfigureAwait(false))
        {
            try
            {
                services.GetRequiredService<SessionStore>().Purge();
                services.GetRequiredService<PortalService>().PurgeFlows();
                // 25 ore: il limite giornaliero delle verifiche fallite deve sopravvivere alla pulizia
                services.GetRequiredService<SlidingWindowRateLimiter>().Purge(TimeSpan.FromHours(25));
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { services.GetRequiredService<ILogger<Program>>().LogError(ex, "Pulizia periodica non riuscita"); }
            try
            {
                TextCatalog.Current = null;
                await services.GetRequiredService<Jobs>().TickAsync(app.Lifetime.ApplicationStopping).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { services.GetRequiredService<ILogger<Program>>().LogError(ex, "Attivita' pianificata non riuscita"); }
            if (tick++ % 1440 == 0)
            {
                try { services.GetRequiredService<AuditLog>().PurgeOlderThan(settings.Current.Audit.RetentionMonths); }
                catch (IOException ex) { services.GetRequiredService<ILogger<Program>>().LogWarning(ex, "Pulizia dell'audit non riuscita"); }
            }
        }
    });
});
app.Lifetime.ApplicationStopping.Register(() =>
    app.Services.GetRequiredService<IAuditLog>().WriteAsync(new AuditEntry(AuditEventId.ServiceStopped, AuditOutcome.Success, null, null, null, "Servizio fermato")).GetAwaiter().GetResult());

app.Run();
return 0;

static X509Certificate2? LoadCertificate(string thumbprint)
{
    if (string.IsNullOrWhiteSpace(thumbprint)) return null;
    using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
    store.Open(OpenFlags.ReadOnly);
    return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint.Replace(" ", string.Empty, StringComparison.Ordinal), false).FirstOrDefault();
}

/// <summary>Controllo password compromesse secondo la configurazione corrente (modificabile dal pannello senza riavvio).</summary>
public sealed class SettingsBreachChecker : IBreachedPasswordChecker
{
    private readonly SettingsStore _settings;
    private readonly IHttpClientFactory _http;
    private OfflineListChecker? _offline;
    private string? _offlinePath;

    public SettingsBreachChecker(SettingsStore settings, IHttpClientFactory http) { _settings = settings; _http = http; }

    public Task<BreachCheckResult> CheckAsync(string password, CancellationToken cancellationToken = default)
    {
        var p = _settings.Current.Passwords;
        switch (p.BreachedCheck)
        {
            case BreachedCheckMode.OnlineKAnonymity:
                return new HibpRangeChecker(_http.CreateClient("hibp")).CheckAsync(password, cancellationToken);
            case BreachedCheckMode.OfflineList:
                if (string.IsNullOrEmpty(p.OfflineListPath) || !File.Exists(p.OfflineListPath)) return Task.FromResult(BreachCheckResult.Unknown);
                if (_offline is null || _offlinePath != p.OfflineListPath) { _offline = OfflineListChecker.FromFile(p.OfflineListPath); _offlinePath = p.OfflineListPath; }
                return _offline.CheckAsync(password, cancellationToken);
            default:
                return Task.FromResult(BreachCheckResult.NotFound);
        }
    }
}
