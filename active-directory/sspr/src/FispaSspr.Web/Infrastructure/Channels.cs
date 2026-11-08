using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Mail;
using System.Text;
using System.Text.Json;
using FispaSspr.Core.Abstractions;
using FispaSspr.Core.Crypto;
using FispaSspr.Core.Model;
using FispaSspr.Core.Settings;

namespace FispaSspr.Web.Infrastructure;

/// <summary>Email via SMTP (relay interno, con o senza autenticazione).</summary>
public sealed class SmtpChannel : IMessageChannel
{
    private readonly SettingsStore _settings;
    private readonly IMasterKeyProvider _keys;

    public SmtpChannel(SettingsStore settings, IMasterKeyProvider keys) { _settings = settings; _keys = keys; }

    public VerificationMethod Method => VerificationMethod.Email;

    public bool Configured => !string.IsNullOrWhiteSpace(_settings.Current.Smtp.Host) && !string.IsNullOrWhiteSpace(_settings.Current.Smtp.From);

    public async Task SendAsync(string destination, string subject, string text, CancellationToken ct = default)
    {
        var s = _settings.Current.Smtp;
        if (!Configured) throw new InvalidOperationException("SMTP non configurato.");
        using var client = new SmtpClient(s.Host, s.Port) { EnableSsl = s.UseStartTls, DeliveryMethod = SmtpDeliveryMethod.Network, Timeout = 20000 };
        if (!string.IsNullOrEmpty(s.UserName))
            client.Credentials = new NetworkCredential(s.UserName, SettingsStore.Decrypt(s.PasswordEnvelope, _keys, "smtp"));
        var safeSubject = subject.Replace("\r", " ", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal);
        using var msg = new MailMessage(s.From, destination, safeSubject, text) { BodyEncoding = Encoding.UTF8, SubjectEncoding = Encoding.UTF8 };
        await client.SendMailAsync(msg, ct).ConfigureAwait(false);
    }
}

/// <summary>SMS via SMS Gateway for Android (modalita' Local Server) o connettore HTTP generico.</summary>
public sealed class SmsChannel : IMessageChannel
{
    private readonly SettingsStore _settings;
    private readonly IMasterKeyProvider _keys;
    private readonly IHttpClientFactory _http;

    public SmsChannel(SettingsStore settings, IMasterKeyProvider keys, IHttpClientFactory http) { _settings = settings; _keys = keys; _http = http; }

    public VerificationMethod Method => VerificationMethod.Sms;

    public bool Configured => _settings.Current.Sms.Provider != SmsProvider.None && !string.IsNullOrWhiteSpace(_settings.Current.Sms.Endpoint);

    public async Task SendAsync(string destination, string subject, string text, CancellationToken ct = default)
    {
        var s = _settings.Current.Sms;
        if (!Configured) throw new InvalidOperationException("Gateway SMS non configurato.");
        var client = _http.CreateClient("sms");
        using var req = new HttpRequestMessage(HttpMethod.Post, s.Endpoint);
        if (!string.IsNullOrEmpty(s.UserName))
        {
            var pwd = SettingsStore.Decrypt(s.PasswordEnvelope, _keys, "sms") ?? string.Empty;
            req.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(s.UserName + ":" + pwd)));
        }
        string body;
        if (s.Provider == SmsProvider.AndroidGatewayLocal)
        {
            body = JsonSerializer.Serialize(new { textMessage = new { text }, phoneNumbers = new[] { destination } });
        }
        else
        {
            var tpl = string.IsNullOrWhiteSpace(s.GenericBodyTemplate) ? "{\"to\":\"{to}\",\"text\":\"{text}\"}" : s.GenericBodyTemplate;
            body = tpl.Replace("{to}", JsonEncoded(destination), StringComparison.Ordinal).Replace("{text}", JsonEncoded(text), StringComparison.Ordinal);
        }
        req.Content = new StringContent(body, Encoding.UTF8, "application/json");
        using var resp = await client.SendAsync(req, ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException($"Gateway SMS: HTTP {(int)resp.StatusCode}");
    }

    private static string JsonEncoded(string value)
    {
        var s = JsonSerializer.Serialize(value);
        return s[1..^1];
    }
}

/// <summary>Audit su Registro eventi "SSPR" e su file JSONL mensili (consultabili dal pannello).</summary>
public sealed class AuditLog : IAuditLog
{
    public const string LogName = "SSPR";
    public const string Source = "FispaSSPR";

    private readonly ILogger<AuditLog> _log;
    private readonly object _lock = new();
    private readonly bool _eventLogAvailable;
    private readonly SettingsStore _settings;
    private readonly IHttpClientFactory _http;
    private readonly System.Threading.Channels.Channel<Record> _forward =
        System.Threading.Channels.Channel.CreateBounded<Record>(new System.Threading.Channels.BoundedChannelOptions(5000) { FullMode = System.Threading.Channels.BoundedChannelFullMode.DropOldest });

    public AuditLog(ILogger<AuditLog> log, SettingsStore settings, IHttpClientFactory http)
    {
        _log = log;
        _settings = settings;
        _http = http;
        _ = Task.Run(ForwardLoop);
        try { _eventLogAvailable = OperatingSystem.IsWindows() && EventLog.SourceExists(Source); }
        catch (System.Security.SecurityException) { _eventLogAvailable = false; }
        catch (InvalidOperationException) { _eventLogAvailable = false; }
    }

    public sealed record Record(DateTimeOffset Time, int EventId, string Event, string Outcome, string? TargetUser, string? Actor, string? ClientIp, string Message);

    public Task WriteAsync(AuditEntry entry, CancellationToken ct = default)
    {
        var rec = new Record(DateTimeOffset.UtcNow, (int)entry.EventId, entry.EventId.ToString(), entry.Outcome.ToString(), entry.TargetUser, entry.Actor, entry.ClientIp, entry.Message);
        var line = JsonSerializer.Serialize(rec);
        lock (_lock)
        {
            Directory.CreateDirectory(SsprPaths.Audit);
            File.AppendAllText(Path.Combine(SsprPaths.Audit, $"audit-{rec.Time:yyyyMM}.jsonl"), line + Environment.NewLine, new UTF8Encoding(false));
        }
        if (_eventLogAvailable)
        {
            var type = entry.Outcome == AuditOutcome.Success ? EventLogEntryType.Information : EventLogEntryType.Warning;
            if (entry.EventId == AuditEventId.Error) type = EventLogEntryType.Error;
            try
            {
                EventLog.WriteEntry(Source, $"{entry.Message}\r\nEsito: {entry.Outcome}\r\nUtente: {entry.TargetUser}\r\nOperatore: {entry.Actor}\r\nClient: {entry.ClientIp}", type, (int)entry.EventId);
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { _log.LogWarning(ex, "Scrittura nel Registro eventi non riuscita"); }
        }
        _log.LogInformation("AUDIT {EventId} {Outcome} user={User} actor={Actor} ip={Ip} {Message}", entry.EventId, entry.Outcome, entry.TargetUser, entry.Actor, entry.ClientIp, entry.Message);
        var a = _settings.Current.Audit;
        if ((a.SyslogEnabled && !string.IsNullOrWhiteSpace(a.SyslogHost)) || !string.IsNullOrWhiteSpace(a.WebhookUrl)) _forward.Writer.TryWrite(rec);
        return Task.CompletedTask;
    }

    // ------------------------------------------------------------------ inoltro a SIEM (syslog) e webhook, fuori dal percorso della richiesta

    private async Task ForwardLoop()
    {
        await foreach (var rec in _forward.Reader.ReadAllAsync().ConfigureAwait(false))
        {
            var a = _settings.Current.Audit;
            if (a.SyslogEnabled && !string.IsNullOrWhiteSpace(a.SyslogHost))
            {
                try { await SendSyslog(a, rec).ConfigureAwait(false); }
                catch (Exception ex) when (ex is System.Net.Sockets.SocketException or IOException or TimeoutException or OperationCanceledException) { _log.LogWarning(ex, "Inoltro syslog non riuscito"); }
            }
            if (!string.IsNullOrWhiteSpace(a.WebhookUrl) && (!a.WebhookOnlyIssues || rec.Outcome != nameof(AuditOutcome.Success) || rec.Actor is not null || rec.EventId == (int)AuditEventId.JobRun))
            {
                try
                {
                    var text = $"[FispaSSPR] {rec.Event} ({rec.EventId}) - {rec.Outcome}: {rec.Message}" +
                               (rec.TargetUser is null ? "" : $" | utente {rec.TargetUser}") + (rec.Actor is null ? "" : $" | operatore {rec.Actor}") + (rec.ClientIp is null ? "" : $" | client {rec.ClientIp}");
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                    using var resp = await _http.CreateClient("webhook").PostAsync(a.WebhookUrl, new StringContent(JsonSerializer.Serialize(new { text }), Encoding.UTF8, "application/json"), cts.Token).ConfigureAwait(false);
                    if (!resp.IsSuccessStatusCode) _log.LogWarning("Webhook: risposta {Status}", (int)resp.StatusCode);
                }
                catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or InvalidOperationException) { _log.LogWarning(ex, "Inoltro al webhook non riuscito"); }
            }
        }
    }

    /// <summary>RFC 5424 su UDP oppure TCP (framing a conteggio di ottetti, RFC 6587). Facility authpriv (10).</summary>
    private static async Task SendSyslog(AuditSettings a, Record rec)
    {
        var sev = rec.Outcome == nameof(AuditOutcome.Success) ? 6 : 4;
        if (rec.EventId == (int)AuditEventId.Error) sev = 3;
        static string P(string? v) => (v ?? "").Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal).Replace("]", "\\]", StringComparison.Ordinal);
        var host = Environment.MachineName;
        var msg = $"<{10 * 8 + sev}>1 {rec.Time.UtcDateTime:yyyy-MM-ddTHH:mm:ss.fffZ} {host} FispaSSPR - {rec.EventId} [fispa@32473 event=\"{P(rec.Event)}\" outcome=\"{P(rec.Outcome)}\" user=\"{P(rec.TargetUser)}\" actor=\"{P(rec.Actor)}\" ip=\"{P(rec.ClientIp)}\"] {rec.Message}";
        var bytes = Encoding.UTF8.GetBytes(msg);
        var port = Math.Clamp(a.SyslogPort, 1, 65535);
        if (string.Equals(a.SyslogProtocol, "Tcp", StringComparison.OrdinalIgnoreCase))
        {
            using var tcp = new System.Net.Sockets.TcpClient();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await tcp.ConnectAsync(a.SyslogHost, port, cts.Token).ConfigureAwait(false);
            var stream = tcp.GetStream();
            var framed = Encoding.ASCII.GetBytes(bytes.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) + " ");
            await stream.WriteAsync(framed, cts.Token).ConfigureAwait(false);
            await stream.WriteAsync(bytes, cts.Token).ConfigureAwait(false);
        }
        else
        {
            using var udp = new System.Net.Sockets.UdpClient();
            await udp.SendAsync(bytes, bytes.Length, a.SyslogHost, port).ConfigureAwait(false);
        }
    }

    /// <summary>Elimina i file mensili piu' vecchi della conservazione configurata.</summary>
    public void PurgeOlderThan(int months)
    {
        if (!Directory.Exists(SsprPaths.Audit)) return;
        var limit = DateTimeOffset.UtcNow.AddMonths(-Math.Clamp(months, 1, 120));
        var cutoff = limit.Year * 100 + limit.Month;
        lock (_lock)
        {
            foreach (var f in Directory.GetFiles(SsprPaths.Audit, "audit-*.jsonl"))
            {
                var stem = Path.GetFileNameWithoutExtension(f);
                if (stem.Length == 12 && int.TryParse(stem[6..], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var ym) && ym < cutoff) File.Delete(f);
            }
        }
    }

    public IReadOnlyList<Record> Query(DateTimeOffset from, DateTimeOffset to, string? user, int? eventId, int max)
    {
        var list = new List<Record>();
        if (!Directory.Exists(SsprPaths.Audit)) return list;
        for (var m = new DateTimeOffset(from.Year, from.Month, 1, 0, 0, 0, TimeSpan.Zero); m <= to; m = m.AddMonths(1))
        {
            var file = Path.Combine(SsprPaths.Audit, $"audit-{m:yyyyMM}.jsonl");
            if (!File.Exists(file)) continue;
            string[] lines;
            lock (_lock) { lines = File.ReadAllLines(file); }
            foreach (var l in lines)
            {
                if (string.IsNullOrWhiteSpace(l)) continue;
                Record? r;
                try { r = JsonSerializer.Deserialize<Record>(l); } catch (JsonException) { continue; }
                if (r is null || r.Time < from || r.Time > to) continue;
                if (eventId is not null && r.EventId != eventId) continue;
                if (!string.IsNullOrEmpty(user) && !(r.TargetUser ?? string.Empty).Contains(user, StringComparison.OrdinalIgnoreCase) && !(r.Actor ?? string.Empty).Contains(user, StringComparison.OrdinalIgnoreCase)) continue;
                list.Add(r);
            }
        }
        return list.OrderByDescending(r => r.Time).Take(max).ToList();
    }
}

/// <summary>Secondo fattore TOTP degli operatori del pannello (anche account protetti), cifrato con la chiave master.</summary>
public sealed class AdminTotpStore
{
    private sealed record Entry(string Secret, long LastStep);

    private readonly IMasterKeyProvider _keys;
    private readonly object _lock = new();

    public AdminTotpStore(IMasterKeyProvider keys) => _keys = keys;

    private Dictionary<string, string> Load() =>
        File.Exists(SsprPaths.AdminTotp)
            ? JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(SsprPaths.AdminTotp)) ?? new()
            : new();

    private static string Aad(string sid) => "admintotp|" + sid;

    public bool IsEnrolled(string sid) { lock (_lock) return Load().ContainsKey(sid); }

    public (byte[] Secret, long LastStep)? Get(string sid)
    {
        lock (_lock)
        {
            if (!Load().TryGetValue(sid, out var env)) return null;
            var e = JsonSerializer.Deserialize<Entry>(SecretEnvelope.UnprotectString(env, _keys, Aad(sid)))!;
            return (Convert.FromBase64String(e.Secret), e.LastStep);
        }
    }

    public void Set(string sid, byte[] secret, long lastStep)
    {
        lock (_lock)
        {
            var d = Load();
            d[sid] = SecretEnvelope.ProtectString(JsonSerializer.Serialize(new Entry(Convert.ToBase64String(secret), lastStep)), _keys.Current, Aad(sid));
            SsprPaths.WriteAtomic(SsprPaths.AdminTotp, JsonSerializer.Serialize(d));
        }
    }

    public void Remove(string sid)
    {
        lock (_lock)
        {
            var d = Load();
            if (d.Remove(sid)) SsprPaths.WriteAtomic(SsprPaths.AdminTotp, JsonSerializer.Serialize(d));
        }
    }
}
