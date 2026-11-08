using System.Text.Json;
using FispaSspr.Core.Abstractions;
using FispaSspr.Core.Crypto;
using FispaSspr.Core.Model;
using FispaSspr.Core.Policy;
using FispaSspr.Core.Settings;
using FispaSspr.Web.Infrastructure;

namespace FispaSspr.Web.App;

/// <summary>
/// Attivita' pianificate interne al servizio: avvisi di scadenza della password e campagna di registrazione.
/// Una sola esecuzione per giorno (stato in jobs.json), invii idempotenti: lo stesso avviso non parte due volte.
/// </summary>
public sealed class Jobs
{
    private readonly SettingsStore _settings;
    private readonly AdDirectory _ad;
    private readonly PortalService _portal;
    private readonly SmtpChannel _mail;
    private readonly SmsChannel _sms;
    private readonly IAuditLog _audit;
    private readonly TextCatalog _texts;
    private readonly EnrollmentCodec _codec;
    private readonly ILogger<Jobs> _log;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public Jobs(SettingsStore settings, AdDirectory ad, PortalService portal, SmtpChannel mail, SmsChannel sms, IAuditLog audit, TextCatalog texts, IMasterKeyProvider keys, ILogger<Jobs> log)
    {
        _settings = settings; _ad = ad; _portal = portal; _mail = mail; _sms = sms; _audit = audit; _texts = texts; _codec = new EnrollmentCodec(keys); _log = log;
    }

    private SsprSettings S => _settings.Current;
    private static string StateFile => Path.Combine(SsprPaths.Root, "jobs.json");

    public sealed class JobState
    {
        public string? LastExpiryDay { get; set; }
        public string? LastCampaignDay { get; set; }
        /// <summary>SID -> "scadenza|giorni" dell'ultimo avviso inviato.</summary>
        public Dictionary<string, string> ExpirySent { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>SID -> data dell'ultimo invito.</summary>
        public Dictionary<string, DateTimeOffset> Invited { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    public sealed record JobResult(string Job, int Checked, int Sent, int Failed, string Message);

    private static JobState Load()
    {
        try { if (File.Exists(StateFile)) return JsonSerializer.Deserialize<JobState>(File.ReadAllText(StateFile), Json.Options) ?? new JobState(); }
        catch (Exception ex) when (ex is IOException or JsonException) { }
        return new JobState();
    }

    private static void Save(JobState st) => SsprPaths.WriteAtomic(StateFile, JsonSerializer.Serialize(st, Json.Options));

    /// <summary>Chiamato ogni minuto: avvia le attivita' all'ora configurata, una volta al giorno.</summary>
    public async Task TickAsync(CancellationToken ct)
    {
        var now = DateTimeOffset.Now;
        var today = now.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        var st = Load();
        if (S.Expiry.Enabled && now.Hour >= Math.Clamp(S.Expiry.HourOfDay, 0, 23) && st.LastExpiryDay != today) await RunExpiryAsync(false, ct).ConfigureAwait(false);
        if (S.Campaign.Enabled && now.Hour >= Math.Clamp(S.Campaign.HourOfDay, 0, 23) && st.LastCampaignDay != today) await RunCampaignAsync(false, ct).ConfigureAwait(false);
    }

    private static readonly System.Globalization.CultureInfo Inv = System.Globalization.CultureInfo.InvariantCulture;

    /// <summary>Utenti dell'ambito; se la directory non risponde l'errore finisce nell'audit (e quindi nel SIEM) e l'attivita' termina.</summary>
    private async Task<IReadOnlyList<AdDirectory.ScopeUser>?> Enumerate(string job, CancellationToken ct)
    {
        try { return await _ad.EnumerateScopeAsync(ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "Attivita' {Job}: lettura della directory non riuscita", job);
            await _audit.WriteAsync(new AuditEntry(AuditEventId.JobRun, AuditOutcome.Failure, null, null, null, $"Attivita' {job} non eseguita: directory non raggiungibile ({ex.GetType().Name})"), ct).ConfigureAwait(false);
            return null;
        }
    }

    /// <summary>Gia' avvisato per questa scadenza con la stessa soglia o una piu' vicina.</summary>
    private static bool AlreadyNotified(string? prev, DateTimeOffset exp, int bucket)
    {
        var p = (prev ?? string.Empty).Split('|');
        return p.Length == 2 && p[0] == exp.ToString("yyyy-MM-dd", Inv) && int.TryParse(p[1], System.Globalization.NumberStyles.None, Inv, out var t) && t <= bucket;
    }

    /// <summary>
    /// Avvisi di scadenza. Per ogni utente si usa la soglia piu' vicina non ancora avvisata (14, 7, 3, 1...): se il servizio
    /// resta fermo un giorno l'avviso arriva comunque al controllo successivo, e nessun avviso parte due volte
    /// (nemmeno con "Esegui ora", che anticipa solo l'orario).
    /// </summary>
    public async Task<JobResult> RunExpiryAsync(bool force, CancellationToken ct)
    {
        if (!await _gate.WaitAsync(0, ct).ConfigureAwait(false)) return new JobResult("expiry", 0, 0, 0, "Attivita' gia' in corso.");
        try
        {
            var st = Load();
            st.LastExpiryDay = DateTimeOffset.Now.ToString("yyyy-MM-dd", Inv);
            Save(st);
            if (!_mail.Configured && !S.Expiry.ToRegisteredMethods) return new JobResult("expiry", 0, 0, 0, "SMTP non configurato.");
            var days = S.Expiry.DaysBefore.Where(d => d is > 0 and <= 90).Distinct().OrderBy(d => d).ToList();
            if (days.Count == 0) return new JobResult("expiry", 0, 0, 0, "Nessuna soglia di preavviso configurata.");
            var users = await Enumerate("avvisi di scadenza", ct).ConfigureAwait(false);
            if (users is null) return new JobResult("expiry", 0, 0, 1, "Directory non raggiungibile: dettagli nell'audit.");
            int sent = 0, failed = 0, due = 0;
            var now = DateTimeOffset.Now;
            foreach (var u in users)
            {
                if (u.PasswordExpires is not { } exp || exp <= now) continue;
                var left = (int)Math.Ceiling((exp - now).TotalDays);
                var bucket = days.FirstOrDefault(d => d >= left);
                if (bucket == 0) continue;
                if (AlreadyNotified(st.ExpirySent.GetValueOrDefault(u.Sid), exp, bucket)) continue;
                due++;
                try
                {
                    var du = await _ad.FindUserBySidAsync(u.Sid, ct).ConfigureAwait(false);
                    if (du is null || !du.Enabled || !AccountProtection.Evaluate(du, _portal.Scope).Manageable) continue;
                    var vars = new (string, object?)[] { ("user", du.SamAccountName), ("displayName", du.DisplayName ?? du.SamAccountName), ("days", left), ("expiry", exp.ToLocalTime().ToString("dd/MM/yyyy HH:mm", Inv)) };
                    var (subject, body, sms) = _texts.Notification("expiry", vars);
                    var targets = 0;
                    if (S.Expiry.ToCorporateEmail && _mail.Configured && !string.IsNullOrWhiteSpace(u.Mail)) { await _mail.SendAsync(u.Mail, subject, body, ct).ConfigureAwait(false); targets++; }
                    if (S.Expiry.ToRegisteredMethods)
                    {
                        var e = _codec.Decode(u.Attributes, u.Sid, out _);
                        if (e.Methods.Contains(VerificationMethod.Email) && _mail.Configured) { await _mail.SendAsync(e.Email!, subject, body, ct).ConfigureAwait(false); targets++; }
                        if (e.Methods.Contains(VerificationMethod.Sms) && _sms.Configured) { await _sms.SendAsync(e.Mobile!, subject, sms, ct).ConfigureAwait(false); targets++; }
                    }
                    if (targets == 0) continue;
                    st.ExpirySent[u.Sid] = $"{exp.ToString("yyyy-MM-dd", Inv)}|{bucket}";
                    sent++;
                    await _audit.WriteAsync(new AuditEntry(AuditEventId.ExpiryNotified, AuditOutcome.Success, du.SamAccountName, null, null, $"Avviso di scadenza password: {left} giorni ({targets} recapiti)"), ct).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    failed++;
                    _log.LogWarning(ex, "Avviso di scadenza non inviato a {User}", u.SamAccountName);
                }
            }
            // pulizia: restano solo gli utenti con una scadenza ancora futura
            var active = users.Where(x => x.PasswordExpires > now).Select(x => x.Sid).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var k in st.ExpirySent.Keys.Where(k => !active.Contains(k)).ToList()) st.ExpirySent.Remove(k);
            Save(st);
            var msg = $"Avvisi di scadenza{(force ? " (esecuzione manuale)" : "")}: {users.Count} utenti verificati, {due} da avvisare, {sent} avvisati, {failed} errori";
            await _audit.WriteAsync(new AuditEntry(AuditEventId.JobRun, failed > 0 ? AuditOutcome.Failure : AuditOutcome.Success, null, null, null, msg), ct).ConfigureAwait(false);
            return new JobResult("expiry", users.Count, sent, failed, msg);
        }
        finally { _gate.Release(); }
    }

    /// <summary>Inviti agli utenti non registrati, al massimo uno ogni IntervalDays per utente (anche con "Esegui ora").</summary>
    public async Task<JobResult> RunCampaignAsync(bool force, CancellationToken ct)
    {
        if (!await _gate.WaitAsync(0, ct).ConfigureAwait(false)) return new JobResult("campaign", 0, 0, 0, "Attivita' gia' in corso.");
        try
        {
            var st = Load();
            st.LastCampaignDay = DateTimeOffset.Now.ToString("yyyy-MM-dd", Inv);
            Save(st);
            if (!_mail.Configured) return new JobResult("campaign", 0, 0, 0, "SMTP non configurato.");
            if (!S.Features.EnrollmentEnabled) return new JobResult("campaign", 0, 0, 0, "Registrazione dei metodi disattivata: nessun invito.");
            var users = await Enumerate("campagna di registrazione", ct).ConfigureAwait(false);
            if (users is null) return new JobResult("campaign", 0, 0, 1, "Directory non raggiungibile: dettagli nell'audit.");
            var min = S.Verification.MinimumEnrolledMethods;
            var interval = TimeSpan.FromDays(Math.Clamp(S.Campaign.IntervalDays, 1, 365));
            var max = Math.Clamp(S.Campaign.MaxPerRun, 1, 5000);
            int sent = 0, failed = 0, pending = 0;
            var now = DateTimeOffset.UtcNow;
            foreach (var u in users)
            {
                if (string.IsNullOrWhiteSpace(u.Mail)) continue;
                var e = _codec.Decode(u.Attributes, u.Sid, out _);
                if (e.IsEnrolled(min)) { st.Invited.Remove(u.Sid); continue; }
                pending++;
                if (sent >= max) continue;
                if (st.Invited.TryGetValue(u.Sid, out var last) && now - last < interval) continue;
                try
                {
                    var du = await _ad.FindUserBySidAsync(u.Sid, ct).ConfigureAwait(false);
                    if (du is null || !du.Enabled || !AccountProtection.Evaluate(du, _portal.Scope).Manageable) { pending--; continue; }
                    var (subject, body, _) = _texts.Notification("invite", ("user", du.SamAccountName), ("displayName", du.DisplayName ?? du.SamAccountName));
                    await _mail.SendAsync(u.Mail, subject, body, ct).ConfigureAwait(false);
                    st.Invited[u.Sid] = now;
                    sent++;
                    await _audit.WriteAsync(new AuditEntry(AuditEventId.CampaignInvite, AuditOutcome.Success, du.SamAccountName, null, null, "Invito automatico a registrarsi"), ct).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    failed++;
                    _log.LogWarning(ex, "Invito non inviato a {User}", u.SamAccountName);
                }
            }
            Save(st);
            var msg = $"Campagna di registrazione{(force ? " (esecuzione manuale)" : "")}: {pending} utenti da registrare, {sent} invitati, {failed} errori";
            await _audit.WriteAsync(new AuditEntry(AuditEventId.JobRun, failed > 0 ? AuditOutcome.Failure : AuditOutcome.Success, null, null, null, msg), ct).ConfigureAwait(false);
            return new JobResult("campaign", users.Count, sent, failed, msg);
        }
        finally { _gate.Release(); }
    }
}
