using System.Security.Cryptography;
using System.Text;

namespace FispaSspr.Core.Otp;

public enum OtpVerifyResult
{
    Ok,
    Invalid,
    Expired,
    TooManyAttempts,
    NotFound,
}

/// <summary>Sfida inviata via SMS o email: in memoria si conserva solo l'HMAC del codice.</summary>
public sealed record OtpChallenge(string Id, string Code, DateTimeOffset ExpiresAt);

/// <summary>
/// Codici monouso a 6 cifre per SMS ed email. In memoria, legati al soggetto (utente + sessione),
/// con scadenza e numero massimo di tentativi. I codici in chiaro non vengono mai conservati.
/// </summary>
public sealed class OtpChallengeStore
{
    private sealed class Entry
    {
        public required string Subject { get; init; }
        public required string Channel { get; init; }
        public required byte[] CodeHash { get; init; }
        public required DateTimeOffset ExpiresAt { get; init; }
        public int Attempts { get; set; }
    }

    private readonly TimeProvider _time;
    private readonly byte[] _hmacKey;
    private readonly int _maxAttempts;
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly object _lock = new();

    public OtpChallengeStore(TimeProvider time, int maxAttempts = 5, byte[]? hmacKey = null)
    {
        _time = time ?? throw new ArgumentNullException(nameof(time));
        ArgumentOutOfRangeException.ThrowIfLessThan(maxAttempts, 1);
        _maxAttempts = maxAttempts;
        _hmacKey = hmacKey ?? RandomNumberGenerator.GetBytes(32);
    }

    public int Count { get { lock (_lock) { return _entries.Count; } } }

    public OtpChallenge Create(string subject, string channel, TimeSpan ttl)
    {
        ArgumentException.ThrowIfNullOrEmpty(subject);
        ArgumentException.ThrowIfNullOrEmpty(channel);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(ttl, TimeSpan.Zero);
        var id = Convert.ToBase64String(RandomNumberGenerator.GetBytes(18)).Replace('+', '-').Replace('/', '_');
        var code = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
        var expires = _time.GetUtcNow().Add(ttl);
        lock (_lock)
        {
            Purge();
            _entries[id] = new Entry { Subject = subject, Channel = channel, CodeHash = Hash(id, code), ExpiresAt = expires };
        }
        return new OtpChallenge(id, code, expires);
    }

    public OtpVerifyResult Verify(string id, string subject, string? code)
    {
        if (string.IsNullOrEmpty(id)) return OtpVerifyResult.NotFound;
        lock (_lock)
        {
            if (!_entries.TryGetValue(id, out var e) || !string.Equals(e.Subject, subject, StringComparison.Ordinal))
                return OtpVerifyResult.NotFound;
            if (_time.GetUtcNow() >= e.ExpiresAt)
            {
                _entries.Remove(id);
                return OtpVerifyResult.Expired;
            }
            var normalized = (code ?? string.Empty).Trim();
            if (CryptographicOperations.FixedTimeEquals(e.CodeHash, Hash(id, normalized)))
            {
                _entries.Remove(id);
                return OtpVerifyResult.Ok;
            }
            e.Attempts++;
            if (e.Attempts >= _maxAttempts)
            {
                _entries.Remove(id);
                return OtpVerifyResult.TooManyAttempts;
            }
            return OtpVerifyResult.Invalid;
        }
    }

    public void Revoke(string id)
    {
        lock (_lock) { _entries.Remove(id); }
    }

    private byte[] Hash(string id, string code) => HMACSHA256.HashData(_hmacKey, Encoding.UTF8.GetBytes(id + ":" + code));

    private void Purge()
    {
        var now = _time.GetUtcNow();
        foreach (var k in _entries.Where(kv => kv.Value.ExpiresAt <= now).Select(kv => kv.Key).ToList())
            _entries.Remove(k);
    }
}
