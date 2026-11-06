namespace FispaSspr.Core.Security;

/// <summary>
/// Limitatore a finestra scorrevole per chiave (utente, IP, globale). In memoria, thread-safe.
/// Un tentativo rifiutato non viene conteggiato, cosi' l'attesa non si allunga all'infinito.
/// </summary>
public sealed class SlidingWindowRateLimiter
{
    private readonly TimeProvider _time;
    private readonly Dictionary<string, Queue<DateTimeOffset>> _hits = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    public SlidingWindowRateLimiter(TimeProvider time) => _time = time ?? throw new ArgumentNullException(nameof(time));

    /// <summary>Registra un tentativo se c'e' spazio nella finestra. Restituisce false se il limite e' raggiunto.</summary>
    public bool TryAcquire(string key, int limit, TimeSpan window)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        if (limit < 1) throw new ArgumentOutOfRangeException(nameof(limit));
        var now = _time.GetUtcNow();
        lock (_lock)
        {
            if (!_hits.TryGetValue(key, out var q)) _hits[key] = q = new Queue<DateTimeOffset>();
            while (q.Count > 0 && now - q.Peek() >= window) q.Dequeue();
            if (q.Count >= limit) return false;
            q.Enqueue(now);
            return true;
        }
    }

    /// <summary>Quanto manca prima che si liberi un posto (zero se c'e' gia' spazio).</summary>
    public TimeSpan RetryAfter(string key, int limit, TimeSpan window)
    {
        var now = _time.GetUtcNow();
        lock (_lock)
        {
            if (!_hits.TryGetValue(key, out var q)) return TimeSpan.Zero;
            while (q.Count > 0 && now - q.Peek() >= window) q.Dequeue();
            if (q.Count < limit) return TimeSpan.Zero;
            return q.Peek() + window - now;
        }
    }

    public void Reset(string key)
    {
        lock (_lock) { _hits.Remove(key); }
    }

    /// <summary>Rimuove le chiavi senza tentativi recenti (da chiamare periodicamente).</summary>
    public void Purge(TimeSpan olderThan)
    {
        var now = _time.GetUtcNow();
        lock (_lock)
        {
            foreach (var k in _hits.Where(kv => kv.Value.Count == 0 || now - kv.Value.Last() >= olderThan).Select(kv => kv.Key).ToList())
                _hits.Remove(k);
        }
    }
}
