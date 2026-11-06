using System.Security.Cryptography;
using System.Text;

namespace FispaSspr.Core.Passwords;

public enum BreachCheckResult
{
    NotFound,
    Breached,
    /// <summary>Servizio non raggiungibile: il chiamante decide se bloccare o lasciar passare (configurazione).</summary>
    Unknown,
}

public interface IBreachedPasswordChecker
{
    Task<BreachCheckResult> CheckAsync(string password, CancellationToken cancellationToken = default);
}

/// <summary>Nessun controllo (configurazione "disattivato").</summary>
public sealed class NoBreachedPasswordChecker : IBreachedPasswordChecker
{
    public Task<BreachCheckResult> CheckAsync(string password, CancellationToken cancellationToken = default)
        => Task.FromResult(BreachCheckResult.NotFound);
}

internal static class Sha1Hex
{
#pragma warning disable CA5350 // SHA-1 e' il formato del database Pwned Passwords, non e' usato per proteggere dati
    public static string Of(string password) => Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
#pragma warning restore CA5350
}

/// <summary>
/// Pwned Passwords (haveibeenpwned.com) in modalita' k-anonymity: al servizio arrivano solo i primi
/// 5 caratteri dell'hash SHA-1, mai la password ne' l'hash completo. Con padding delle risposte.
/// </summary>
public sealed class HibpRangeChecker : IBreachedPasswordChecker
{
    private readonly HttpClient _http;
    private readonly Uri _baseUri;

    public HibpRangeChecker(HttpClient http, Uri? baseUri = null)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _baseUri = baseUri ?? new Uri("https://api.pwnedpasswords.com/range/");
    }

    public async Task<BreachCheckResult> CheckAsync(string password, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(password);
        var hash = Sha1Hex.Of(password);
        var prefix = hash[..5];
        var suffix = hash[5..];
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, new Uri(_baseUri, prefix));
            req.Headers.TryAddWithoutValidation("Add-Padding", "true");
            using var resp = await _http.SendAsync(req, cancellationToken).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return BreachCheckResult.Unknown;
            var body = await resp.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            return ParseRange(body, suffix) ? BreachCheckResult.Breached : BreachCheckResult.NotFound;
        }
        catch (HttpRequestException) { return BreachCheckResult.Unknown; }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested) { return BreachCheckResult.Unknown; }
    }

    /// <summary>Righe "SUFFISSO:CONTEGGIO"; le righe di padding hanno conteggio 0.</summary>
    internal static bool ParseRange(string body, string suffix)
    {
        foreach (var raw in body.Split('\n'))
        {
            var line = raw.Trim();
            var colon = line.IndexOf(':');
            if (colon <= 0) continue;
            if (!line.AsSpan(0, colon).Equals(suffix, StringComparison.OrdinalIgnoreCase)) continue;
            return long.TryParse(line.AsSpan(colon + 1), out var count) && count > 0;
        }
        return false;
    }
}

/// <summary>Lista offline di hash SHA-1 (una riga per hash, eventualmente "HASH:CONTEGGIO"), per server senza internet.</summary>
public sealed class OfflineListChecker : IBreachedPasswordChecker
{
    private readonly HashSet<string> _hashes;

    public OfflineListChecker(IEnumerable<string> sha1Lines)
    {
        ArgumentNullException.ThrowIfNull(sha1Lines);
        _hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in sha1Lines)
        {
            var line = raw.Trim();
            var colon = line.IndexOf(':');
            if (colon > 0) line = line[..colon];
            if (line.Length == 40) _hashes.Add(line);
        }
    }

    public static OfflineListChecker FromFile(string path) => new(File.ReadLines(path));

    public int Count => _hashes.Count;

    public Task<BreachCheckResult> CheckAsync(string password, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(password);
        return Task.FromResult(_hashes.Contains(Sha1Hex.Of(password)) ? BreachCheckResult.Breached : BreachCheckResult.NotFound);
    }
}
