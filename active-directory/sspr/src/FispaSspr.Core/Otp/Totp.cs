using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace FispaSspr.Core.Otp;

/// <summary>TOTP RFC 6238 con HMAC-SHA1, compatibile con Microsoft/Google Authenticator e simili.</summary>
public static class Totp
{
    public const int DefaultDigits = 6;
    public const int DefaultPeriodSeconds = 30;
    public const int SecretSize = 20;

    private static readonly int[] Powers = { 1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000 };

    public static byte[] NewSecret() => RandomNumberGenerator.GetBytes(SecretSize);

    public static long TimeStep(DateTimeOffset time, int periodSeconds = DefaultPeriodSeconds)
        => time.ToUnixTimeSeconds() / periodSeconds;

    public static string Generate(ReadOnlySpan<byte> secret, long timeStep, int digits = DefaultDigits)
    {
        if (digits < 6 || digits > 8) throw new ArgumentOutOfRangeException(nameof(digits));
        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, timeStep);
        Span<byte> hash = stackalloc byte[20];
#pragma warning disable CA5350 // HMAC-SHA1 e' richiesto da RFC 6238 e dalle app di autenticazione; non e' usato come hash di sicurezza
        HMACSHA1.HashData(secret, counter, hash);
#pragma warning restore CA5350
        var offset = hash[19] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        return (binary % Powers[digits]).ToString("D" + digits, System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Verifica un codice accettando <paramref name="window"/> passi prima e dopo (orologi non allineati).
    /// I passi uguali o precedenti a <paramref name="lastUsedStep"/> vengono rifiutati (anti-replay).
    /// </summary>
    /// <returns>Il passo accettato, oppure null.</returns>
    public static long? Verify(ReadOnlySpan<byte> secret, string? code, DateTimeOffset now, long lastUsedStep,
        int window = 1, int digits = DefaultDigits, int periodSeconds = DefaultPeriodSeconds)
    {
        if (string.IsNullOrWhiteSpace(code)) return null;
        var normalized = code.Replace(" ", string.Empty, StringComparison.Ordinal);
        if (normalized.Length != digits || !normalized.All(char.IsAsciiDigit)) return null;
        var given = Encoding.ASCII.GetBytes(normalized);
        var current = TimeStep(now, periodSeconds);
        long? matched = null;
        // Si confrontano tutti i passi della finestra, senza uscire prima: tempo costante rispetto al passo corretto
        for (var d = -window; d <= window; d++)
        {
            var step = current + d;
            var expected = Encoding.ASCII.GetBytes(Generate(secret, step, digits));
            if (CryptographicOperations.FixedTimeEquals(expected, given) && step > lastUsedStep && matched is null)
                matched = step;
        }
        return matched;
    }

    /// <summary>URI otpauth:// per il QR code delle app di autenticazione.</summary>
    public static string ProvisioningUri(ReadOnlySpan<byte> secret, string issuer, string account,
        int digits = DefaultDigits, int periodSeconds = DefaultPeriodSeconds)
    {
        var label = Uri.EscapeDataString(issuer) + ":" + Uri.EscapeDataString(account);
        return $"otpauth://totp/{label}?secret={Base32.Encode(secret)}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits={digits}&period={periodSeconds}";
    }
}
