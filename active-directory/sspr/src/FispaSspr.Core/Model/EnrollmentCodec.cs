using System.Text.Json;
using System.Text.Json.Serialization;
using FispaSspr.Core.Crypto;

namespace FispaSspr.Core.Model;

/// <summary>Nomi LDAP degli attributi (vedi docs/schema.md).</summary>
public static class SsprAttributes
{
    public const string Totp = "fispaSsprTotp";
    public const string Mobile = "fispaSsprMobile";
    public const string Email = "fispaSsprEmail";
    public const string State = "fispaSsprState";
    public const string AuxiliaryClass = "fispaSsprUser";

    public static IReadOnlyList<string> All { get; } = new[] { Totp, Mobile, Email, State };
}

/// <summary>
/// Converte i metodi registrati da/verso i valori cifrati degli attributi AD.
/// Ogni valore e' legato all'attributo e al SID dell'utente tramite i dati associati di AES-GCM.
/// </summary>
public sealed class EnrollmentCodec
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        WriteIndented = false,
    };

    private readonly IMasterKeyProvider _keys;

    public EnrollmentCodec(IMasterKeyProvider keys) => _keys = keys ?? throw new ArgumentNullException(nameof(keys));

    /// <summary>Valori da scrivere in AD. Null = attributo da svuotare.</summary>
    public IReadOnlyDictionary<string, string?> Encode(Enrollment enrollment, string userSid)
    {
        ArgumentNullException.ThrowIfNull(enrollment);
        ArgumentException.ThrowIfNullOrEmpty(userSid);
        var key = _keys.Current;
        string? Str(string attr, string? value) =>
            string.IsNullOrEmpty(value) ? null : SecretEnvelope.ProtectString(value, key, SecretEnvelope.AssociatedData(attr, userSid));

        return new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
        {
            [SsprAttributes.Totp] = enrollment.TotpSecret is { Length: > 0 } s
                ? SecretEnvelope.Protect(s, key, SecretEnvelope.AssociatedData(SsprAttributes.Totp, userSid))
                : null,
            [SsprAttributes.Mobile] = Str(SsprAttributes.Mobile, enrollment.Mobile),
            [SsprAttributes.Email] = Str(SsprAttributes.Email, enrollment.Email),
            [SsprAttributes.State] = Str(SsprAttributes.State, JsonSerializer.Serialize(enrollment.State, Json)),
        };
    }

    /// <summary>
    /// Legge i valori da AD. Un valore non decifrabile (alterato, chiave persa, copiato da un altro utente)
    /// viene scartato e segnalato in <paramref name="invalidAttributes"/>: l'utente dovra' registrare di nuovo quel metodo.
    /// </summary>
    public Enrollment Decode(IReadOnlyDictionary<string, string?> values, string userSid, out IReadOnlyList<string> invalidAttributes)
    {
        ArgumentNullException.ThrowIfNull(values);
        ArgumentException.ThrowIfNullOrEmpty(userSid);
        var invalid = new List<string>();

        byte[]? Bytes(string attr)
        {
            if (!values.TryGetValue(attr, out var v) || string.IsNullOrEmpty(v)) return null;
            try { return SecretEnvelope.Unprotect(v, _keys, SecretEnvelope.AssociatedData(attr, userSid)); }
            catch (System.Security.Cryptography.CryptographicException) { invalid.Add(attr); return null; }
        }
        string? Text(string attr) { var b = Bytes(attr); return b is null ? null : System.Text.Encoding.UTF8.GetString(b); }

        var state = new EnrollmentState();
        var stateJson = Text(SsprAttributes.State);
        if (stateJson is not null)
        {
            try { state = JsonSerializer.Deserialize<EnrollmentState>(stateJson, Json) ?? new EnrollmentState(); }
            catch (JsonException) { invalid.Add(SsprAttributes.State); }
        }

        invalidAttributes = invalid;
        return new Enrollment
        {
            TotpSecret = Bytes(SsprAttributes.Totp),
            Mobile = Text(SsprAttributes.Mobile),
            Email = Text(SsprAttributes.Email),
            State = state,
        };
    }

    /// <summary>True se almeno un valore e' cifrato con una chiave diversa da quella attiva (da ricifrare dopo una rotazione).</summary>
    public bool NeedsReEncryption(IReadOnlyDictionary<string, string?> values)
        => values.Values.Any(v => SecretEnvelope.KeyIdOf(v) is { } kid && !string.Equals(kid, _keys.Current.Id, StringComparison.OrdinalIgnoreCase));
}
