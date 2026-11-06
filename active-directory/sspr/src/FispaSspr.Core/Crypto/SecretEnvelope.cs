using System.Security.Cryptography;
using System.Text;

namespace FispaSspr.Core.Crypto;

/// <summary>Chiave master con il suo identificativo (8 caratteri esadecimali).</summary>
public sealed class MasterKey
{
    public MasterKey(string id, byte[] key)
    {
        if (string.IsNullOrWhiteSpace(id) || id.Length != 8 || !id.All(Uri.IsHexDigit))
            throw new ArgumentException("L'id della chiave deve essere di 8 caratteri esadecimali.", nameof(id));
        if (key is null || key.Length != 32)
            throw new ArgumentException("La chiave master deve essere di 32 byte.", nameof(key));
        Id = id.ToLowerInvariant();
        Key = key;
    }

    public string Id { get; }
    internal byte[] Key { get; }

    public static MasterKey Generate()
    {
        var id = Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant();
        return new MasterKey(id, RandomNumberGenerator.GetBytes(32));
    }
}

/// <summary>Fornisce la chiave attiva (per cifrare) e tutte le chiavi note (per decifrare).</summary>
public interface IMasterKeyProvider
{
    MasterKey Current { get; }
    MasterKey? Find(string id);
}

public sealed class StaticMasterKeyProvider : IMasterKeyProvider
{
    private readonly Dictionary<string, MasterKey> _keys;

    public StaticMasterKeyProvider(MasterKey current, params MasterKey[] previous)
    {
        Current = current ?? throw new ArgumentNullException(nameof(current));
        _keys = previous.Append(current).ToDictionary(k => k.Id, StringComparer.OrdinalIgnoreCase);
    }

    public MasterKey Current { get; }
    public MasterKey? Find(string id) => _keys.TryGetValue(id, out var k) ? k : null;
}

/// <summary>
/// Busta AES-256-GCM: v1:&lt;kid&gt;:base64(nonce[12] | ciphertext | tag[16]).
/// I dati associati legano il valore all'attributo e all'utente (vedi docs/crypto.md).
/// </summary>
public static class SecretEnvelope
{
    private const string Version = "v1";
    private const int NonceSize = 12;
    private const int TagSize = 16;

    public static string AssociatedData(string attributeName, string userSid) => $"{attributeName}|{userSid}";

    public static string Protect(ReadOnlySpan<byte> plaintext, MasterKey key, string associatedData)
    {
        ArgumentNullException.ThrowIfNull(key);
        var aad = Encoding.UTF8.GetBytes(associatedData ?? throw new ArgumentNullException(nameof(associatedData)));
        var buffer = new byte[NonceSize + plaintext.Length + TagSize];
        var nonce = buffer.AsSpan(0, NonceSize);
        var cipher = buffer.AsSpan(NonceSize, plaintext.Length);
        var tag = buffer.AsSpan(NonceSize + plaintext.Length, TagSize);
        RandomNumberGenerator.Fill(nonce);
        using (var aes = new AesGcm(key.Key, TagSize))
        {
            aes.Encrypt(nonce, plaintext, cipher, tag, aad);
        }
        return $"{Version}:{key.Id}:{Convert.ToBase64String(buffer)}";
    }

    public static string ProtectString(string plaintext, MasterKey key, string associatedData)
        => Protect(Encoding.UTF8.GetBytes(plaintext ?? throw new ArgumentNullException(nameof(plaintext))), key, associatedData);

    /// <exception cref="CryptographicException">Valore alterato, chiave sbagliata o dati associati diversi.</exception>
    public static byte[] Unprotect(string envelope, IMasterKeyProvider keys, string associatedData)
    {
        ArgumentNullException.ThrowIfNull(keys);
        if (string.IsNullOrEmpty(envelope)) throw new CryptographicException("Valore vuoto.");
        var parts = envelope.Split(':', 3);
        if (parts.Length != 3 || parts[0] != Version) throw new CryptographicException("Formato della busta non riconosciuto.");
        var key = keys.Find(parts[1]) ?? throw new CryptographicException($"Chiave master '{parts[1]}' non disponibile.");
        byte[] buffer;
        try { buffer = Convert.FromBase64String(parts[2]); }
        catch (FormatException ex) { throw new CryptographicException("Busta non in base64.", ex); }
        if (buffer.Length < NonceSize + TagSize) throw new CryptographicException("Busta troppo corta.");

        var nonce = buffer.AsSpan(0, NonceSize);
        var cipherLength = buffer.Length - NonceSize - TagSize;
        var cipher = buffer.AsSpan(NonceSize, cipherLength);
        var tag = buffer.AsSpan(NonceSize + cipherLength, TagSize);
        var plain = new byte[cipherLength];
        var aad = Encoding.UTF8.GetBytes(associatedData ?? throw new ArgumentNullException(nameof(associatedData)));
        using (var aes = new AesGcm(key.Key, TagSize))
        {
            aes.Decrypt(nonce, cipher, tag, plain, aad);
        }
        return plain;
    }

    public static string UnprotectString(string envelope, IMasterKeyProvider keys, string associatedData)
        => Encoding.UTF8.GetString(Unprotect(envelope, keys, associatedData));

    /// <summary>Id della chiave usata per una busta (per sapere se va ricifrata dopo una rotazione).</summary>
    public static string? KeyIdOf(string? envelope)
    {
        if (string.IsNullOrEmpty(envelope)) return null;
        var parts = envelope.Split(':', 3);
        return parts.Length == 3 && parts[0] == Version ? parts[1] : null;
    }
}
