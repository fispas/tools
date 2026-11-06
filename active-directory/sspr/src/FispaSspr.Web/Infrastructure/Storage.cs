using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml.Linq;
using FispaSspr.Core.Crypto;
using FispaSspr.Core.Settings;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.Logging.Abstractions;

namespace FispaSspr.Web.Infrastructure;

public static class SsprPaths
{
    public static string Root { get; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FispaSSPR");
    public static string Config => Path.Combine(Root, "config.json");
    public static string Keys => Path.Combine(Root, "keys");
    public static string Audit => Path.Combine(Root, "audit");
    public static string AdminTotp => Path.Combine(Root, "admin-totp.json");

    public static void WriteAtomic(string path, string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, content, new UTF8Encoding(false));
        if (File.Exists(path)) File.Replace(tmp, path, path + ".bak", ignoreMetadataErrors: true);
        else File.Move(tmp, path);
    }
}

public static class Json
{
    public static JsonSerializerOptions Options { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };
}

/// <summary>
/// Chiavi master in %ProgramData%\FispaSSPR\keys, protette con DPAPI-NG verso il SID del gMSA:
/// le decifra solo un processo che gira come quel gMSA (vedi docs/crypto.md).
/// </summary>
public sealed class KeyStore : IMasterKeyProvider
{
    private readonly Dictionary<string, MasterKey> _keys = new(StringComparer.OrdinalIgnoreCase);
    private MasterKey? _current;

    public MasterKey Current => _current ?? throw new InvalidOperationException("Nessuna chiave master disponibile: eseguire l'installazione.");
    public MasterKey? Find(string id) => _keys.TryGetValue(id, out var k) ? k : null;
    public bool HasKey => _current is not null;
    public string? LoadError { get; private set; }

    public static KeyStore Load(string? folder = null)
    {
        var ks = new KeyStore();
        var dir = folder ?? SsprPaths.Keys;
        if (!Directory.Exists(dir)) { ks.LoadError = "Cartella delle chiavi assente."; return ks; }
        var decryptor = new DpapiNGXmlDecryptor();
        DateTimeOffset newest = DateTimeOffset.MinValue;
        foreach (var file in Directory.GetFiles(dir, "*.key"))
        {
            try
            {
                var doc = XElement.Load(file);
                var id = (string?)doc.Attribute("id") ?? throw new CryptographicException("id mancante");
                var created = DateTimeOffset.Parse((string?)doc.Attribute("created") ?? "2000-01-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture);
                var plain = decryptor.Decrypt(doc.Elements().First());
                var key = new MasterKey(id, Convert.FromBase64String(plain.Value));
                ks._keys[id] = key;
                if (created > newest) { newest = created; ks._current = key; }
            }
            catch (Exception ex) when (ex is CryptographicException or FormatException or InvalidOperationException or System.Xml.XmlException)
            {
                ks.LoadError = $"Chiave {Path.GetFileName(file)} non decifrabile: {ex.Message}";
            }
        }
        if (ks._current is null && ks.LoadError is null) ks.LoadError = "Nessuna chiave master trovata.";
        return ks;
    }

    /// <summary>Crea e salva una nuova chiave protetta verso <paramref name="serviceSid"/>. Usata dall'installer (come amministratore).</summary>
    public static MasterKey CreateKey(string serviceSid, string? folder = null)
    {
        if (string.IsNullOrWhiteSpace(serviceSid) || !serviceSid.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("SID del gMSA non valido.", nameof(serviceSid));
        var key = MasterKey.Generate();
        var encryptor = new DpapiNGXmlEncryptor($"SID={serviceSid}", DpapiNGProtectionDescriptorFlags.None, NullLoggerFactory.Instance);
        var info = encryptor.Encrypt(new XElement("secret", Convert.ToBase64String(KeyBytes(key))));
        var doc = new XElement("masterKey",
            new XAttribute("id", key.Id),
            new XAttribute("created", DateTimeOffset.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture)),
            new XAttribute("protectedTo", serviceSid),
            info.EncryptedElement);
        var dir = folder ?? SsprPaths.Keys;
        Directory.CreateDirectory(dir);
        doc.Save(Path.Combine(dir, key.Id + ".key"));
        return key;
    }

    internal static byte[] KeyBytes(MasterKey key) => key.Key;

    /// <summary>Backup della chiave cifrato con password: PBKDF2-SHA256 600.000 iterazioni + AES-256-GCM.</summary>
    public static void ExportBackup(MasterKey key, string password, string file)
    {
        if (string.IsNullOrEmpty(password) || password.Length < 12) throw new ArgumentException("La password del backup deve avere almeno 12 caratteri.");
        var salt = RandomNumberGenerator.GetBytes(16);
        var kek = Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000, HashAlgorithmName.SHA256, 32);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var plain = KeyBytes(key);
        var cipher = new byte[plain.Length];
        var tag = new byte[16];
        using (var aes = new AesGcm(kek, 16)) aes.Encrypt(nonce, plain, cipher, tag, Encoding.UTF8.GetBytes("FispaSSPR-backup|" + key.Id));
        var json = JsonSerializer.Serialize(new { v = 1, kid = key.Id, kdf = "PBKDF2-SHA256", iterations = 600_000, salt = Convert.ToBase64String(salt), nonce = Convert.ToBase64String(nonce), ct = Convert.ToBase64String(cipher), tag = Convert.ToBase64String(tag) });
        SsprPaths.WriteAtomic(file, json);
    }

    public static MasterKey ImportBackup(string file, string password)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(file));
        var r = doc.RootElement;
        var kid = r.GetProperty("kid").GetString()!;
        var kek = Rfc2898DeriveBytes.Pbkdf2(password, Convert.FromBase64String(r.GetProperty("salt").GetString()!), r.GetProperty("iterations").GetInt32(), HashAlgorithmName.SHA256, 32);
        var cipher = Convert.FromBase64String(r.GetProperty("ct").GetString()!);
        var plain = new byte[cipher.Length];
        using (var aes = new AesGcm(kek, 16))
            aes.Decrypt(Convert.FromBase64String(r.GetProperty("nonce").GetString()!), cipher, Convert.FromBase64String(r.GetProperty("tag").GetString()!), plain, Encoding.UTF8.GetBytes("FispaSSPR-backup|" + kid));
        return new MasterKey(kid, plain);
    }

    /// <summary>Riscrive una chiave importata da backup, protetta verso il SID del servizio.</summary>
    public static void SaveImported(MasterKey key, string serviceSid, string? folder = null)
    {
        var encryptor = new DpapiNGXmlEncryptor($"SID={serviceSid}", DpapiNGProtectionDescriptorFlags.None, NullLoggerFactory.Instance);
        var info = encryptor.Encrypt(new XElement("secret", Convert.ToBase64String(KeyBytes(key))));
        var dir = folder ?? SsprPaths.Keys;
        Directory.CreateDirectory(dir);
        new XElement("masterKey", new XAttribute("id", key.Id), new XAttribute("created", DateTimeOffset.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture)),
            new XAttribute("protectedTo", serviceSid), info.EncryptedElement).Save(Path.Combine(dir, key.Id + ".key"));
    }
}

/// <summary>Configurazione su file, ricaricabile. I segreti sono buste cifrate con la chiave master.</summary>
public sealed class SettingsStore
{
    private readonly object _lock = new();
    private SsprSettings _current;
    private readonly string _path;

    public SettingsStore(string? path = null)
    {
        _path = path ?? SsprPaths.Config;
        _current = File.Exists(_path) ? Read(_path) : new SsprSettings();
    }

    public SsprSettings Current { get { lock (_lock) return _current; } }

    public static SsprSettings Read(string path) =>
        JsonSerializer.Deserialize<SsprSettings>(File.ReadAllText(path), Json.Options) ?? new SsprSettings();

    public void Save(SsprSettings settings)
    {
        lock (_lock)
        {
            SsprPaths.WriteAtomic(_path, JsonSerializer.Serialize(settings, Json.Options));
            _current = settings;
        }
    }

    public static string SecretAad(string name) => "config|" + name;

    public static string? Decrypt(string? envelope, IMasterKeyProvider keys, string name) =>
        string.IsNullOrEmpty(envelope) ? null : SecretEnvelope.UnprotectString(envelope, keys, SecretAad(name));

    public static string? Encrypt(string? plain, MasterKey key, string name) =>
        string.IsNullOrEmpty(plain) ? null : SecretEnvelope.ProtectString(plain, key, SecretAad(name));
}
