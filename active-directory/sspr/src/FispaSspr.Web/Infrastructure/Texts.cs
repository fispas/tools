using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using FispaSspr.Core.Branding;
using FispaSspr.Core.Settings;

namespace FispaSspr.Web.Infrastructure;

public sealed record TextDef(string Group, string Text, string Description);

/// <summary>
/// Catalogo dei testi del portale, degli errori e delle notifiche (Texts/texts.it.json, incorporato).
/// I testi personalizzati dal pannello (Branding.Texts) sostituiscono quelli predefiniti, chiave per chiave.
/// I testi sono sempre testo semplice: l'interfaccia li inserisce con textContent, mai come HTML.
/// </summary>
public sealed partial class TextCatalog
{
    public const int MaxTextLength = 4000;
    public const string BaseLanguage = "it";
    private static readonly AsyncLocal<string?> _current = new();
    private readonly SettingsStore _settings;
    private readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, TextDef>> _catalogs;

    public TextCatalog(SettingsStore settings)
    {
        _settings = settings;
        _catalogs = LoadCatalogs();
        Defaults = _catalogs[BaseLanguage];
    }

    /// <summary>Catalogo della lingua base (chiavi, sezioni e descrizioni).</summary>
    public IReadOnlyDictionary<string, TextDef> Defaults { get; }

    public IReadOnlyList<string> SupportedLanguages => _catalogs.Keys.ToList();

    /// <summary>Lingua della richiesta in corso (impostata dal middleware); null = lingua predefinita.</summary>
    public static string? Current { get => _current.Value; set => _current.Value = value; }

    internal static IReadOnlyDictionary<string, IReadOnlyDictionary<string, TextDef>> LoadCatalogs()
    {
        var asm = typeof(TextCatalog).Assembly;
        var all = new Dictionary<string, IReadOnlyDictionary<string, TextDef>>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in asm.GetManifestResourceNames())
        {
            var m = ResourceName().Match(name);
            if (!m.Success) continue;
            using var stream = asm.GetManifestResourceStream(name)!;
            using var doc = JsonDocument.Parse(stream);
            var d = new Dictionary<string, TextDef>(StringComparer.Ordinal);
            foreach (var p in doc.RootElement.EnumerateObject())
                d[p.Name] = new TextDef(p.Value.GetProperty("g").GetString() ?? "", p.Value.GetProperty("t").GetString() ?? "", p.Value.GetProperty("d").GetString() ?? "");
            all[m.Groups[1].Value.ToLowerInvariant()] = d;
        }
        if (!all.ContainsKey(BaseLanguage)) throw new InvalidOperationException("Catalogo dei testi di base mancante.");
        return all;
    }

    private SsprSettings S => _settings.Current;

    /// <summary>Lingue attive: configurate e disponibili, la prima e' la predefinita.</summary>
    public IReadOnlyList<string> ActiveLanguages
    {
        get
        {
            var l = S.General.Languages.Select(x => x.ToLowerInvariant()).Where(_catalogs.ContainsKey).Distinct().ToList();
            if (l.Count == 0) l.Add(BaseLanguage);
            return l;
        }
    }

    public string DefaultLanguage => ActiveLanguages[0];

    public string Effective(string? lang = null)
    {
        var x = (lang ?? Current)?.ToLowerInvariant();
        return x is not null && ActiveLanguages.Contains(x) ? x : DefaultLanguage;
    }

    /// <summary>Testo senza segnaposto sostituiti, nella lingua indicata o in quella della richiesta.</summary>
    public string Raw(string key, string? lang = null)
    {
        var l = Effective(lang);
        var texts = S.Branding.Texts;
        if (texts.TryGetValue(l + ":" + key, out var c1) && !string.IsNullOrWhiteSpace(c1)) return c1;
        if (l == BaseLanguage && texts.TryGetValue(key, out var c2) && !string.IsNullOrWhiteSpace(c2)) return c2;
        if (_catalogs.TryGetValue(l, out var cat) && cat.TryGetValue(key, out var d1)) return d1.Text;
        return Defaults.TryGetValue(key, out var d2) ? d2.Text : key;
    }

    public string DefaultText(string key, string lang) =>
        _catalogs.TryGetValue(lang, out var cat) && cat.TryGetValue(key, out var d) ? d.Text : (Defaults.TryGetValue(key, out var b) ? b.Text : key);

    /// <summary>Testo personalizzato per una lingua (null se si usa il predefinito).</summary>
    public string? Custom(string key, string lang)
    {
        var texts = S.Branding.Texts;
        if (texts.TryGetValue(lang + ":" + key, out var c1)) return c1;
        if (lang == BaseLanguage && texts.TryGetValue(key, out var c2)) return c2;
        return null;
    }

    /// <summary>Testo con i segnaposto {nome}; {company}, {helpdesk} e {portalUrl} sono sempre disponibili.</summary>
    public string Get(string key, params (string Name, object? Value)[] vars)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["company"] = Company,
            ["helpdesk"] = Helpdesk,
            ["portalUrl"] = string.IsNullOrWhiteSpace(S.General.PortalUrl) ? Company : S.General.PortalUrl,
        };
        foreach (var (n, v) in vars) map[n] = Convert.ToString(v, System.Globalization.CultureInfo.CurrentCulture) ?? string.Empty;
        return Fill(Raw(key), map);
    }

    public string Company => string.IsNullOrWhiteSpace(S.General.CompanyName) ? Raw("ui.headerTitle") : S.General.CompanyName;
    public string Helpdesk => string.IsNullOrWhiteSpace(S.General.HelpdeskContact) ? Raw("ui.helpdeskDefault") : S.General.HelpdeskContact;

    public static string Fill(string template, IReadOnlyDictionary<string, string> vars) => BrandingRules.Fill(template, vars);

    /// <summary>Testi per l'interfaccia nella lingua indicata (esclusi quelli delle notifiche).</summary>
    public Dictionary<string, string> ForClient(string lang)
    {
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var k in Defaults.Keys) if (!k.StartsWith("notify.", StringComparison.Ordinal)) d[k] = Raw(k, lang);
        return d;
    }

    /// <summary>
    /// Pulisce i testi personalizzati in arrivo dal pannello: chiavi note ("chiave" per l'italiano, lingua base stabile anche se cambia la predefinita; "en:chiave" per le altre),
    /// lunghezza limitata, niente copie del testo predefinito.
    /// </summary>
    public Dictionary<string, string> Sanitize(IReadOnlyDictionary<string, string>? texts, List<string> errors)
    {
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        if (texts is null) return d;
        foreach (var (k, v) in texts)
        {
            var lang = BaseLanguage;
            var key = k;
            var i = k.IndexOf(':', StringComparison.Ordinal);
            if (i > 0 && i < 6)
            {
                lang = k[..i].ToLowerInvariant();
                key = k[(i + 1)..];
                if (!_catalogs.ContainsKey(lang)) continue;
            }
            if (!Defaults.ContainsKey(key)) continue;
            var value = (v ?? string.Empty).Replace("\r\n", "\n", StringComparison.Ordinal);
            if (string.IsNullOrWhiteSpace(value) || value == DefaultText(key, lang)) continue;
            if (value.Length > MaxTextLength) { errors.Add($"Testo {k} troppo lungo (massimo {MaxTextLength} caratteri)."); continue; }
            if (value.Any(c => char.IsControl(c) && c != '\n' && c != '\t')) { errors.Add($"Testo {k}: caratteri di controllo non ammessi."); continue; }
            d[lang == BaseLanguage ? key : lang + ":" + key] = value;
        }
        return d;
    }

    /// <summary>Notifica gia' composta: oggetto e testo email, testo SMS.</summary>
    public (string Subject, string Body, string Sms) Notification(string name, params (string Name, object? Value)[] vars)
    {
        var subject = Get($"notify.{name}.subject", vars).Replace("\r", " ", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal);
        var body = Get($"notify.{name}.body", vars);
        var smsKey = $"notify.{name}.sms";
        var sms = Defaults.ContainsKey(smsKey) ? Get(smsKey, vars) : subject;
        return (subject.Length > 200 ? subject[..200] : subject, body, sms);
    }

    [GeneratedRegex(@"texts\.([a-z]{2})\.json$", RegexOptions.IgnoreCase)]
    private static partial Regex ResourceName();
}

/// <summary>File dell'aspetto (logo, icona, sfondo) caricati dal pannello e foglio di stile del tema. Le regole sono in Core (BrandingRules).</summary>
public static partial class BrandingStore
{
    public const int MaxBytes = BrandingRules.MaxImageBytes;
    public static string Folder => Path.Combine(SsprPaths.Root, "branding");
    public static readonly string[] Assets = { "logo", "favicon", "background" };

    private static readonly Dictionary<string, string> Types = new(StringComparer.OrdinalIgnoreCase)
    {
        [".png"] = "image/png", [".jpg"] = "image/jpeg", [".webp"] = "image/webp", [".gif"] = "image/gif", [".svg"] = "image/svg+xml", [".ico"] = "image/x-icon",
    };

    public static string? ContentType(string file) => Types.TryGetValue(Path.GetExtension(file), out var t) ? t : null;

    public static string Save(string asset, byte[] data)
    {
        if (!Assets.Contains(asset)) throw new ArgumentException("Elemento non valido.");
        var ext = BrandingRules.DetectImageExtension(asset, data);
        Directory.CreateDirectory(Folder);
        foreach (var old in Directory.GetFiles(Folder, asset + ".*")) File.Delete(old);
        var file = asset + ext;
        var tmp = Path.Combine(Folder, file + ".tmp");
        File.WriteAllBytes(tmp, data);
        File.Move(tmp, Path.Combine(Folder, file), overwrite: true);
        return file;
    }

    public static void Delete(string asset)
    {
        if (!Assets.Contains(asset) || !Directory.Exists(Folder)) return;
        foreach (var old in Directory.GetFiles(Folder, asset + ".*")) File.Delete(old);
    }

    /// <summary>Percorso del file solo se il nome e' uno di quelli generati da Save (niente percorsi arbitrari).</summary>
    public static string? PathOf(string? file)
    {
        if (string.IsNullOrEmpty(file) || !SafeName().IsMatch(file)) return null;
        var p = Path.Combine(Folder, file);
        return File.Exists(p) ? p : null;
    }

    public static bool IsColor(string? v) => BrandingRules.IsColor(v);
    public static bool IsFont(string? v) => BrandingRules.IsFont(v);
    public static string? CssProblem(string? css) => BrandingRules.CssProblem(css);
    public static string ThemeCss(BrandingSettings b) => BrandingRules.ThemeCss(b, PathOf(b.BackgroundFile) is not null);

    [GeneratedRegex(@"^(logo|favicon|background)\.(png|jpg|webp|gif|svg|ico)$")]
    private static partial Regex SafeName();
}
