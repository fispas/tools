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
    private readonly SettingsStore _settings;

    public TextCatalog(SettingsStore settings)
    {
        _settings = settings;
        Defaults = LoadDefaults();
    }

    public IReadOnlyDictionary<string, TextDef> Defaults { get; }

    internal static IReadOnlyDictionary<string, TextDef> LoadDefaults()
    {
        var asm = typeof(TextCatalog).Assembly;
        var name = asm.GetManifestResourceNames().First(n => n.EndsWith("texts.it.json", StringComparison.OrdinalIgnoreCase));
        using var stream = asm.GetManifestResourceStream(name)!;
        using var doc = JsonDocument.Parse(stream);
        var d = new Dictionary<string, TextDef>(StringComparer.Ordinal);
        foreach (var p in doc.RootElement.EnumerateObject())
            d[p.Name] = new TextDef(p.Value.GetProperty("g").GetString() ?? "", p.Value.GetProperty("t").GetString() ?? "", p.Value.GetProperty("d").GetString() ?? "");
        return d;
    }

    private SsprSettings S => _settings.Current;

    /// <summary>Testo senza segnaposto sostituiti.</summary>
    public string Raw(string key)
    {
        if (S.Branding.Texts.TryGetValue(key, out var custom) && !string.IsNullOrWhiteSpace(custom)) return custom;
        return Defaults.TryGetValue(key, out var def) ? def.Text : key;
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

    /// <summary>Testi per l'interfaccia (esclusi quelli delle notifiche).</summary>
    public Dictionary<string, string> ForClient()
    {
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var k in Defaults.Keys) if (!k.StartsWith("notify.", StringComparison.Ordinal)) d[k] = Raw(k);
        return d;
    }

    /// <summary>Pulisce i testi personalizzati in arrivo dal pannello: solo chiavi note, lunghezza limitata, niente copie del predefinito.</summary>
    public Dictionary<string, string> Sanitize(IReadOnlyDictionary<string, string>? texts, List<string> errors)
    {
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        if (texts is null) return d;
        foreach (var (k, v) in texts)
        {
            if (!Defaults.TryGetValue(k, out var def)) continue;
            var value = (v ?? string.Empty).Replace("\r\n", "\n", StringComparison.Ordinal);
            if (string.IsNullOrWhiteSpace(value) || value == def.Text) continue;
            if (value.Length > MaxTextLength) { errors.Add($"Testo {k} troppo lungo (massimo {MaxTextLength} caratteri)."); continue; }
            if (value.Any(c => char.IsControl(c) && c != '\n' && c != '\t')) { errors.Add($"Testo {k}: caratteri di controllo non ammessi."); continue; }
            d[k] = value;
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
