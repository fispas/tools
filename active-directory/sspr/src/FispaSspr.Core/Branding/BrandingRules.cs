using System.Text;
using System.Text.RegularExpressions;
using FispaSspr.Core.Settings;

namespace FispaSspr.Core.Branding;

/// <summary>
/// Regole dell'aspetto personalizzabile: riconoscimento dei file caricati, controlli su colori, caratteri e CSS,
/// sostituzione dei segnaposto nei testi. Funzioni pure, senza accesso a disco.
/// </summary>
public static partial class BrandingRules
{
    public const int MaxImageBytes = 1024 * 1024;
    public const int MaxCssLength = 20000;

    /// <summary>Riconosce il formato dai byte (mai dall'estensione o dal Content-Type dichiarato) e rifiuta SVG con contenuti attivi.</summary>
    public static string DetectImageExtension(string asset, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (data.Length == 0 || data.Length > MaxImageBytes) throw new ArgumentException($"File vuoto o troppo grande (massimo {MaxImageBytes / 1024} KB).");
        bool Starts(params byte[] sig) => data.Length >= sig.Length && data.AsSpan(0, sig.Length).SequenceEqual(sig);
        string ext;
        if (Starts(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)) ext = ".png";
        else if (Starts(0xFF, 0xD8, 0xFF)) ext = ".jpg";
        else if (Starts(0x47, 0x49, 0x46, 0x38)) ext = ".gif";
        else if (data.Length > 12 && Starts(0x52, 0x49, 0x46, 0x46) && data.AsSpan(8, 4).SequenceEqual("WEBP"u8)) ext = ".webp";
        else if (Starts(0x00, 0x00, 0x01, 0x00)) ext = ".ico";
        else
        {
            var text = Encoding.UTF8.GetString(data);
            if (!SvgRoot().IsMatch(text)) throw new ArgumentException("Formato non riconosciuto: usare PNG, JPEG, WEBP, GIF, SVG o ICO.");
            if (SvgActive().IsMatch(text)) throw new ArgumentException("SVG non ammesso: contiene script, gestori di eventi, riferimenti esterni o contenuti incorporati.");
            ext = ".svg";
        }
        if (asset == "favicon" && ext is ".jpg" or ".webp") throw new ArgumentException("Per l'icona usare PNG, ICO o SVG.");
        return ext;
    }

    public static bool IsColor(string? v) => v is not null && Color().IsMatch(v);
    public static bool IsFont(string? v) => v is not null && Font().IsMatch(v);

    /// <summary>Controlli sul CSS personalizzato: niente chiusura del foglio, import, espressioni o URL esterni.</summary>
    public static string? CssProblem(string? css)
    {
        if (string.IsNullOrEmpty(css)) return null;
        if (css.Length > MaxCssLength) return $"CSS personalizzato troppo lungo (massimo {MaxCssLength} caratteri).";
        if (CssBad().IsMatch(css)) return "CSS personalizzato non ammesso: @import, expression(), javascript:, URL esterni e '<' non sono consentiti.";
        return null;
    }

    /// <summary>Sostituisce i segnaposto {nome}; quelli sconosciuti restano invariati.</summary>
    public static string Fill(string template, IReadOnlyDictionary<string, string> vars)
    {
        ArgumentNullException.ThrowIfNull(template);
        ArgumentNullException.ThrowIfNull(vars);
        return Placeholder().Replace(template, m => vars.TryGetValue(m.Groups[1].Value, out var v) ? v : m.Value);
    }

    /// <summary>Foglio di stile del tema: solo valori validati (i non validi tornano al predefinito).</summary>
    public static string ThemeCss(BrandingSettings b, bool hasBackground)
    {
        ArgumentNullException.ThrowIfNull(b);
        static string C(string? v, string def) => IsColor(v) ? v! : def;
        var d = new BrandingSettings();
        var inv = System.Globalization.CultureInfo.InvariantCulture;
        var sb = new StringBuilder();
        sb.Append(":root{")
          .Append("--accent:").Append(C(b.PrimaryColor, d.PrimaryColor)).Append(';')
          .Append("--accent-d:").Append(C(b.PrimaryDarkColor, d.PrimaryDarkColor)).Append(';')
          .Append("--bg:").Append(C(b.BackgroundColor, d.BackgroundColor)).Append(';')
          .Append("--card:").Append(C(b.CardColor, d.CardColor)).Append(';')
          .Append("--text:").Append(C(b.TextColor, d.TextColor)).Append(';')
          .Append("--muted:").Append(C(b.MutedColor, d.MutedColor)).Append(';')
          .Append("--header:").Append(C(b.HeaderColor, d.HeaderColor)).Append(';')
          .Append("--header-text:").Append(C(b.HeaderTextColor, d.HeaderTextColor)).Append(';')
          .Append("--ok:").Append(C(b.SuccessColor, d.SuccessColor)).Append(';')
          .Append("--err:").Append(C(b.ErrorColor, d.ErrorColor)).Append(';')
          .Append("--radius:").Append(Math.Clamp(b.CornerRadius, 0, 30).ToString(inv)).Append("px;")
          .Append("--logo-h:").Append(Math.Clamp(b.LogoHeight, 16, 160).ToString(inv)).Append("px;")
          .Append("--font:").Append(IsFont(b.FontFamily) ? b.FontFamily : d.FontFamily).Append(';')
          .Append("}\n");
        if (hasBackground)
            sb.Append("body{background-image:url('/branding/background');background-size:cover;background-attachment:fixed;background-position:center}\n");
        if (!string.IsNullOrWhiteSpace(b.CustomCss) && CssProblem(b.CustomCss) is null)
            sb.Append("/* personalizzato */\n").Append(b.CustomCss).Append('\n');
        return sb.ToString();
    }

    [GeneratedRegex(@"^\s*(<\?xml[^>]*>\s*)?(<!--.*?-->\s*)*(<!DOCTYPE svg[^>]*>\s*)?<svg[\s>]", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex SvgRoot();
    [GeneratedRegex(@"<script|<foreignObject|<iframe|<embed|<object|<!ENTITY|\son[a-z]+\s*=|javascript:|data:text/html|(?:href|src)\s*=\s*[""']?\s*(?:https?:|//)", RegexOptions.IgnoreCase)]
    private static partial Regex SvgActive();
    [GeneratedRegex(@"^#[0-9A-Fa-f]{6}$")]
    private static partial Regex Color();
    [GeneratedRegex(@"^[A-Za-z0-9 ,""'\-]{1,120}$")]
    private static partial Regex Font();
    [GeneratedRegex(@"@import|expression\s*\(|javascript:|behavior\s*:|-moz-binding|<|url\s*\(\s*[""']?\s*(?:https?:|//|data:(?!image/))", RegexOptions.IgnoreCase)]
    private static partial Regex CssBad();
    [GeneratedRegex(@"\{([A-Za-z][A-Za-z0-9]*)\}")]
    private static partial Regex Placeholder();
}
