using System.Text;
using FispaSspr.Core.Branding;
using FispaSspr.Core.Settings;
using Xunit;

namespace FispaSspr.Core.Tests;

public class BrandingTests
{
    private static readonly byte[] Png = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0x0D };

    [Fact]
    public void Image_type_comes_from_bytes_not_from_name()
    {
        Assert.Equal(".png", BrandingRules.DetectImageExtension("logo", Png));
        Assert.Equal(".jpg", BrandingRules.DetectImageExtension("logo", new byte[] { 0xFF, 0xD8, 0xFF, 0xE0, 1, 2 }));
        Assert.Equal(".ico", BrandingRules.DetectImageExtension("favicon", new byte[] { 0, 0, 1, 0, 1, 0 }));
        Assert.Throws<ArgumentException>(() => BrandingRules.DetectImageExtension("logo", Encoding.UTF8.GetBytes("MZ eseguibile")));
        Assert.Throws<ArgumentException>(() => BrandingRules.DetectImageExtension("logo", Array.Empty<byte>()));
        Assert.Throws<ArgumentException>(() => BrandingRules.DetectImageExtension("logo", new byte[BrandingRules.MaxImageBytes + 1]));
    }

    [Fact]
    public void Favicon_rejects_jpeg()
    {
        Assert.Throws<ArgumentException>(() => BrandingRules.DetectImageExtension("favicon", new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 }));
    }

    [Fact]
    public void Clean_svg_is_accepted()
    {
        var svg = "<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 10 10\"><rect width=\"10\" height=\"10\" fill=\"#123456\"/></svg>";
        Assert.Equal(".svg", BrandingRules.DetectImageExtension("logo", Encoding.UTF8.GetBytes(svg)));
    }

    [Theory]
    [InlineData("<svg><script>alert(1)</script></svg>")]
    [InlineData("<svg onload=\"alert(1)\"></svg>")]
    [InlineData("<svg><foreignObject><body/></foreignObject></svg>")]
    [InlineData("<svg><image href=\"https://evil.example/x.png\"/></svg>")]
    [InlineData("<svg><a href=\"javascript:alert(1)\">x</a></svg>")]
    [InlineData("<!DOCTYPE svg [<!ENTITY x SYSTEM \"file:///c:/windows/win.ini\">]><svg>&x;</svg>")]
    [InlineData("<svg><use href=\"//evil.example/a.svg#x\"/></svg>")]
    public void Active_svg_is_rejected(string svg)
    {
        Assert.Throws<ArgumentException>(() => BrandingRules.DetectImageExtension("logo", Encoding.UTF8.GetBytes(svg)));
    }

    [Theory]
    [InlineData("#1d4ed8", true)]
    [InlineData("#FFFFFF", true)]
    [InlineData("red", false)]
    [InlineData("#fff", false)]
    [InlineData("#123456;}body{display:none", false)]
    [InlineData(null, false)]
    public void Colors_are_strict(string? value, bool ok) => Assert.Equal(ok, BrandingRules.IsColor(value));

    [Theory]
    [InlineData("\"Segoe UI\", Arial, sans-serif", true)]
    [InlineData("Arial;}*{display:none}", false)]
    [InlineData("url(x)", false)]
    public void Fonts_are_strict(string value, bool ok) => Assert.Equal(ok, BrandingRules.IsFont(value));

    [Theory]
    [InlineData(".choice b{font-size:18px}", true)]
    [InlineData("header{background:url('/branding/logo')}", true)]
    [InlineData("@import url(https://evil.example/x.css);", false)]
    [InlineData("body{background:url(https://evil.example/t.png)}", false)]
    [InlineData("body{background:url(//evil.example/t.png)}", false)]
    [InlineData("</style><script>alert(1)</script>", false)]
    [InlineData("div{width:expression(alert(1))}", false)]
    [InlineData("a{background:url(data:text/html,x)}", false)]
    public void Custom_css_rules(string css, bool ok) => Assert.Equal(ok, BrandingRules.CssProblem(css) is null);

    [Fact]
    public void Theme_falls_back_to_defaults_for_invalid_values()
    {
        var b = new BrandingSettings { PrimaryColor = "#abcdef", TextColor = "red;}x{", CornerRadius = 99, CustomCss = "@import url(x)" };
        var css = BrandingRules.ThemeCss(b, hasBackground: false);
        Assert.Contains("--accent:#abcdef;", css);
        Assert.Contains("--text:" + new BrandingSettings().TextColor + ";", css);
        Assert.Contains("--radius:30px;", css);
        Assert.DoesNotContain("@import", css);
        Assert.DoesNotContain("background-image", css);
    }

    [Fact]
    public void Placeholders_are_replaced_only_when_known()
    {
        var vars = new Dictionary<string, string> { ["company"] = "Contoso", ["code"] = "123456" };
        Assert.Equal("Contoso: 123456 {unknown}", BrandingRules.Fill("{company}: {code} {unknown}", vars));
        Assert.Equal("{1x} { company}", BrandingRules.Fill("{1x} { company}", vars));
    }
}
