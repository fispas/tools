using FispaSspr.Core.Model;
using FispaSspr.Core.Passwords;
using FispaSspr.Core.Policy;
using FispaSspr.Core.Security;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace FispaSspr.Core.Tests;

public class AccountProtectionTests
{
    private const string Domain = "S-1-5-21-1111111111-2222222222-3333333333";
    private static readonly ScopeSettings Scope = new() { AllowedOus = new[] { "OU=Utenti,DC=contoso,DC=local" } };

    private static DirectoryUser User(Action<List<string>>? groups = null, int adminCount = 0, string dn = "CN=Mario Rossi,OU=Uffici,OU=Utenti,DC=contoso,DC=local", string rid = "1105", string[]? classes = null)
    {
        var g = new List<string> { Domain + "-513" };
        groups?.Invoke(g);
        return new DirectoryUser
        {
            Sid = Domain + "-" + rid,
            SamAccountName = "mario.rossi",
            DistinguishedName = dn,
            AdminCount = adminCount,
            GroupSids = g,
            ObjectClasses = classes ?? new[] { "top", "person", "organizationalPerson", "user" },
        };
    }

    [Fact]
    public void Normal_user_in_scope_is_manageable() => Assert.True(AccountProtection.Evaluate(User(), Scope).Manageable);

    [Fact]
    public void User_outside_allowed_ous_is_not_manageable()
        => Assert.False(AccountProtection.Evaluate(User(dn: "CN=Mario Rossi,OU=Altro,DC=contoso,DC=local"), Scope).Manageable);

    [Fact]
    public void Ou_match_requires_full_rdn_boundary()
        => Assert.False(AccountProtection.Evaluate(User(dn: "CN=X,OU=FintiUtenti,DC=contoso,DC=local"), new ScopeSettings { AllowedOus = new[] { "Utenti,DC=contoso,DC=local" } }).Manageable);

    [Fact]
    public void No_allowed_ous_means_nobody_is_manageable()
        => Assert.False(AccountProtection.Evaluate(User(), new ScopeSettings()).Manageable);

    [Theory]
    [InlineData("-512")]
    [InlineData("-519")]
    [InlineData("-525")]
    public void Members_of_privileged_domain_groups_are_protected(string rid)
        => Assert.False(AccountProtection.Evaluate(User(g => g.Add(Domain + rid)), Scope).Manageable);

    [Theory]
    [InlineData("S-1-5-32-544")]
    [InlineData("S-1-5-32-548")]
    [InlineData("S-1-5-32-551")]
    public void Members_of_privileged_builtin_groups_are_protected(string sid)
        => Assert.False(AccountProtection.Evaluate(User(g => g.Add(sid)), Scope).Manageable);

    [Fact]
    public void AdminCount_accounts_are_protected() => Assert.False(AccountProtection.Evaluate(User(adminCount: 1), Scope).Manageable);

    [Fact]
    public void Builtin_administrator_is_protected() => Assert.False(AccountProtection.Evaluate(User(rid: "500"), Scope).Manageable);

    [Fact]
    public void Managed_service_accounts_are_protected()
        => Assert.False(AccountProtection.Evaluate(User(classes: new[] { "top", "user", "computer", "msDS-GroupManagedServiceAccount" }), Scope).Manageable);

    [Fact]
    public void Excluded_groups_are_respected()
    {
        var scope = Scope with { ExcludedGroupSids = new[] { Domain + "-3001" } };
        Assert.False(AccountProtection.Evaluate(User(g => g.Add(Domain + "-3001")), scope).Manageable);
    }
}

public class PasswordPolicyTests
{
    private static readonly PasswordContext Ctx = new("mario.rossi", "Mario Rossi");

    [Fact]
    public void Strong_password_passes()
        => Assert.Empty(PasswordPolicy.Validate("Cavallo-Batteria-27", new PasswordRules(), Ctx));

    [Fact]
    public void Too_short_fails()
        => Assert.NotEmpty(PasswordPolicy.Validate("Ab1!xyz", new PasswordRules { MinLength = 12 }, Ctx));

    [Fact]
    public void Low_complexity_fails()
        => Assert.NotEmpty(PasswordPolicy.Validate("tuttominuscolelungo", new PasswordRules(), Ctx));

    [Theory]
    [InlineData("Mario.Rossi.2026!")]
    [InlineData("xx-Rossi-Tempo99")]
    public void Password_containing_name_fails(string pwd)
        => Assert.NotEmpty(PasswordPolicy.Validate(pwd, new PasswordRules(), Ctx));

    [Theory]
    [InlineData("Contoso-2026-Inverno")]
    [InlineData("C0nt0s0-2026-Inverno")]
    public void Banned_words_fail_also_in_leet_form(string pwd)
        => Assert.NotEmpty(PasswordPolicy.Validate(pwd, new PasswordRules { BannedWords = new[] { "contoso" } }, Ctx));

    [Fact]
    public void Categories_follow_windows_rules()
    {
        Assert.Equal(1, PasswordPolicy.Categories("abc"));
        Assert.Equal(4, PasswordPolicy.Categories("aB3!"));
    }
}

public class BreachedPasswordTests
{
    // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    [Fact]
    public void Range_response_is_parsed_and_padding_ignored()
    {
        var body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\nAAAA000000000000000000000000000000:0\r\n";
        Assert.True(HibpRangeChecker.ParseRange(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"));
        Assert.False(HibpRangeChecker.ParseRange(body, "AAAA000000000000000000000000000000"));
        Assert.False(HibpRangeChecker.ParseRange(body, "BBBB000000000000000000000000000000"));
    }

    [Fact]
    public async Task Offline_list_detects_known_hash()
    {
        var checker = new OfflineListChecker(new[] { "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:100", "garbage" });
        Assert.Equal(1, checker.Count);
        Assert.Equal(BreachCheckResult.Breached, await checker.CheckAsync("password"));
        Assert.Equal(BreachCheckResult.NotFound, await checker.CheckAsync("Cavallo-Batteria-27"));
    }
}

public class SecurityHelpersTests
{
    [Theory]
    [InlineData("+393331234567", "+39 *** *** 567")]
    [InlineData("3331234567", "*** *** 567")]
    [InlineData("", "")]
    public void Phone_masking(string input, string expected) => Assert.Equal(expected, Masking.Phone(input));

    [Theory]
    [InlineData("mario.rossi@gmail.com", "m***@g***.com")]
    [InlineData("a@b", "a***@b***")]
    [InlineData("bad", "***")]
    public void Email_masking(string input, string expected) => Assert.Equal(expected, Masking.Email(input));

    [Theory]
    [InlineData("333 123 4567", "+393331234567")]
    [InlineData("+39 333-123-4567", "+393331234567")]
    [InlineData("0039 3331234567", "+393331234567")]
    [InlineData("12", null)]
    [InlineData("333abc", null)]
    public void Phone_normalization(string input, string? expected) => Assert.Equal(expected, Normalization.Phone(input));

    [Theory]
    [InlineData("Mario.Rossi@Example.COM", "Mario.Rossi@example.com")]
    [InlineData("no-at-sign", null)]
    [InlineData("a b@c.it", null)]
    public void Email_normalization(string input, string? expected) => Assert.Equal(expected, Normalization.Email(input));

    [Theory]
    [InlineData("CONTOSO\\mario.rossi", "mario.rossi")]
    [InlineData("mario.rossi@contoso.local", "mario.rossi@contoso.local")]
    [InlineData("mario*", null)]
    [InlineData("a)(objectClass=*", null)]
    public void User_name_normalization_blocks_ldap_injection(string input, string? expected)
        => Assert.Equal(expected, Normalization.UserName(input));

    [Fact]
    public void Rate_limiter_blocks_and_releases_with_time()
    {
        var time = new FakeTimeProvider();
        var rl = new SlidingWindowRateLimiter(time);
        for (var i = 0; i < 3; i++) Assert.True(rl.TryAcquire("u", 3, TimeSpan.FromMinutes(10)));
        Assert.False(rl.TryAcquire("u", 3, TimeSpan.FromMinutes(10)));
        Assert.True(rl.RetryAfter("u", 3, TimeSpan.FromMinutes(10)) > TimeSpan.Zero);
        time.Advance(TimeSpan.FromMinutes(10));
        Assert.True(rl.TryAcquire("u", 3, TimeSpan.FromMinutes(10)));
    }
}
