using System.Text;
using FispaSspr.Core.Otp;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace FispaSspr.Core.Tests;

public class TotpTests
{
    // RFC 6238, appendice B (HMAC-SHA1, segreto ASCII "12345678901234567890", 8 cifre)
    private static readonly byte[] RfcSecret = Encoding.ASCII.GetBytes("12345678901234567890");

    [Theory]
    [InlineData(59L, "94287082")]
    [InlineData(1111111109L, "07081804")]
    [InlineData(1111111111L, "14050471")]
    [InlineData(1234567890L, "89005924")]
    [InlineData(2000000000L, "69279037")]
    [InlineData(20000000000L, "65353130")]
    public void Generate_matches_rfc6238_vectors(long unixTime, string expected)
    {
        var step = Totp.TimeStep(DateTimeOffset.FromUnixTimeSeconds(unixTime));
        Assert.Equal(expected, Totp.Generate(RfcSecret, step, 8));
    }

    [Fact]
    public void Verify_accepts_current_and_adjacent_steps_and_returns_matched_step()
    {
        var secret = Totp.NewSecret();
        var now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
        var step = Totp.TimeStep(now);
        Assert.Equal(step, Totp.Verify(secret, Totp.Generate(secret, step), now, lastUsedStep: 0));
        Assert.Equal(step - 1, Totp.Verify(secret, Totp.Generate(secret, step - 1), now, lastUsedStep: 0));
        Assert.Equal(step + 1, Totp.Verify(secret, Totp.Generate(secret, step + 1), now, lastUsedStep: 0));
        Assert.Null(Totp.Verify(secret, Totp.Generate(secret, step + 2), now, lastUsedStep: 0));
    }

    [Fact]
    public void Verify_rejects_replay_of_used_step()
    {
        var secret = Totp.NewSecret();
        var now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
        var step = Totp.TimeStep(now);
        var code = Totp.Generate(secret, step);
        Assert.Null(Totp.Verify(secret, code, now, lastUsedStep: step));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("12a456")]
    public void Verify_rejects_malformed_codes(string? code)
    {
        Assert.Null(Totp.Verify(Totp.NewSecret(), code, DateTimeOffset.UtcNow, 0));
    }

    [Fact]
    public void ProvisioningUri_contains_base32_secret_and_issuer()
    {
        var secret = Encoding.ASCII.GetBytes("12345678901234567890");
        var uri = Totp.ProvisioningUri(secret, "Contoso SSPR", "utente.test@contoso.local");
        Assert.StartsWith("otpauth://totp/Contoso%20SSPR:utente.test%40contoso.local?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", uri);
        Assert.Contains("issuer=Contoso%20SSPR", uri);
    }
}

public class Base32Tests
{
    [Theory]
    [InlineData("", "")]
    [InlineData("f", "MY")]
    [InlineData("fo", "MZXQ")]
    [InlineData("foo", "MZXW6")]
    [InlineData("foob", "MZXW6YQ")]
    [InlineData("fooba", "MZXW6YTB")]
    [InlineData("foobar", "MZXW6YTBOI")]
    public void Encode_and_decode_rfc4648_vectors(string plain, string encoded)
    {
        var bytes = Encoding.ASCII.GetBytes(plain);
        Assert.Equal(encoded, Base32.Encode(bytes));
        Assert.Equal(bytes, Base32.Decode(encoded));
        Assert.Equal(bytes, Base32.Decode(encoded.ToLowerInvariant()));
    }

    [Fact]
    public void Decode_rejects_invalid_characters()
    {
        Assert.Throws<FormatException>(() => Base32.Decode("MZXW1"));
    }
}

public class OtpChallengeStoreTests
{
    [Fact]
    public void Correct_code_is_accepted_once()
    {
        var time = new FakeTimeProvider();
        var store = new OtpChallengeStore(time);
        var c = store.Create("utente|sessione", "sms", TimeSpan.FromMinutes(5));
        Assert.Equal(6, c.Code.Length);
        Assert.Equal(OtpVerifyResult.Ok, store.Verify(c.Id, "utente|sessione", c.Code));
        Assert.Equal(OtpVerifyResult.NotFound, store.Verify(c.Id, "utente|sessione", c.Code));
    }

    [Fact]
    public void Code_is_bound_to_subject()
    {
        var store = new OtpChallengeStore(new FakeTimeProvider());
        var c = store.Create("utente-a", "email", TimeSpan.FromMinutes(5));
        Assert.Equal(OtpVerifyResult.NotFound, store.Verify(c.Id, "utente-b", c.Code));
        Assert.Equal(OtpVerifyResult.Ok, store.Verify(c.Id, "utente-a", c.Code));
    }

    [Fact]
    public void Code_expires()
    {
        var time = new FakeTimeProvider();
        var store = new OtpChallengeStore(time);
        var c = store.Create("u", "sms", TimeSpan.FromMinutes(5));
        time.Advance(TimeSpan.FromMinutes(5));
        Assert.Equal(OtpVerifyResult.Expired, store.Verify(c.Id, "u", c.Code));
    }

    [Fact]
    public void Too_many_wrong_attempts_invalidate_the_challenge()
    {
        var store = new OtpChallengeStore(new FakeTimeProvider(), maxAttempts: 3);
        var c = store.Create("u", "sms", TimeSpan.FromMinutes(5));
        var wrong = c.Code == "000000" ? "111111" : "000000";
        Assert.Equal(OtpVerifyResult.Invalid, store.Verify(c.Id, "u", wrong));
        Assert.Equal(OtpVerifyResult.Invalid, store.Verify(c.Id, "u", wrong));
        Assert.Equal(OtpVerifyResult.TooManyAttempts, store.Verify(c.Id, "u", wrong));
        Assert.Equal(OtpVerifyResult.NotFound, store.Verify(c.Id, "u", c.Code));
    }

    [Fact]
    public void Max_attempts_follow_the_current_configuration()
    {
        var max = 5;
        var store = new OtpChallengeStore(new FakeTimeProvider(), () => max);
        var c = store.Create("u", "sms", TimeSpan.FromMinutes(5));
        var wrong = c.Code == "000000" ? "111111" : "000000";
        max = 2;
        Assert.Equal(OtpVerifyResult.Invalid, store.Verify(c.Id, "u", wrong));
        Assert.Equal(OtpVerifyResult.TooManyAttempts, store.Verify(c.Id, "u", wrong));
    }
}
