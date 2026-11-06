using System.Security.Cryptography;
using FispaSspr.Core.Crypto;
using FispaSspr.Core.Model;
using Xunit;

namespace FispaSspr.Core.Tests;

public class SecretEnvelopeTests
{
    private const string Sid = "S-1-5-21-1111111111-2222222222-3333333333-1105";

    [Fact]
    public void Roundtrip_with_same_associated_data()
    {
        var key = MasterKey.Generate();
        var keys = new StaticMasterKeyProvider(key);
        var aad = SecretEnvelope.AssociatedData(SsprAttributes.Mobile, Sid);
        var env = SecretEnvelope.ProtectString("+393331234567", key, aad);
        Assert.StartsWith("v1:" + key.Id + ":", env);
        Assert.Equal("+393331234567", SecretEnvelope.UnprotectString(env, keys, aad));
    }

    [Fact]
    public void Same_plaintext_gives_different_ciphertexts()
    {
        var key = MasterKey.Generate();
        var aad = SecretEnvelope.AssociatedData(SsprAttributes.Email, Sid);
        Assert.NotEqual(SecretEnvelope.ProtectString("a@b.it", key, aad), SecretEnvelope.ProtectString("a@b.it", key, aad));
    }

    [Fact]
    public void Value_copied_to_another_user_or_attribute_does_not_decrypt()
    {
        var key = MasterKey.Generate();
        var keys = new StaticMasterKeyProvider(key);
        var env = SecretEnvelope.ProtectString("+393331234567", key, SecretEnvelope.AssociatedData(SsprAttributes.Mobile, Sid));
        Assert.ThrowsAny<CryptographicException>(() =>
            SecretEnvelope.UnprotectString(env, keys, SecretEnvelope.AssociatedData(SsprAttributes.Mobile, Sid.Replace("1105", "1106", StringComparison.Ordinal))));
        Assert.ThrowsAny<CryptographicException>(() =>
            SecretEnvelope.UnprotectString(env, keys, SecretEnvelope.AssociatedData(SsprAttributes.Email, Sid)));
    }

    [Fact]
    public void Tampered_value_does_not_decrypt()
    {
        var key = MasterKey.Generate();
        var keys = new StaticMasterKeyProvider(key);
        var aad = SecretEnvelope.AssociatedData(SsprAttributes.Totp, Sid);
        var env = SecretEnvelope.Protect(new byte[20], key, aad);
        var raw = Convert.FromBase64String(env.Split(':')[2]);
        raw[15] ^= 0x01;
        var tampered = $"v1:{key.Id}:{Convert.ToBase64String(raw)}";
        Assert.ThrowsAny<CryptographicException>(() => SecretEnvelope.Unprotect(tampered, keys, aad));
    }

    [Fact]
    public void Old_key_still_decrypts_after_rotation()
    {
        var oldKey = MasterKey.Generate();
        var newKey = MasterKey.Generate();
        var aad = SecretEnvelope.AssociatedData(SsprAttributes.Email, Sid);
        var env = SecretEnvelope.ProtectString("x@y.it", oldKey, aad);
        var keys = new StaticMasterKeyProvider(newKey, oldKey);
        Assert.Equal("x@y.it", SecretEnvelope.UnprotectString(env, keys, aad));
        Assert.Equal(oldKey.Id, SecretEnvelope.KeyIdOf(env));
    }

    [Theory]
    [InlineData("")]
    [InlineData("v2:abcdef01:AAAA")]
    [InlineData("v1:abcdef01")]
    [InlineData("v1:abcdef01:non-base64!")]
    public void Malformed_envelopes_are_rejected(string env)
    {
        var keys = new StaticMasterKeyProvider(new MasterKey("abcdef01", new byte[32]));
        Assert.ThrowsAny<CryptographicException>(() => SecretEnvelope.Unprotect(env, keys, "x"));
    }
}

public class EnrollmentCodecTests
{
    private const string Sid = "S-1-5-21-1111111111-2222222222-3333333333-1105";

    [Fact]
    public void Encode_and_decode_full_enrollment()
    {
        var keys = new StaticMasterKeyProvider(MasterKey.Generate());
        var codec = new EnrollmentCodec(keys);
        var now = DateTimeOffset.Parse("2026-11-06T10:00:00Z", System.Globalization.CultureInfo.InvariantCulture);
        var e = new Enrollment
        {
            TotpSecret = Enumerable.Range(1, 20).Select(i => (byte)i).ToArray(),
            Mobile = "+393331234567",
            Email = "mario.rossi@example.com",
            State = new EnrollmentState { EnrolledAt = now, TotpVerifiedAt = now, MobileVerifiedAt = now, EmailVerifiedAt = now, LastTotpStep = 42 },
        };
        var values = codec.Encode(e, Sid);
        Assert.All(SsprAttributes.All, a => Assert.StartsWith("v1:", values[a]));

        var back = codec.Decode(values, Sid, out var invalid);
        Assert.Empty(invalid);
        Assert.Equal(e.TotpSecret, back.TotpSecret);
        Assert.Equal(e.Mobile, back.Mobile);
        Assert.Equal(e.Email, back.Email);
        Assert.Equal(42, back.State.LastTotpStep);
        Assert.Equal(3, back.Methods.Count);
        Assert.True(back.IsEnrolled(2));
    }

    [Fact]
    public void Empty_enrollment_clears_attributes()
    {
        var codec = new EnrollmentCodec(new StaticMasterKeyProvider(MasterKey.Generate()));
        var values = codec.Encode(new Enrollment { State = new EnrollmentState() }, Sid);
        Assert.Null(values[SsprAttributes.Totp]);
        Assert.Null(values[SsprAttributes.Mobile]);
        Assert.Null(values[SsprAttributes.Email]);
        Assert.NotNull(values[SsprAttributes.State]);
    }

    [Fact]
    public void Values_of_another_user_are_reported_invalid_and_ignored()
    {
        var codec = new EnrollmentCodec(new StaticMasterKeyProvider(MasterKey.Generate()));
        var values = codec.Encode(new Enrollment { Mobile = "+393331234567", State = new EnrollmentState { MobileVerifiedAt = DateTimeOffset.UtcNow } }, Sid);
        var back = codec.Decode(values, Sid.Replace("1105", "1199", StringComparison.Ordinal), out var invalid);
        Assert.Null(back.Mobile);
        Assert.Contains(SsprAttributes.Mobile, invalid);
        Assert.Empty(back.Methods);
    }

    [Fact]
    public void Unverified_methods_do_not_count()
    {
        var e = new Enrollment { Mobile = "+393331234567", Email = "a@b.it", State = new EnrollmentState { EmailVerifiedAt = DateTimeOffset.UtcNow } };
        Assert.Equal(new[] { VerificationMethod.Email }, e.Methods);
        Assert.False(e.IsEnrolled(2));
    }

    [Fact]
    public void Needs_reencryption_after_key_rotation()
    {
        var oldKey = MasterKey.Generate();
        var values = new EnrollmentCodec(new StaticMasterKeyProvider(oldKey)).Encode(new Enrollment { Email = "a@b.it" }, Sid);
        var rotated = new EnrollmentCodec(new StaticMasterKeyProvider(MasterKey.Generate(), oldKey));
        Assert.True(rotated.NeedsReEncryption(values));
        Assert.False(new EnrollmentCodec(new StaticMasterKeyProvider(oldKey)).NeedsReEncryption(values));
    }
}
