using System.Text;

namespace FispaSspr.Core.Otp;

/// <summary>Base32 RFC 4648 (alfabeto A-Z2-7), usato per i segreti TOTP nelle app di autenticazione.</summary>
public static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Encode(ReadOnlySpan<byte> data, bool padding = false)
    {
        var sb = new StringBuilder((data.Length + 4) / 5 * 8);
        int buffer = 0, bits = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                sb.Append(Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0) sb.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        if (padding) while (sb.Length % 8 != 0) sb.Append('=');
        return sb.ToString();
    }

    /// <exception cref="FormatException">Carattere non valido.</exception>
    public static byte[] Decode(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var output = new List<byte>(text.Length * 5 / 8);
        int buffer = 0, bits = 0;
        foreach (var raw in text)
        {
            if (raw == '=' || raw == ' ' || raw == '-') continue;
            var c = char.ToUpperInvariant(raw);
            var v = Alphabet.IndexOf(c);
            if (v < 0) throw new FormatException($"Carattere non valido in Base32: '{raw}'.");
            buffer = (buffer << 5) | v;
            bits += 5;
            if (bits >= 8)
            {
                output.Add((byte)((buffer >> (bits - 8)) & 0xFF));
                bits -= 8;
            }
        }
        return output.ToArray();
    }
}
