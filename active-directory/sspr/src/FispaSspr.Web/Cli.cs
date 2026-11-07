using System.Text.Json;
using FispaSspr.Core.Settings;
using FispaSspr.Web.Infrastructure;

namespace FispaSspr.Web;

/// <summary>
/// Comandi usati dall'installer (eseguito come amministratore, non come gMSA). I segreti arrivano solo
/// da variabili d'ambiente, mai dalla riga di comando.
///   FispaSSPR.exe init --sid S-1-5-21-...    crea la chiave master protetta verso il gMSA, il backup e cifra i segreti
///   FispaSSPR.exe restore --sid S-1-5-21-... --backup file   reimporta la chiave dal backup
///   FispaSSPR.exe validate                     verifica config.json
///   FispaSSPR.exe version
/// Variabili: FISPASSPR_BACKUP_FILE, FISPASSPR_BACKUP_PASSWORD, FISPASSPR_SMTP_PASSWORD, FISPASSPR_SMS_PASSWORD
/// </summary>
public static class Cli
{
    private static readonly string[] Commands = { "init", "restore", "validate", "version" };

    public static bool IsCommand(string arg) => Commands.Contains(arg, StringComparer.OrdinalIgnoreCase);

    private static string? Arg(string[] args, string name)
    {
        var i = Array.FindIndex(args, a => string.Equals(a, name, StringComparison.OrdinalIgnoreCase));
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    public static int Run(string[] args)
    {
        try
        {
            switch (args[0].ToLowerInvariant())
            {
                case "version":
                    Console.WriteLine(typeof(Cli).Assembly.GetName().Version);
                    return 0;

                case "validate":
                {
                    var s = SettingsStore.Read(SsprPaths.Config);
                    var errors = Validate(s);
                    foreach (var e in errors) Console.WriteLine("ERRORE: " + e);
                    if (errors.Count == 0) Console.WriteLine("OK");
                    return errors.Count == 0 ? 0 : 2;
                }

                case "init":
                {
                    var sid = Arg(args, "--sid") ?? throw new ArgumentException("--sid obbligatorio");
                    if (Directory.Exists(SsprPaths.Keys) && Directory.GetFiles(SsprPaths.Keys, "*.key").Length > 0 && !args.Contains("--force", StringComparer.OrdinalIgnoreCase))
                    {
                        Console.WriteLine("SKIP: chiave master gia' presente (usare --force per crearne una nuova: i dati registrati andrebbero persi).");
                        return 0;
                    }
                    var backupFile = Environment.GetEnvironmentVariable("FISPASSPR_BACKUP_FILE") ?? throw new ArgumentException("FISPASSPR_BACKUP_FILE mancante");
                    var backupPwd = Environment.GetEnvironmentVariable("FISPASSPR_BACKUP_PASSWORD") ?? throw new ArgumentException("FISPASSPR_BACKUP_PASSWORD mancante");
                    var key = KeyStore.CreateKey(sid);
                    KeyStore.ExportBackup(key, backupPwd, backupFile);
                    var s = SettingsStore.Read(SsprPaths.Config);
                    var smtp = Environment.GetEnvironmentVariable("FISPASSPR_SMTP_PASSWORD");
                    var sms = Environment.GetEnvironmentVariable("FISPASSPR_SMS_PASSWORD");
                    var hosting = s.Hosting with { ServiceAccountSid = sid };
                    var smtpCfg = s.Smtp with { PasswordEnvelope = string.IsNullOrEmpty(smtp) ? s.Smtp.PasswordEnvelope : SettingsStore.Encrypt(smtp, key, "smtp") };
                    var smsCfg = s.Sms with { PasswordEnvelope = string.IsNullOrEmpty(sms) ? s.Sms.PasswordEnvelope : SettingsStore.Encrypt(sms, key, "sms") };
                    s = s with { Hosting = hosting, Smtp = smtpCfg, Sms = smsCfg };
                    new SettingsStore().Save(s);
                    Console.WriteLine("OK " + key.Id);
                    return 0;
                }

                case "restore":
                {
                    var sid = Arg(args, "--sid") ?? throw new ArgumentException("--sid obbligatorio");
                    var file = Arg(args, "--backup") ?? throw new ArgumentException("--backup obbligatorio");
                    var pwd = Environment.GetEnvironmentVariable("FISPASSPR_BACKUP_PASSWORD") ?? ReadSecret("Password del backup: ");
                    var key = KeyStore.ImportBackup(file, pwd);
                    KeyStore.SaveImported(key, sid);
                    Console.WriteLine("OK " + key.Id);
                    return 0;
                }
            }
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or JsonException or System.Security.Cryptography.CryptographicException or InvalidOperationException)
        {
            Console.Error.WriteLine("ERRORE: " + ex.Message);
            return 1;
        }
        return 1;
    }

    /// <summary>Lettura della password da console senza eco.</summary>
    private static string ReadSecret(string prompt)
    {
        if (Console.IsInputRedirected) throw new ArgumentException("FISPASSPR_BACKUP_PASSWORD mancante");
        Console.Write(prompt);
        var sb = new System.Text.StringBuilder();
        while (true)
        {
            var k = Console.ReadKey(intercept: true);
            if (k.Key == ConsoleKey.Enter) break;
            if (k.Key == ConsoleKey.Backspace) { if (sb.Length > 0) sb.Length--; continue; }
            if (!char.IsControl(k.KeyChar)) sb.Append(k.KeyChar);
        }
        Console.WriteLine();
        return sb.ToString();
    }

    public static List<string> Validate(SsprSettings s)
    {
        var e = new List<string>();
        if (s.Directory.AllowedOus.Count == 0) e.Add("Nessuna OU abilitata.");
        if (string.IsNullOrWhiteSpace(s.Hosting.CertificateThumbprint)) e.Add("Certificato HTTPS non configurato.");
        if (s.Hosting.Port is < 1 or > 65535) e.Add("Porta non valida.");
        if (string.IsNullOrWhiteSpace(s.Admin.AdminGroupSid)) e.Add("Gruppo degli amministratori non configurato.");
        var methods = (s.Verification.TotpEnabled ? 1 : 0) + (s.Verification.SmsEnabled ? 1 : 0) + (s.Verification.EmailEnabled ? 1 : 0);
        if (methods < s.Verification.MinimumEnrolledMethods) e.Add($"Metodi attivi ({methods}) inferiori al minimo richiesto ({s.Verification.MinimumEnrolledMethods}).");
        if (s.Verification.EmailEnabled && string.IsNullOrWhiteSpace(s.Smtp.Host)) e.Add("Email attiva ma SMTP non configurato.");
        if (s.Verification.SmsEnabled && (s.Sms.Provider == SmsProvider.None || string.IsNullOrWhiteSpace(s.Sms.Endpoint))) e.Add("SMS attivi ma gateway non configurato.");
        return e;
    }
}
