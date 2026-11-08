using System.DirectoryServices;
using Ldap = System.DirectoryServices.Protocols;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using FispaSspr.Core.Abstractions;
using FispaSspr.Core.Model;
using FispaSspr.Core.Passwords;

namespace FispaSspr.Web.Infrastructure;

/// <summary>
/// Accesso ad AD con l'identita' del processo (gMSA del servizio), Kerberos con firma e cifratura.
/// Tutte le chiamate sono sincrone nell'API ADSI: vengono eseguite su thread del pool.
/// </summary>
public sealed class AdDirectory : IDirectory, IEnrollmentStore
{
    private const AuthenticationTypes Auth = AuthenticationTypes.Secure | AuthenticationTypes.Signing | AuthenticationTypes.Sealing;
    private const int UfAccountDisable = 0x2;
    private const int UfLockout = 0x10;
    private const int UfPasswordExpired = 0x800000;

    private static readonly string[] UserProps =
    {
        "objectSid", "sAMAccountName", "userPrincipalName", "displayName", "distinguishedName", "userAccountControl",
        "msDS-User-Account-Control-Computed", "adminCount", "objectClass", "tokenGroups", "mail",
    };

    private readonly SettingsStore _settings;
    private readonly ILogger<AdDirectory> _log;
    private string? _namingContext;

    public AdDirectory(SettingsStore settings, ILogger<AdDirectory> log)
    {
        _settings = settings;
        _log = log;
    }

    private string Server => _settings.Current.Directory.DomainController?.Trim() ?? string.Empty;
    private string Prefix => Server.Length > 0 ? $"LDAP://{Server}/" : "LDAP://";

    private DirectoryEntry Entry(string dn) => new(Prefix + dn.Replace("/", "\\/", StringComparison.Ordinal), null, null, Auth);

    public string NamingContext
    {
        get
        {
            if (_namingContext is null)
            {
                using var root = new DirectoryEntry(Prefix + "RootDSE", null, null, Auth);
                _namingContext = (string)root.Properties["defaultNamingContext"].Value!;
            }
            return _namingContext;
        }
    }

    internal static string EscapeFilter(string value)
    {
        var sb = new System.Text.StringBuilder(value.Length);
        foreach (var c in value)
        {
            sb.Append(c switch
            {
                '\\' => "\\5c",
                '*' => "\\2a",
                '(' => "\\28",
                ')' => "\\29",
                '\0' => "\\00",
                _ => c.ToString(),
            });
        }
        return sb.ToString();
    }

    private DirectoryUser? Map(DirectoryEntry de)
    {
        de.RefreshCache(UserProps);
        if (de.Properties["objectSid"].Value is not byte[] sidBytes) return null;
        var uac = Convert.ToInt32(de.Properties["userAccountControl"].Value ?? 0, System.Globalization.CultureInfo.InvariantCulture);
        var computed = Convert.ToInt32(de.Properties["msDS-User-Account-Control-Computed"].Value ?? 0, System.Globalization.CultureInfo.InvariantCulture);
        var groups = new List<string>();
        foreach (var g in de.Properties["tokenGroups"])
            if (g is byte[] b) groups.Add(new SecurityIdentifier(b, 0).Value);
        var classes = de.Properties["objectClass"].Cast<object>().Select(o => o.ToString() ?? string.Empty).ToList();
        // solo utenti: niente computer, gMSA, gruppi o contatti anche se il SID arriva dall'esterno
        if (!classes.Contains("user", StringComparer.OrdinalIgnoreCase) || classes.Contains("computer", StringComparer.OrdinalIgnoreCase)) return null;
        return new DirectoryUser
        {
            Sid = new SecurityIdentifier(sidBytes, 0).Value,
            SamAccountName = (string)de.Properties["sAMAccountName"].Value!,
            DistinguishedName = (string)de.Properties["distinguishedName"].Value!,
            UserPrincipalName = de.Properties["userPrincipalName"].Value as string,
            DisplayName = de.Properties["displayName"].Value as string,
            Enabled = (uac & UfAccountDisable) == 0,
            LockedOut = (computed & UfLockout) != 0,
            PasswordExpired = (computed & UfPasswordExpired) != 0,
            AdminCount = Convert.ToInt32(de.Properties["adminCount"].Value ?? 0, System.Globalization.CultureInfo.InvariantCulture),
            GroupSids = groups,
            ObjectClasses = classes,
        };
    }

    /// <summary>Email aziendale (attributo mail), usata solo per gli inviti a registrarsi.</summary>
    public Task<string?> GetMailAsync(DirectoryUser user, CancellationToken ct = default) => Task.Run(() =>
    {
        using var de = Entry(user.DistinguishedName);
        de.RefreshCache(new[] { "mail" });
        return de.Properties["mail"].Value as string;
    }, ct);

    public Task<DirectoryUser?> FindUserAsync(string userName, CancellationToken ct = default) => Task.Run(() =>
    {
        var name = EscapeFilter(userName);
        using var root = Entry(NamingContext);
        using var ds = new DirectorySearcher(root, $"(&(objectCategory=person)(objectClass=user)(|(sAMAccountName={name})(userPrincipalName={name})))", new[] { "distinguishedName" })
        {
            SizeLimit = 2,
        };
        using var results = ds.FindAll();
        if (results.Count != 1) return null;
        using var de = Entry((string)results[0].Properties["distinguishedName"][0]);
        return Map(de);
    }, ct);

    public Task<DirectoryUser?> FindUserBySidAsync(string sid, CancellationToken ct = default) => Task.Run(() =>
    {
        _ = new SecurityIdentifier(sid); // valida il formato
        using var de = new DirectoryEntry(Prefix + $"<SID={sid}>", null, null, Auth);
        try { return Map(de); }
        catch (COMException) { return null; }
    }, ct);

    // ------------------------------------------------------------------ gruppi privilegiati senza RID fisso

    /// <summary>Gruppi con privilegi elevati ma SID diverso in ogni dominio: DnsAdmins (codice sui DC) e i gruppi di Exchange con diritti su AD.</summary>
    private static readonly string[] ExtraPrivilegedNames =
    {
        "DnsAdmins", "Organization Management", "Exchange Trusted Subsystem", "Exchange Windows Permissions",
    };

    private readonly object _privLock = new();
    private IReadOnlyList<string> _extraPriv = Array.Empty<string>();
    private DateTimeOffset _extraPrivAt = DateTimeOffset.MinValue;

    /// <summary>SID dei gruppi privilegiati trovati nel dominio, riletti ogni ora (in caso di errore resta l'ultimo elenco noto).</summary>
    public IReadOnlyList<string> ExtraPrivilegedGroupSids()
    {
        lock (_privLock)
        {
            if (DateTimeOffset.UtcNow - _extraPrivAt < TimeSpan.FromHours(1)) return _extraPriv;
            _extraPrivAt = DateTimeOffset.UtcNow;
            try
            {
                var filter = "(&(objectCategory=group)(|" + string.Concat(ExtraPrivilegedNames.Select(n => $"(sAMAccountName={EscapeFilter(n)})")) + "))";
                using var root = Entry(NamingContext);
                using var ds = new DirectorySearcher(root, filter, new[] { "objectSid" }) { PageSize = 100 };
                using var results = ds.FindAll();
                var list = new List<string>();
                foreach (SearchResult r in results)
                    if (r.Properties["objectSid"].Count > 0 && r.Properties["objectSid"][0] is byte[] b) list.Add(new SecurityIdentifier(b, 0).Value);
                _extraPriv = list;
            }
            catch (Exception ex) when (ex is COMException or InvalidOperationException) { _log.LogWarning(ex, "Gruppi privilegiati aggiuntivi non leggibili: uso l'ultimo elenco noto"); }
            return _extraPriv;
        }
    }

    public Task<IReadOnlyList<DirectoryUser>> SearchUsersAsync(string text, int max, CancellationToken ct = default) => Task.Run<IReadOnlyList<DirectoryUser>>(() =>
    {
        var list = new List<DirectoryUser>();
        var filter = $"(&(objectCategory=person)(objectClass=user)(anr={EscapeFilter(text)}))";
        foreach (var ou in _settings.Current.Directory.AllowedOus)
        {
            using var root = Entry(ou);
            using var ds = new DirectorySearcher(root, filter, new[] { "distinguishedName" }) { SizeLimit = max, SearchScope = SearchScope.Subtree };
            using var results = ds.FindAll();
            foreach (SearchResult r in results)
            {
                using var de = Entry((string)r.Properties["distinguishedName"][0]);
                var u = Map(de);
                if (u is not null) list.Add(u);
                if (list.Count >= max) return list;
            }
        }
        return list;
    }, ct);

    /// <summary>Utente dell'ambito. <paramref name="MustChange"/>: password scaduta o da cambiare al prossimo accesso.</summary>
    public sealed record ScopeUser(string Sid, string SamAccountName, string? DisplayName, string? Mail, DateTimeOffset? PasswordExpires, IReadOnlyDictionary<string, string?> Attributes, bool MustChange = false);

    /// <summary>
    /// Utenti attivi nelle OU abilitate, con scadenza della password (msDS-UserPasswordExpiryTimeComputed) e attributi SSPR,
    /// in un'unica ricerca paginata per OU. Non applica la protezione degli account: chi usa i dati la verifica sul singolo utente.
    /// </summary>
    public Task<IReadOnlyList<ScopeUser>> EnumerateScopeAsync(CancellationToken ct = default) => Task.Run<IReadOnlyList<ScopeUser>>(() =>
    {
        var list = new List<ScopeUser>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var props = new List<string> { "sAMAccountName", "displayName", "mail", "objectSid", "msDS-UserPasswordExpiryTimeComputed" };
        props.AddRange(SsprAttributes.All);
        foreach (var ou in _settings.Current.Directory.AllowedOus)
        {
            ct.ThrowIfCancellationRequested();
            using var root = Entry(ou);
            using var ds = new DirectorySearcher(root, "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", props.ToArray()) { PageSize = 1000, SearchScope = SearchScope.Subtree };
            using var results = ds.FindAll();
            foreach (SearchResult r in results)
            {
                if (r.Properties["objectSid"].Count == 0) continue;
                var sid = new SecurityIdentifier((byte[])r.Properties["objectSid"][0], 0).Value;
                if (!seen.Add(sid)) continue;
                DateTimeOffset? exp = null;
                var mustChange = false;
                if (r.Properties["msDS-UserPasswordExpiryTimeComputed"].Count > 0 && r.Properties["msDS-UserPasswordExpiryTimeComputed"][0] is long ft)
                {
                    // 0 = cambio obbligatorio al prossimo accesso; valore massimo = non scade mai
                    if (ft == 0) mustChange = true;
                    else if (ft > 0 && ft < DateTime.MaxValue.ToFileTimeUtc()) exp = DateTimeOffset.FromFileTime(ft);
                }
                if (exp is { } e0 && e0 <= DateTimeOffset.Now) mustChange = true;
                var attrs = SsprAttributes.All.ToDictionary(a => a, a => r.Properties[a].Count > 0 ? r.Properties[a][0] as string : null);
                list.Add(new ScopeUser(sid, (string)r.Properties["sAMAccountName"][0], r.Properties["displayName"].Count > 0 ? r.Properties["displayName"][0] as string : null,
                    r.Properties["mail"].Count > 0 ? r.Properties["mail"][0] as string : null, exp, attrs, mustChange));
            }
        }
        return list;
    }, ct);

    public Task<(int InScope, int Enrolled)> CountUsersAsync(CancellationToken ct = default) => Task.Run(() =>
    {
        int total = 0, enrolled = 0;
        foreach (var ou in _settings.Current.Directory.AllowedOus)
        {
            using var root = Entry(ou);
            total += Count(root, "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))");
            enrolled += Count(root, "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(fispaSsprState=*))");
        }
        return (total, enrolled);

        static int Count(DirectoryEntry root, string filter)
        {
            using var ds = new DirectorySearcher(root, filter, new[] { "distinguishedName" }) { PageSize = 1000 };
            using var r = ds.FindAll();
            return r.Count;
        }
    }, ct);

    public Task<PasswordRules> GetPasswordRulesAsync(DirectoryUser user, CancellationToken ct = default) => Task.Run(() =>
    {
        var portal = _settings.Current.Passwords;
        int min = 7; var complexity = true;
        try
        {
            using var de = Entry(user.DistinguishedName);
            de.RefreshCache(new[] { "msDS-ResultantPSO" });
            if (de.Properties["msDS-ResultantPSO"].Value is string psoDn)
            {
                using var pso = Entry(psoDn);
                pso.RefreshCache(new[] { "msDS-MinimumPasswordLength", "msDS-PasswordComplexityEnabled" });
                min = Convert.ToInt32(pso.Properties["msDS-MinimumPasswordLength"].Value ?? min, System.Globalization.CultureInfo.InvariantCulture);
                complexity = pso.Properties["msDS-PasswordComplexityEnabled"].Value is not bool b || b;
            }
            else
            {
                using var dom = Entry(NamingContext);
                dom.RefreshCache(new[] { "minPwdLength", "pwdProperties" });
                min = Convert.ToInt32(dom.Properties["minPwdLength"].Value ?? min, System.Globalization.CultureInfo.InvariantCulture);
                complexity = (Convert.ToInt32(dom.Properties["pwdProperties"].Value ?? 1, System.Globalization.CultureInfo.InvariantCulture) & 1) != 0;
            }
        }
        catch (COMException ex) { _log.LogWarning(ex, "Policy password non leggibile, uso i valori del portale"); }
        return new PasswordRules
        {
            MinLength = Math.Max(min, portal.MinLength),
            RequireComplexity = complexity,
            BannedWords = portal.BannedWords,
        };
    }, ct);

    public Task<PasswordOperationResult> ResetPasswordAsync(DirectoryUser user, string newPassword, bool mustChangeAtNextLogon, CancellationToken ct = default) => Task.Run(() =>
    {
        try
        {
            var done = false;
            if (_settings.Current.Passwords.EnforceHistoryOnReset)
            {
                // DC non raggiungibile via LDAP diretto: si ripiega sul reset standard (ADSI con DC locator)
                try { done = SetPasswordWithPolicy(user.DistinguishedName, newPassword); }
                catch (Ldap.LdapException ex) { _log.LogWarning(ex, "Reset con controllo della cronologia non eseguibile: uso il reset standard"); }
            }
            using var de = Entry(user.DistinguishedName);
            if (!done) de.Invoke("SetPassword", newPassword);
            if (mustChangeAtNextLogon) de.Properties["pwdLastSet"].Value = 0;
            if (user.LockedOut) de.Properties["lockoutTime"].Value = 0;
            if (mustChangeAtNextLogon || user.LockedOut) de.CommitChanges();
            return PasswordOperationResult.Ok;
        }
        catch (Exception ex) { return MapError(ex, "reset"); }
    }, ct);

    /// <summary>Gli OID del controllo LDAP_SERVER_POLICY_HINTS: attuale (2012 R2+) e precedente (2008 R2 SP1).</summary>
    private static readonly string[] PolicyHintsOids = { "1.2.840.113556.1.4.2239", "1.2.840.113556.1.4.2066" };

    /// <summary>
    /// Reset (sostituzione di unicodePwd con il diritto "Reimposta password" del gMSA) con il controllo LDAP_SERVER_POLICY_HINTS:
    /// AD applica cronologia ed eta' minima come in un cambio password. Connessione Kerberos firmata e cifrata.
    /// Restituisce false se il DC non supporta il controllo (si usa allora il reset standard). Le violazioni dei criteri sono eccezioni.
    /// </summary>
    private bool SetPasswordWithPolicy(string dn, string newPassword)
    {
        var host = Server.Length > 0 ? Server : DnsDomain;
        using var conn = new Ldap.LdapConnection(new Ldap.LdapDirectoryIdentifier(host), null, Ldap.AuthType.Negotiate);
        conn.SessionOptions.ProtocolVersion = 3;
        conn.SessionOptions.Signing = true;
        conn.SessionOptions.Sealing = true;
        conn.Timeout = TimeSpan.FromSeconds(15);
        conn.Bind();
        foreach (var oid in PolicyHintsOids)
        {
            var mod = new Ldap.DirectoryAttributeModification { Name = "unicodePwd", Operation = Ldap.DirectoryAttributeOperation.Replace };
            mod.Add(System.Text.Encoding.Unicode.GetBytes("\"" + newPassword + "\""));
            var req = new Ldap.ModifyRequest(dn, mod);
            // valore BER: SEQUENCE { INTEGER 1 } = applica i criteri
            req.Controls.Add(new Ldap.DirectoryControl(oid, new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 }, true, true));
            try
            {
                conn.SendRequest(req);
                return true;
            }
            catch (Ldap.DirectoryOperationException ex) when (ex.Response?.ResultCode == Ldap.ResultCode.UnavailableCriticalExtension) { }
        }
        _log.LogWarning("Il domain controller {Host} non supporta LDAP_SERVER_POLICY_HINTS: reset senza controllo della cronologia", host);
        return false;
    }

    public Task<PasswordOperationResult> ChangePasswordAsync(DirectoryUser user, string currentPassword, string newPassword, CancellationToken ct = default) => Task.Run(() =>
    {
        try
        {
            using var de = Entry(user.DistinguishedName);
            de.Invoke("ChangePassword", currentPassword, newPassword);
            return PasswordOperationResult.Ok;
        }
        catch (Exception ex) { return MapError(ex, "change"); }
    }, ct);

    /// <summary>
    /// Verifica della password con un bind LDAP Kerberos/Negotiate firmato e cifrato, poi "Who am I" (RFC 4532):
    /// l'identita' autenticata deve corrispondere esattamente all'utente cercato (niente fallback su Guest o account locali).
    /// </summary>
    public Task<bool> ValidateCredentialsAsync(DirectoryUser user, string password, CancellationToken ct = default) => Task.Run(() =>
    {
        var domain = DomainNetbios;
        var host = Server.Length > 0 ? Server : DnsDomain;
        try
        {
            using var conn = new Ldap.LdapConnection(new Ldap.LdapDirectoryIdentifier(host), new NetworkCredential(user.SamAccountName, password, domain), Ldap.AuthType.Negotiate);
            conn.SessionOptions.ProtocolVersion = 3;
            conn.SessionOptions.Signing = true;
            conn.SessionOptions.Sealing = true;
            conn.Timeout = TimeSpan.FromSeconds(10);
            conn.Bind();
            var resp = (Ldap.ExtendedResponse)conn.SendRequest(new Ldap.ExtendedRequest("1.3.6.1.4.1.4203.1.11.3"));
            var who = resp.ResponseValue is null ? string.Empty : System.Text.Encoding.UTF8.GetString(resp.ResponseValue);
            return string.Equals(who, $"u:{domain}\\{user.SamAccountName}", StringComparison.OrdinalIgnoreCase);
        }
        catch (Ldap.DirectoryException) { return false; }
    }, ct);

    private string? _netbios;
    private string? _dns;

    private string DnsDomain => _dns ??= NamingContext.Split(',').Where(p => p.StartsWith("DC=", StringComparison.OrdinalIgnoreCase)).Select(p => p[3..]).Aggregate((a, b) => a + "." + b);

    /// <summary>Nome NetBIOS del dominio, letto dalla partizione di configurazione.</summary>
    private string DomainNetbios
    {
        get
        {
            if (_netbios is not null) return _netbios;
            using var root = new DirectoryEntry(Prefix + "RootDSE", null, null, Auth);
            var config = (string)root.Properties["configurationNamingContext"].Value!;
            using var parts = Entry("CN=Partitions," + config);
            using var ds = new DirectorySearcher(parts, $"(&(objectClass=crossRef)(nCName={EscapeFilter(NamingContext)}))", new[] { "nETBIOSName" }, SearchScope.OneLevel);
            var r = ds.FindOne();
            _netbios = r?.Properties["nETBIOSName"].Count > 0 ? (string)r.Properties["nETBIOSName"][0] : DnsDomain.Split('.')[0].ToUpperInvariant();
            return _netbios;
        }
    }

    public Task<PasswordOperationResult> UnlockAsync(DirectoryUser user, CancellationToken ct = default) => Task.Run(() =>
    {
        try
        {
            using var de = Entry(user.DistinguishedName);
            de.Properties["lockoutTime"].Value = 0;
            de.CommitChanges();
            return PasswordOperationResult.Ok;
        }
        catch (Exception ex) { return MapError(ex, "unlock"); }
    }, ct);

    public Task<IReadOnlyDictionary<string, string?>> ReadAsync(DirectoryUser user, CancellationToken ct = default) => Task.Run<IReadOnlyDictionary<string, string?>>(() =>
    {
        using var de = Entry(user.DistinguishedName);
        de.RefreshCache(SsprAttributes.All.ToArray());
        var d = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var a in SsprAttributes.All) d[a] = de.Properties[a].Value as string;
        return d;
    }, ct);

    public Task WriteAsync(DirectoryUser user, IReadOnlyDictionary<string, string?> values, CancellationToken ct = default) => Task.Run(() =>
    {
        using var de = Entry(user.DistinguishedName);
        foreach (var (attr, value) in values)
        {
            if (string.IsNullOrEmpty(value)) { if (de.Properties[attr].Count > 0) de.Properties[attr].Clear(); }
            else de.Properties[attr].Value = value;
        }
        de.CommitChanges();
    }, ct);

    private PasswordOperationResult MapError(Exception ex, string op)
    {
        var e = ex is TargetInvocationException { InnerException: { } inner } ? inner : ex;
        if (e is Ldap.DirectoryOperationException doe)
        {
            var code = doe.Response?.ResultCode;
            var msg = doe.Response?.ErrorMessage ?? doe.Message;
            _log.LogWarning("Operazione {Op} non riuscita (LDAP {Code}): {Message}", op, code, msg);
            // 0000052D = criteri della password (lunghezza, complessita', cronologia, eta' minima)
            if (msg.Contains("0000052D", StringComparison.OrdinalIgnoreCase) || code == Ldap.ResultCode.ConstraintViolation) return PasswordOperationResult.PolicyViolation;
            if (code == Ldap.ResultCode.InsufficientAccessRights) return PasswordOperationResult.AccessDenied;
            return PasswordOperationResult.Error;
        }
        if (e is Ldap.LdapException le)
        {
            _log.LogWarning("Operazione {Op} non riuscita: connessione LDAP {Code} {Message}", op, le.ErrorCode, le.Message);
            return PasswordOperationResult.Error;
        }
        var hr = e.HResult;
        var text = (e as DirectoryServicesCOMException)?.ExtendedErrorMessage ?? e.Message;
        _log.LogWarning("Operazione {Op} non riuscita: 0x{Hr:X8} {Message}", op, hr, text);
        if (hr == unchecked((int)0x800708C5) || text.Contains("0000052D", StringComparison.OrdinalIgnoreCase)) return PasswordOperationResult.PolicyViolation;
        if (hr == unchecked((int)0x80070056) || text.Contains("00000056", StringComparison.OrdinalIgnoreCase)) return PasswordOperationResult.WrongCurrentPassword;
        if (hr == unchecked((int)0x80070775)) return PasswordOperationResult.AccountLocked;
        if (hr == unchecked((int)0x80070005) || e is UnauthorizedAccessException) return PasswordOperationResult.AccessDenied;
        return PasswordOperationResult.Error;
    }
}
