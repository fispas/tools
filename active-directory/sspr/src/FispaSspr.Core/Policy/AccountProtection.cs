using FispaSspr.Core.Model;

namespace FispaSspr.Core.Policy;

public sealed record ScopeSettings
{
    /// <summary>OU abilitate (distinguishedName). Un utente e' gestibile solo se si trova in una di queste OU o sotto.</summary>
    public IReadOnlyList<string> AllowedOus { get; init; } = Array.Empty<string>();
    /// <summary>Gruppi (SID) i cui membri non sono mai gestibili, oltre a quelli privilegiati integrati.</summary>
    public IReadOnlyList<string> ExcludedGroupSids { get; init; } = Array.Empty<string>();
}

public sealed record ProtectionResult(bool Manageable, string? Reason)
{
    public static ProtectionResult Ok { get; } = new(true, null);
    public static ProtectionResult Deny(string reason) => new(false, reason);
}

/// <summary>
/// Decide se un account puo' essere gestito dal portale e dal pannello. Questo controllo si aggiunge
/// ai permessi delegati in AD: anche con permessi sbagliati, gli account protetti restano fuori.
/// </summary>
public static class AccountProtection
{
    // RID dei gruppi privilegiati di dominio
    private static readonly string[] PrivilegedRids =
    {
        "-512", // Domain Admins
        "-516", // Domain Controllers
        "-518", // Schema Admins
        "-519", // Enterprise Admins
        "-520", // Group Policy Creator Owners
        "-521", // Read-only Domain Controllers
        "-525", // Protected Users
        "-526", // Key Admins
        "-527", // Enterprise Key Admins
    };

    // Gruppi BUILTIN privilegiati
    private static readonly HashSet<string> PrivilegedBuiltin = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-5-32-544", // Administrators
        "S-1-5-32-548", // Account Operators
        "S-1-5-32-549", // Server Operators
        "S-1-5-32-550", // Print Operators
        "S-1-5-32-551", // Backup Operators
        "S-1-5-32-552", // Replicator
    };

    private static readonly HashSet<string> ServiceClasses = new(StringComparer.OrdinalIgnoreCase)
    {
        "computer", "msDS-GroupManagedServiceAccount", "msDS-ManagedServiceAccount", "msDS-DelegatedManagedServiceAccount",
    };

    public static ProtectionResult Evaluate(DirectoryUser user, ScopeSettings scope)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(scope);

        if (user.ObjectClasses.Any(ServiceClasses.Contains)) return ProtectionResult.Deny("account di servizio o computer");
        if (user.AdminCount > 0) return ProtectionResult.Deny("account protetto (adminCount)");
        if (IsBuiltinAdministrator(user.Sid)) return ProtectionResult.Deny("account Administrator integrato");
        if (string.Equals(user.SamAccountName, "krbtgt", StringComparison.OrdinalIgnoreCase)) return ProtectionResult.Deny("account krbtgt");
        foreach (var g in user.GroupSids)
        {
            if (PrivilegedBuiltin.Contains(g) || (g.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) && PrivilegedRids.Any(r => g.EndsWith(r, StringComparison.Ordinal))))
                return ProtectionResult.Deny("membro di un gruppo privilegiato");
            if (scope.ExcludedGroupSids.Contains(g, StringComparer.OrdinalIgnoreCase))
                return ProtectionResult.Deny("membro di un gruppo escluso");
        }
        if (!IsInScope(user.DistinguishedName, scope.AllowedOus)) return ProtectionResult.Deny("fuori dalle OU abilitate");
        return ProtectionResult.Ok;
    }

    public static bool IsInScope(string distinguishedName, IReadOnlyList<string> allowedOus)
    {
        if (string.IsNullOrEmpty(distinguishedName) || allowedOus.Count == 0) return false;
        foreach (var ou in allowedOus)
        {
            var o = ou.Trim();
            if (o.Length == 0) continue;
            if (distinguishedName.EndsWith("," + o, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static bool IsBuiltinAdministrator(string sid) =>
        sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) && sid.EndsWith("-500", StringComparison.Ordinal);
}
