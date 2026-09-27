using System.Security.Principal;
using Shared.Contracts;

namespace WindowsLabAgent;

public sealed class EnvironmentAttestor
{
    public ValidationResult Attest()
    {
        if (!OperatingSystem.IsWindows()) return ValidationResult.Invalid("WINDOWS_REQUIRED", "The agent only runs on Windows.");
        using var identity = WindowsIdentity.GetCurrent();
        if (identity.IsSystem) return ValidationResult.Invalid("SYSTEM_FORBIDDEN", "The agent must not run as SYSTEM.");
        var principal = new WindowsPrincipal(identity);
        if (principal.IsInRole(WindowsBuiltInRole.Administrator))
            return ValidationResult.Invalid("ELEVATION_FORBIDDEN", "Run the laboratory agent under a standard user token.");
        return ValidationResult.Valid();
    }
}
