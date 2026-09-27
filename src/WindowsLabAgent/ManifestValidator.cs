using System.Security.Cryptography;
using System.Text.Json;
using Shared.Contracts;
using LateralMovementSimulator;

namespace WindowsLabAgent;

public sealed class ManifestValidator(
    RSA pinnedControllerKey,
    INonceStore nonceStore,
    Func<DateTimeOffset> utcNow,
    Func<string> vmFingerprint)
{
    public const long MaximumVolumeCeiling = 512L * 1024 * 1024;
    public const long MaximumTransformCeiling = 256L * 1024 * 1024;
    public const int MaximumFilesCeiling = 1024;
    public const int MaximumRuntimeCeiling = 3600;

    public async ValueTask<ValidationResult> ValidateAsync(ReadOnlyMemory<byte> json, ReadOnlyMemory<byte> signature, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        byte[] canonical;
        ScenarioManifest? manifest;
        try
        {
            canonical = CanonicalJson.Canonicalize(json.Span);
            manifest = JsonSerializer.Deserialize<ScenarioManifest>(json.Span, ContractJson.CreateOptions());
        }
        catch (Exception ex) when (ex is JsonException or ArgumentException or NotSupportedException)
        {
            return ValidationResult.Invalid("MANIFEST_MALFORMED", ex.Message);
        }

        if (manifest is null) return ValidationResult.Invalid("MANIFEST_EMPTY", "Manifest is empty.");
        if (!pinnedControllerKey.VerifyData(canonical, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
            return ValidationResult.Invalid("SIGNATURE_INVALID", "Detached signature does not match the canonical manifest.");
        if (!string.Equals(PinnedKeyProvider.ComputeThumbprint(pinnedControllerKey), manifest.ControllerThumbprint, StringComparison.OrdinalIgnoreCase))
            return ValidationResult.Invalid("KEY_MISMATCH", "Controller key thumbprint mismatch.");

        var now = utcNow();
        if (manifest.IssuedAtUtc > now.AddMinutes(2)) return ValidationResult.Invalid("NOT_YET_VALID", "Manifest issue time is in the future.");
        if (manifest.ExpiresAtUtc <= now || manifest.ExpiresAtUtc <= manifest.IssuedAtUtc) return ValidationResult.Invalid("EXPIRED", "Manifest has expired.");
        if (manifest.ExpiresAtUtc - manifest.IssuedAtUtc > TimeSpan.FromHours(2)) return ValidationResult.Invalid("WINDOW_TOO_LONG", "Validity window exceeds two hours.");
        if (!string.Equals(manifest.VmFingerprint, vmFingerprint(), StringComparison.Ordinal)) return ValidationResult.Invalid("VM_MISMATCH", "VM fingerprint mismatch.");
        if (manifest.ScenarioId == Guid.Empty || manifest.AgentId == Guid.Empty) return ValidationResult.Invalid("IDENTITY_INVALID", "Scenario and agent IDs are required.");
        if (manifest.Operations.Count == 0 || manifest.Operations.Distinct().Count() != manifest.Operations.Count || manifest.Operations.Any(operation => !Enum.IsDefined(operation)))
            return ValidationResult.Invalid("OPERATIONS_INVALID", "Operations must be supported, non-empty, and unique.");
        if (manifest.Limits.MaximumVolumeBytes > MaximumVolumeCeiling || manifest.Limits.MaximumTransformBytes > MaximumTransformCeiling ||
            manifest.Limits.MaximumFiles > MaximumFilesCeiling || manifest.Limits.MaximumRuntimeSeconds > MaximumRuntimeCeiling)
            return ValidationResult.Invalid("LIMIT_EXCEEDED", "Manifest exceeds compile-time safety ceilings.");
        try
        {
            ValidateArtifactPaths(manifest.Paths);
            foreach (var address in manifest.DocumentationAddresses) _ = DocumentationAddress.Parse(address);
        }
        catch (Exception ex) when (ex is ArgumentException or UnauthorizedAccessException or NotSupportedException)
        {
            return ValidationResult.Invalid("BOUNDARY_INVALID", ex.Message);
        }
        if (!await nonceStore.TryConsumeAsync(manifest.Nonce, cancellationToken).ConfigureAwait(false))
            return ValidationResult.Invalid("NONCE_REPLAY", "Scenario nonce was already consumed or is invalid.");
        return ValidationResult.Valid();
    }

    private static void ValidateArtifactPaths(ArtifactPaths paths)
    {
        if (!Path.IsPathFullyQualified(paths.WorkingDirectory) || paths.WorkingDirectory.StartsWith(@"\\", StringComparison.Ordinal))
            throw new ArgumentException("Working directory must be a local absolute path.");
        var root = Path.GetFullPath(paths.WorkingDirectory);
        var artifacts = new[] { paths.DiskImage, paths.ForensicVolume, paths.OfflinePcap, paths.TelemetryJsonl, paths.RecoveryEscrow, paths.TimelineJson };
        foreach (var candidate in artifacts)
        {
            var full = SafeArtifactPath.ValidateLexically(candidate);
            var relative = Path.GetRelativePath(root, full);
            if (relative == ".." || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                throw new UnauthorizedAccessException("Every artifact must remain beneath the declared working directory.");
        }
    }
}
