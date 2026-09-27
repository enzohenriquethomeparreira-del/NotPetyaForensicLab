using Shared.Contracts;
using WindowsLabAgent.Handlers;

namespace WindowsLabAgent;

public static class ExecutionPreflight
{
    public static ValidationResult Validate(ScenarioManifest manifest)
    {
        try
        {
            var paths = new[] { manifest.Paths.DiskImage, manifest.Paths.ForensicVolume, manifest.Paths.OfflinePcap, manifest.Paths.TelemetryJsonl, manifest.Paths.RecoveryEscrow, manifest.Paths.TimelineJson }
                .Select(Path.GetFullPath).ToArray();
            if (paths.Distinct(StringComparer.OrdinalIgnoreCase).Count() != paths.Length)
                return ValidationResult.Invalid("ARTIFACT_ALIAS", "Every artifact must use a distinct file.");

            var operations = manifest.Operations.ToList();
            if (!OrderedBefore(operations, AllowedOperation.CreateForensicVolume, AllowedOperation.EncryptVirtualFiles) ||
                !OrderedBefore(operations, AllowedOperation.EncryptVirtualFiles, AllowedOperation.RestoreFromEscrow) ||
                !OrderedBefore(operations, AllowedOperation.WriteSyntheticSectorZero, AllowedOperation.RenderLockScreen))
                return ValidationResult.Invalid("OPERATION_ORDER", "Dependent operations are missing or out of order.");

            if (operations.Contains(AllowedOperation.CreateForensicVolume))
            {
                if (manifest.Limits.MaximumVolumeBytes < 1024 * 1024) return ValidationResult.Invalid("VOLUME_LIMIT_TOO_SMALL", "maximumVolumeBytes is below 1 MiB.");
                if (manifest.Limits.MaximumFiles < LabFixtureCatalog.Create().Count) return ValidationResult.Invalid("FILE_LIMIT_TOO_SMALL", "maximumFiles cannot hold all fixtures.");
            }
            if (operations.Contains(AllowedOperation.EncryptVirtualFiles) && manifest.Limits.MaximumTransformBytes < LabFixtureCatalog.TotalPlaintextBytes)
                return ValidationResult.Invalid("TRANSFORM_LIMIT_TOO_SMALL", "maximumTransformBytes cannot cover the fixture set.");

            ValidatePrepared(manifest.Paths.TelemetryJsonl, 16 * 1024 * 1024);
            ValidatePrepared(manifest.Paths.TimelineJson, 4 * 1024 * 1024);
            if (operations.Contains(AllowedOperation.WriteSyntheticSectorZero) || operations.Contains(AllowedOperation.RenderLockScreen))
                ValidatePrepared(manifest.Paths.DiskImage, 512);
            if (operations.Any(o => o is AllowedOperation.CreateForensicVolume or AllowedOperation.EncryptVirtualFiles or AllowedOperation.RestoreFromEscrow))
                ValidatePrepared(manifest.Paths.ForensicVolume, manifest.Limits.MaximumVolumeBytes);
            if (operations.Contains(AllowedOperation.GenerateOfflinePcap)) ValidatePrepared(manifest.Paths.OfflinePcap, 16 * 1024 * 1024);
            if (operations.Contains(AllowedOperation.EncryptVirtualFiles)) ValidatePrepared(manifest.Paths.RecoveryEscrow, 1024 * 1024);
            return ValidationResult.Valid();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return ValidationResult.Invalid("PREFLIGHT_FAILED", ex.Message);
        }
    }

    private static bool OrderedBefore(IReadOnlyList<AllowedOperation> operations, AllowedOperation prerequisite, AllowedOperation dependent)
    {
        var dependentIndex = operations.IndexOf(dependent);
        if (dependentIndex < 0) return true;
        var prerequisiteIndex = operations.IndexOf(prerequisite);
        return prerequisiteIndex >= 0 && prerequisiteIndex < dependentIndex;
    }

    private static void ValidatePrepared(string path, long maximum)
    {
        using var handle = SafeArtifactPath.OpenPreparedOutputFile(path, maximum);
    }

    private static int IndexOf(this IReadOnlyList<AllowedOperation> source, AllowedOperation value)
    {
        for (var i = 0; i < source.Count; i++) if (source[i] == value) return i;
        return -1;
    }
}
