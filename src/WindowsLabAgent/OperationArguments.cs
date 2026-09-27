using Shared.Contracts;

namespace WindowsLabAgent;

public static class OperationArguments
{
    public const string DiskImage = "diskImage", ForensicVolume = "forensicVolume", OfflinePcap = "offlinePcap", Telemetry = "telemetry",
        Escrow = "escrow", Timeline = "timeline", WorkingDirectory = "workingDirectory", MaximumVolumeBytes = "maximumVolumeBytes",
        MaximumFiles = "maximumFiles", MaximumTransformBytes = "maximumTransformBytes", ClientAddress = "clientAddress", ServerAddress = "serverAddress", ManifestSha256 = "manifestSha256";

    public static IReadOnlyDictionary<string, string> FromManifest(ScenarioManifest manifest, ReadOnlySpan<byte> manifestHash) =>
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [DiskImage] = manifest.Paths.DiskImage,
            [ForensicVolume] = manifest.Paths.ForensicVolume,
            [OfflinePcap] = manifest.Paths.OfflinePcap,
            [Telemetry] = manifest.Paths.TelemetryJsonl,
            [Escrow] = manifest.Paths.RecoveryEscrow,
            [Timeline] = manifest.Paths.TimelineJson,
            [WorkingDirectory] = manifest.Paths.WorkingDirectory,
            [MaximumVolumeBytes] = manifest.Limits.MaximumVolumeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            [MaximumFiles] = manifest.Limits.MaximumFiles.ToString(System.Globalization.CultureInfo.InvariantCulture),
            [MaximumTransformBytes] = manifest.Limits.MaximumTransformBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            [ClientAddress] = manifest.DocumentationAddresses.ElementAtOrDefault(0) ?? "192.0.2.10",
            [ServerAddress] = manifest.DocumentationAddresses.ElementAtOrDefault(1) ?? "198.51.100.20",
            [ManifestSha256] = Convert.ToHexString(manifestHash)
        };
}
