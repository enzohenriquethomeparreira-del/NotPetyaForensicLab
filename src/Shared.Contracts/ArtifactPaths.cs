namespace Shared.Contracts;

public sealed record ArtifactPaths(
    string WorkingDirectory,
    string DiskImage,
    string ForensicVolume,
    string OfflinePcap,
    string TelemetryJsonl,
    string RecoveryEscrow,
    string TimelineJson);
