namespace Shared.Contracts;

public sealed record ManifestLimits
{
    public long MaximumVolumeBytes { get; init; }
    public int MaximumFiles { get; init; }
    public long MaximumTransformBytes { get; init; }
    public int MaximumRuntimeSeconds { get; init; }

    public ManifestLimits(long maximumVolumeBytes, int maximumFiles, long maximumTransformBytes, int maximumRuntimeSeconds)
    {
        if (maximumVolumeBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maximumVolumeBytes));
        if (maximumFiles <= 0) throw new ArgumentOutOfRangeException(nameof(maximumFiles));
        if (maximumTransformBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maximumTransformBytes));
        if (maximumRuntimeSeconds <= 0) throw new ArgumentOutOfRangeException(nameof(maximumRuntimeSeconds));
        MaximumVolumeBytes = maximumVolumeBytes;
        MaximumFiles = maximumFiles;
        MaximumTransformBytes = maximumTransformBytes;
        MaximumRuntimeSeconds = maximumRuntimeSeconds;
    }
}
