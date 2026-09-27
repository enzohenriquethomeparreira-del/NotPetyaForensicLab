namespace HoneypotCrypto;

public static class ForensicVolumeLayout
{
    public const int HeaderSize = 4096;
    public const int DirectoryEntrySize = 512;
    public const int JournalSize = 64 * 1024;
    public const int EscrowRegionSize = 64 * 1024;
    public static ReadOnlySpan<byte> Magic => "FLABVOL1"u8;

    public static long Align(long value, int alignment)
    {
        if (value < 0 || alignment <= 0 || (alignment & (alignment - 1)) != 0) throw new ArgumentOutOfRangeException();
        return checked((value + alignment - 1) & ~(alignment - 1));
    }
}

public sealed record ForensicVolumeOptions
{
    public long VolumeSize { get; }
    public int BlockSize { get; }
    public int MaximumFiles { get; }

    public ForensicVolumeOptions(long volumeSize, int blockSize, int maximumFiles)
    {
        if (volumeSize < 1024 * 1024 || volumeSize > 512L * 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(volumeSize));
        if (blockSize is < 512 or > 64 * 1024 || (blockSize & (blockSize - 1)) != 0) throw new ArgumentOutOfRangeException(nameof(blockSize));
        if (maximumFiles is < 1 or > 1024) throw new ArgumentOutOfRangeException(nameof(maximumFiles));
        VolumeSize = volumeSize;
        BlockSize = blockSize;
        MaximumFiles = maximumFiles;
    }
}
