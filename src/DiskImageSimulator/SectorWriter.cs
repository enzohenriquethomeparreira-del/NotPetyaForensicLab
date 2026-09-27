using Microsoft.Win32.SafeHandles;
using System.Security.Cryptography;

namespace DiskImageSimulator;

public sealed record SectorWriteResult(bool Verified, string BeforeSha256, string AfterSha256, SectorDiff Diff);

public static class SectorWriter
{
    public static async ValueTask<SectorWriteResult> WriteAndVerifyAsync(SafeFileHandle image, long offset, ReadOnlyMemory<byte> sector, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(image);
        if (image.IsInvalid || image.IsClosed) throw new ObjectDisposedException(nameof(image));
        if (offset != 0) throw new ArgumentOutOfRangeException(nameof(offset), "Synthetic sector zero must be written at offset zero.");
        if (sector.Length != SyntheticMbrLayout.SectorSize) throw new ArgumentException("Sector must contain exactly 512 bytes.", nameof(sector));

        var before = new byte[SyntheticMbrLayout.SectorSize];
        var existingLength = RandomAccess.GetLength(image);
        if (existingLength > 0) await ReadAvailableAsync(image, before, Math.Min(existingLength, before.Length), cancellationToken).ConfigureAwait(false);
        if (existingLength < SyntheticMbrLayout.SectorSize) RandomAccess.SetLength(image, SyntheticMbrLayout.SectorSize);

        await RandomAccess.WriteAsync(image, sector, offset, cancellationToken).ConfigureAwait(false);
        RandomAccess.FlushToDisk(image);

        var after = new byte[SyntheticMbrLayout.SectorSize];
        await ReadExactAsync(image, after, offset, cancellationToken).ConfigureAwait(false);
        var verified = CryptographicOperations.FixedTimeEquals(sector.Span, after);
        return new SectorWriteResult(
            verified,
            Convert.ToHexString(SHA256.HashData(before)),
            Convert.ToHexString(SHA256.HashData(after)),
            SectorDiffReporter.Create(before, after));
    }

    private static async ValueTask ReadAvailableAsync(SafeFileHandle handle, Memory<byte> destination, long count, CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < count)
        {
            var read = await RandomAccess.ReadAsync(handle, destination[total..(int)count], total, cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            total += read;
        }
    }

    private static async ValueTask ReadExactAsync(SafeFileHandle handle, Memory<byte> destination, long offset, CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < destination.Length)
        {
            var read = await RandomAccess.ReadAsync(handle, destination[total..], checked(offset + total), cancellationToken).ConfigureAwait(false);
            if (read == 0) throw new EndOfStreamException("Short sector read.");
            total += read;
        }
    }
}
