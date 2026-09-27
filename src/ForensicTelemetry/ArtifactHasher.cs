using Microsoft.Win32.SafeHandles;
using System.Security.Cryptography;

namespace ForensicTelemetry;

public static class ArtifactHasher
{
    public static async ValueTask<byte[]> ComputeSha256Async(SafeFileHandle handle, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(handle);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[64 * 1024];
        long offset = 0;
        try
        {
            var length = RandomAccess.GetLength(handle);
            while (offset < length)
            {
                var count = (int)Math.Min(buffer.Length, length - offset);
                var read = await RandomAccess.ReadAsync(handle, buffer.AsMemory(0, count), offset, cancellationToken).ConfigureAwait(false);
                if (read == 0) throw new EndOfStreamException("Unexpected short read while hashing artifact.");
                hash.AppendData(buffer, 0, read);
                offset = checked(offset + read);
            }
            return hash.GetHashAndReset();
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }
}
