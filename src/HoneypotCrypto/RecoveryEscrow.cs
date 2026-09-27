using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace HoneypotCrypto;

public sealed record VerifiedEscrow(string ManifestPath, string PublicKeySha256, RSA RecoveryKey);

public static class RecoveryEscrow
{
    public static async ValueTask<VerifiedEscrow> PrepareAndVerifyAsync(string manifestPath, SafeFileHandle manifestHandle, RSA recoveryKey, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(manifestPath);
        ArgumentNullException.ThrowIfNull(manifestHandle);
        ArgumentNullException.ThrowIfNull(recoveryKey);
        if (recoveryKey.KeySize != 2048) throw new CryptographicException("Recovery RSA key must be exactly 2048 bits.");
        _ = recoveryKey.ExportParameters(includePrivateParameters: true);
        var probe = RandomNumberGenerator.GetBytes(32);
        try
        {
            var wrapped = recoveryKey.Encrypt(probe, RSAEncryptionPadding.OaepSHA256);
            var unwrapped = recoveryKey.Decrypt(wrapped, RSAEncryptionPadding.OaepSHA256);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(probe, unwrapped)) throw new CryptographicException("Recovery key round-trip verification failed.");
            }
            finally { CryptographicOperations.ZeroMemory(unwrapped); }

            var publicKey = recoveryKey.ExportSubjectPublicKeyInfo();
            var fingerprint = Convert.ToHexString(SHA256.HashData(publicKey));
            var document = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schema = "forensic-lab-escrow-v1",
                publicKeySha256 = fingerprint,
                algorithm = "RSA-2048-OAEP-SHA256",
                verifiedAtUtc = DateTimeOffset.UtcNow,
                note = "Private recovery key is external and is never embedded in an artifact."
            });
            RandomAccess.SetLength(manifestHandle, 0);
            await RandomAccess.WriteAsync(manifestHandle, document, 0, cancellationToken).ConfigureAwait(false);
            RandomAccess.FlushToDisk(manifestHandle);
            return new VerifiedEscrow(manifestPath, fingerprint, recoveryKey);
        }
        finally { CryptographicOperations.ZeroMemory(probe); }
    }
}
