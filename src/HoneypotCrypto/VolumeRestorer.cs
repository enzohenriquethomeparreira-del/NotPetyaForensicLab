using System.Security.Cryptography;
using System.Text.Json;

namespace HoneypotCrypto;

public sealed record RestoreResult(VirtualFileEntry Entry, byte[] Plaintext);

public static class VolumeRestorer
{
    public static async ValueTask<RestoreResult> RestoreAsync(ForensicVolume volume, VirtualFileEntry entry, VerifiedEscrow escrow, CancellationToken cancellationToken,
        Func<TransformCheckpoint, bool>? simulateInterruption = null)
    {
        if (!entry.Encrypted || entry.Nonce.Length != 12 || entry.Tag.Length != 16 || entry.WrappedKey.Length == 0)
            throw new InvalidDataException("Virtual file does not contain complete authenticated-encryption metadata.");
        var ciphertext = await volume.ReadVirtualFileAsync(entry, cancellationToken).ConfigureAwait(false);
        var plaintext = new byte[ciphertext.Length];
        var key = escrow.RecoveryKey.Decrypt(entry.WrappedKey, RSAEncryptionPadding.OaepSHA256);
        try
        {
            using (var aes = new AesGcm(key, entry.Tag.Length))
                aes.Decrypt(entry.Nonce, ciphertext, entry.Tag, plaintext, entry.FileId.ToByteArray());
            if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(plaintext), entry.OriginalSha256))
                throw new CryptographicException("Restored plaintext hash does not match the original fixture.");
            var restoredEntry = entry with { Encrypted = false, Nonce = [], Tag = [], WrappedKey = [] };
            await volume.BeginTransactionAsync(entry, ciphertext, "Restore", cancellationToken).ConfigureAwait(false);
            if (simulateInterruption?.Invoke(TransformCheckpoint.AfterPrepared) == true) throw new SimulatedPowerLossException(TransformCheckpoint.AfterPrepared);
            await volume.WriteDataAsync(entry, plaintext, cancellationToken).ConfigureAwait(false);
            volume.Flush();
            await volume.AdvanceTransactionAsync("DataWritten", cancellationToken).ConfigureAwait(false);
            if (simulateInterruption?.Invoke(TransformCheckpoint.AfterDataWritten) == true) throw new SimulatedPowerLossException(TransformCheckpoint.AfterDataWritten);
            await volume.WriteEntryAsync(restoredEntry, cancellationToken).ConfigureAwait(false);
            volume.Flush();
            if (simulateInterruption?.Invoke(TransformCheckpoint.AfterEntryWritten) == true) throw new SimulatedPowerLossException(TransformCheckpoint.AfterEntryWritten);
            await volume.CompleteTransactionAsync(cancellationToken).ConfigureAwait(false);
            return new RestoreResult(restoredEntry, plaintext);
        }
        catch (SimulatedPowerLossException)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }
        catch
        {
            await volume.RecoverPendingAsync(CancellationToken.None).ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }
}
