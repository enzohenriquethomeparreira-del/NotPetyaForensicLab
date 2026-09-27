using System.Security.Cryptography;

namespace HoneypotCrypto;

public sealed record TransformResult(long DataOffset, VirtualFileEntry Entry, string CiphertextSha256);

public static class InPlaceBlockTransformer
{
    public static async ValueTask<TransformResult> TransformAsync(ForensicVolume volume, VirtualFileEntry entry, VerifiedEscrow escrow, CancellationToken cancellationToken,
        Func<TransformCheckpoint, bool>? simulateInterruption = null)
    {
        ArgumentNullException.ThrowIfNull(volume);
        ArgumentNullException.ThrowIfNull(escrow);
        if (entry.Encrypted) throw new InvalidOperationException("Virtual file is already transformed.");
        if (!File.Exists(escrow.ManifestPath)) throw new InvalidOperationException("Verified escrow manifest is missing.");

        var plaintext = await volume.ReadVirtualFileAsync(entry, cancellationToken).ConfigureAwait(false);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        using var material = CngKeyProvider.GenerateFileMaterial();
        byte[] wrappedKey = [];
        try
        {
            using (var aes = new AesGcm(material.Key, tag.Length))
                aes.Encrypt(material.Nonce, plaintext, ciphertext, tag, entry.FileId.ToByteArray());
            wrappedKey = escrow.RecoveryKey.Encrypt(material.Key, RSAEncryptionPadding.OaepSHA256);
            var encryptedEntry = entry with { Encrypted = true, Nonce = material.Nonce.ToArray(), Tag = tag.ToArray(), WrappedKey = wrappedKey.ToArray() };

            await volume.BeginTransactionAsync(entry, plaintext, "Encrypt", cancellationToken).ConfigureAwait(false);
            if (simulateInterruption?.Invoke(TransformCheckpoint.AfterPrepared) == true) throw new SimulatedPowerLossException(TransformCheckpoint.AfterPrepared);
            await volume.WriteDataAsync(entry, ciphertext, cancellationToken).ConfigureAwait(false);
            volume.Flush();
            await volume.AdvanceTransactionAsync("DataWritten", cancellationToken).ConfigureAwait(false);
            if (simulateInterruption?.Invoke(TransformCheckpoint.AfterDataWritten) == true) throw new SimulatedPowerLossException(TransformCheckpoint.AfterDataWritten);
            await volume.WriteEntryAsync(encryptedEntry, cancellationToken).ConfigureAwait(false);
            volume.Flush();
            if (simulateInterruption?.Invoke(TransformCheckpoint.AfterEntryWritten) == true) throw new SimulatedPowerLossException(TransformCheckpoint.AfterEntryWritten);
            await volume.CompleteTransactionAsync(cancellationToken).ConfigureAwait(false);
            return new TransformResult(entry.DataOffset, encryptedEntry, Convert.ToHexString(SHA256.HashData(ciphertext)));
        }
        catch (SimulatedPowerLossException) { throw; }
        catch
        {
            await volume.RecoverPendingAsync(CancellationToken.None).ConfigureAwait(false);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            if (wrappedKey.Length > 0) CryptographicOperations.ZeroMemory(wrappedKey);
        }
    }

}
