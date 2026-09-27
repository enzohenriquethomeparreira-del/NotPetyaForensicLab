using System.Security.Cryptography;
using HoneypotCrypto;

namespace HoneypotCrypto.Tests;

public sealed class CryptoTransformTests
{
    [Fact]
    public async Task Transform_is_in_place_and_restores_byte_for_byte()
    {
        var path = Path.GetTempFileName();
        var escrowPath = Path.GetTempFileName();
        using var handle = File.OpenHandle(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None, FileOptions.Asynchronous);
        var volume = await ForensicVolume.CreateAsync(handle, new ForensicVolumeOptions(2 * 1024 * 1024, 4096, 8), default);
        var original = RandomNumberGenerator.GetBytes(6000);
        var entry = await volume.AddVirtualFileAsync("fixture.bin", original, default);
        using var rsa = RSA.Create(2048);
        using var escrowHandle = File.OpenHandle(escrowPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None, FileOptions.Asynchronous);
        var escrow = await RecoveryEscrow.PrepareAndVerifyAsync(escrowPath, escrowHandle, rsa, default);
        var result = await InPlaceBlockTransformer.TransformAsync(volume, entry, escrow, default);
        Assert.Equal(entry.DataOffset, result.DataOffset);
        Assert.NotEqual(original, await volume.ReadVirtualFileAsync(result.Entry, default));
        var restored = await VolumeRestorer.RestoreAsync(volume, result.Entry, escrow, default);
        Assert.Equal(original, restored.Plaintext);
        await volume.DisposeAsync();
        escrowHandle.Dispose();
        File.Delete(path);
        File.Delete(escrowPath);
    }

    [Fact]
    public async Task Interrupted_transform_rolls_back_from_staging_on_reopen()
    {
        var path = Path.GetTempFileName();
        var escrowPath = Path.GetTempFileName();
        var original = RandomNumberGenerator.GetBytes(6000);
        using var rsa = RSA.Create(2048);
        using (var handle = File.OpenHandle(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None, FileOptions.Asynchronous))
        {
            var volume = await ForensicVolume.CreateAsync(handle, new ForensicVolumeOptions(2 * 1024 * 1024, 4096, 8), default);
            var entry = await volume.AddVirtualFileAsync("recover.bin", original, default);
            using var escrowHandle = File.OpenHandle(escrowPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None, FileOptions.Asynchronous);
            var escrow = await RecoveryEscrow.PrepareAndVerifyAsync(escrowPath, escrowHandle, rsa, default);
            await Assert.ThrowsAsync<SimulatedPowerLossException>(async () =>
                await InPlaceBlockTransformer.TransformAsync(volume, entry, escrow, default, checkpoint => checkpoint == TransformCheckpoint.AfterDataWritten));
            await volume.DisposeAsync();
        }
        using (var reopenHandle = File.OpenHandle(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None, FileOptions.Asynchronous))
        {
            var reopened = await ForensicVolume.OpenAsync(reopenHandle, default);
            Assert.Equal(original, await reopened.ReadVirtualFileAsync(reopened.Entries.Single(), default));
            await reopened.DisposeAsync();
        }
        File.Delete(path);
        File.Delete(escrowPath);
    }
}
