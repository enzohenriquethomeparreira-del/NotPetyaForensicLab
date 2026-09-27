using HoneypotCrypto;

namespace HoneypotCrypto.Tests;

public sealed class ForensicVolumeTests
{
    [Fact]
    public async Task Virtual_file_round_trips_at_allocated_offset()
    {
        var path = Path.GetTempFileName();
        using var handle = File.OpenHandle(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None, FileOptions.Asynchronous);
        var volume = await ForensicVolume.CreateAsync(handle, new ForensicVolumeOptions(2 * 1024 * 1024, 4096, 8), default);
        var content = "known forensic fixture"u8.ToArray();
        var entry = await volume.AddVirtualFileAsync("fixture.txt", content, default);
        Assert.Equal(content, await volume.ReadVirtualFileAsync(entry, default));
        Assert.True(entry.DataOffset >= volume.Header.DataOffset);
        await volume.DisposeAsync();
        File.Delete(path);
    }

    [Fact]
    public void Invalid_sizes_are_rejected() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => new ForensicVolumeOptions(1024, 4096, 0));
}
