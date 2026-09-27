using DiskImageSimulator;
using Microsoft.Win32.SafeHandles;

namespace DiskImage.Tests;

public sealed class SectorWriterTests
{
    [Fact]
    public async Task Sector_is_written_and_verified_without_touching_following_bytes()
    {
        var path = Path.GetTempFileName();
        await File.WriteAllBytesAsync(path, Enumerable.Repeat((byte)0xCC, 1024).ToArray());
        using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None, FileOptions.Asynchronous);
        var sector = Enumerable.Range(0, 512).Select(i => (byte)i).ToArray();
        var result = await SectorWriter.WriteAndVerifyAsync(handle, 0, sector, default);
        var bytes = await File.ReadAllBytesAsync(path);
        Assert.True(result.Verified);
        Assert.All(bytes[512..], b => Assert.Equal(0xCC, b));
        handle.Dispose();
        File.Delete(path);
    }
}
