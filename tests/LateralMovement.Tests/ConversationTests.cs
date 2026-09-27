using LateralMovementSimulator;

namespace LateralMovement.Tests;

public sealed class ConversationTests
{
    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("127.0.0.1")]
    [InlineData("10.0.0.1")]
    public void Non_documentation_addresses_are_rejected(string address) =>
        Assert.Throws<ArgumentException>(() => DocumentationAddress.Parse(address));

    [Fact]
    public async Task Generator_writes_file_only_pcapng_with_smb_stage_markers()
    {
        var path = Path.GetTempFileName();
        using var handle = File.OpenHandle(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None, FileOptions.Asynchronous);
        var scenario = ConversationScenario.CreateDefault("192.0.2.10", "198.51.100.20");
        var result = await OfflineConversationGenerator.GenerateAsync(handle, scenario, default);
        handle.Dispose();
        var bytes = await File.ReadAllBytesAsync(path);
        Assert.True(result.PacketCount >= 10);
        Assert.Equal(0x0A0D0D0Au, System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(bytes));
        Assert.True(bytes.AsSpan().IndexOf("LAB_SERVICE_CREATE_FIXTURE"u8) >= 0);
        File.Delete(path);
    }
}
