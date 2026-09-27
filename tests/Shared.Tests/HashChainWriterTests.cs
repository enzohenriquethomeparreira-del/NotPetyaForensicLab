using ForensicTelemetry;

namespace Shared.Tests;

public sealed class HashChainWriterTests
{
    [Fact]
    public async Task Events_form_a_verifiable_monotonic_chain()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".jsonl");
        try
        {
            var handle = File.OpenHandle(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read, FileOptions.Asynchronous);
            await using var writer = new HashChainWriter(handle, Guid.NewGuid(), Guid.NewGuid());
            var first = await writer.AppendAsync("Start", new Dictionary<string, string>(), default);
            var second = await writer.AppendAsync("Next", new Dictionary<string, string> { ["b"] = "2", ["a"] = "1" }, default);
            Assert.Equal(new string('0', 64), first.PreviousHash);
            Assert.Equal(first.CurrentHash, second.PreviousHash);
            Assert.Equal(2, second.Sequence);
            Assert.True(await HashChainWriter.VerifyAsync(path, default));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task Tampered_jsonl_fails_verification()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".jsonl");
        var handle = File.OpenHandle(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read, FileOptions.Asynchronous);
        await using (var writer = new HashChainWriter(handle, Guid.NewGuid(), Guid.NewGuid()))
            await writer.AppendAsync("Start", new Dictionary<string, string> { ["x"] = "y" }, default);
        await File.AppendAllTextAsync(path, "{\"invalid\":true}\n");
        Assert.False(await HashChainWriter.VerifyAsync(path, default));
        File.Delete(path);
    }
}
