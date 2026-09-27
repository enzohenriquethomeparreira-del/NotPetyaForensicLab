using Shared.Contracts;
using WindowsLabAgent;

namespace Agent.Tests;

public sealed class OperationDispatcherTests
{
    [Fact]
    public async Task Unknown_operation_is_rejected()
    {
        var dispatcher = new OperationDispatcher([]);
        var result = await dispatcher.DispatchAsync(new OperationRequest(Guid.NewGuid(), AllowedOperation.CreateForensicVolume, new Dictionary<string, string>()), default);
        Assert.False(result.Success);
        Assert.Equal("HANDLER_MISSING", result.Code);
    }
}
