using LateralMovementSimulator;
using Shared.Contracts;

namespace WindowsLabAgent.Handlers;

public sealed class GenerateOfflinePcapHandler : IOperationHandler
{
    public AllowedOperation Operation => AllowedOperation.GenerateOfflinePcap;

    public async ValueTask<OperationResult> ExecuteAsync(OperationRequest request, CancellationToken cancellationToken)
    {
        using var handle = SafeArtifactPath.OpenPreparedOutputFile(request.Arguments[OperationArguments.OfflinePcap], 16 * 1024 * 1024);
        var scenario = ConversationScenario.CreateDefault(request.Arguments[OperationArguments.ClientAddress], request.Arguments[OperationArguments.ServerAddress]);
        var result = await OfflineConversationGenerator.GenerateAsync(handle, scenario, cancellationToken).ConfigureAwait(false);
        return OperationResult.Ok("Offline PCAPNG generated; no packet was transmitted.", new Dictionary<string, string> { ["packets"] = result.PacketCount.ToString(), ["bytes"] = result.Length.ToString() });
    }
}
