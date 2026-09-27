using System.Text.Json;
using Shared.Contracts;

namespace WindowsLabAgent.Handlers;

public sealed class CollectArtifactsHandler : IOperationHandler
{
    public AllowedOperation Operation => AllowedOperation.CollectArtifacts;
    public async ValueTask<OperationResult> ExecuteAsync(OperationRequest request, CancellationToken cancellationToken)
    {
        var path = request.Arguments[OperationArguments.Timeline];
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schema = "forensic-lab-timeline-v1",
            scenarioId = request.ScenarioId,
            generatedAtUtc = DateTimeOffset.UtcNow,
            artifacts = new[] { request.Arguments[OperationArguments.DiskImage], request.Arguments[OperationArguments.ForensicVolume], request.Arguments[OperationArguments.OfflinePcap], request.Arguments[OperationArguments.Escrow] }
        }, new JsonSerializerOptions { WriteIndented = true });
        using var handle = SafeArtifactPath.OpenPreparedOutputFile(path, 4 * 1024 * 1024, requireEmpty: false);
        RandomAccess.SetLength(handle, 0);
        await RandomAccess.WriteAsync(handle, bytes, 0, cancellationToken).ConfigureAwait(false);
        RandomAccess.FlushToDisk(handle);
        return OperationResult.Ok("Timeline manifest created.", new Dictionary<string, string> { ["path"] = path });
    }
}
