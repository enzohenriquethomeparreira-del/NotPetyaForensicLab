using HoneypotCrypto;
using Shared.Contracts;

namespace WindowsLabAgent.Handlers;

public sealed class EncryptVirtualFilesHandler(ScenarioRuntimeState state) : IOperationHandler
{
    public AllowedOperation Operation => AllowedOperation.EncryptVirtualFiles;

    public async ValueTask<OperationResult> ExecuteAsync(OperationRequest request, CancellationToken cancellationToken)
    {
        if (state.Volume is null) return OperationResult.Fail("VOLUME_MISSING", "CreateForensicVolume must run first.");
        var maximumTransformBytes = long.Parse(request.Arguments[OperationArguments.MaximumTransformBytes], System.Globalization.CultureInfo.InvariantCulture);
        var totalBytes = state.Entries.Sum(entry => (long)entry.PlaintextLength);
        if (totalBytes > maximumTransformBytes) return OperationResult.Fail("TRANSFORM_LIMIT_EXCEEDED", "Virtual fixture bytes exceed signed maximumTransformBytes.");
        var escrowPath = SafeArtifactPath.ValidateForLab(request.Arguments[OperationArguments.Escrow]);
        using var escrowHandle = SafeArtifactPath.OpenPreparedOutputFile(escrowPath, 1024 * 1024);
        state.Escrow = await RecoveryEscrow.PrepareAndVerifyAsync(escrowPath, escrowHandle, state.RecoveryKey, cancellationToken).ConfigureAwait(false);
        for (var i = 0; i < state.Entries.Count; i++)
        {
            var transformed = await InPlaceBlockTransformer.TransformAsync(state.Volume, state.Entries[i], state.Escrow, cancellationToken).ConfigureAwait(false);
            state.Entries[i] = transformed.Entry;
        }
        return OperationResult.Ok($"Transformed {state.Entries.Count} virtual files inside the custom image.");
    }
}
