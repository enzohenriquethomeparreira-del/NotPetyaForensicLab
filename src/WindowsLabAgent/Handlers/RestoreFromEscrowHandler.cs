using HoneypotCrypto;
using Shared.Contracts;

namespace WindowsLabAgent.Handlers;

public sealed class RestoreFromEscrowHandler(ScenarioRuntimeState state) : IOperationHandler
{
    public AllowedOperation Operation => AllowedOperation.RestoreFromEscrow;
    public async ValueTask<OperationResult> ExecuteAsync(OperationRequest request, CancellationToken cancellationToken)
    {
        if (state.Volume is null || state.Escrow is null) return OperationResult.Fail("RECOVERY_NOT_READY", "Volume and verified escrow are required.");
        for (var i = 0; i < state.Entries.Count; i++)
        {
            if (!state.Entries[i].Encrypted) continue;
            var restored = await VolumeRestorer.RestoreAsync(state.Volume, state.Entries[i], state.Escrow, cancellationToken).ConfigureAwait(false);
            state.Entries[i] = restored.Entry;
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(restored.Plaintext);
        }
        return OperationResult.Ok("All transformed virtual files were restored and authenticated.");
    }
}
