using Shared.Contracts;

namespace WindowsLabAgent.Handlers;

public sealed class RenderLockScreenHandler : IOperationHandler
{
    public AllowedOperation Operation => AllowedOperation.RenderLockScreen;
    public ValueTask<OperationResult> ExecuteAsync(OperationRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(OperationResult.Ok("Lock-screen fixture is a separately launched, closable viewer.", new Dictionary<string, string> { ["image"] = request.Arguments[OperationArguments.DiskImage] }));
    }
}
