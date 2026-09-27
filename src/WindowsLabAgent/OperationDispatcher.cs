using Shared.Contracts;

namespace WindowsLabAgent;

public interface IOperationHandler
{
    AllowedOperation Operation { get; }
    ValueTask<OperationResult> ExecuteAsync(OperationRequest request, CancellationToken cancellationToken);
}

public sealed class OperationDispatcher
{
    private readonly IReadOnlyDictionary<AllowedOperation, IOperationHandler> _handlers;

    public OperationDispatcher(IEnumerable<IOperationHandler> handlers)
    {
        var map = new Dictionary<AllowedOperation, IOperationHandler>();
        foreach (var handler in handlers)
            if (!map.TryAdd(handler.Operation, handler)) throw new InvalidOperationException($"Duplicate handler for {handler.Operation}.");
        _handlers = map;
    }

    public ValueTask<OperationResult> DispatchAsync(OperationRequest request, CancellationToken cancellationToken) =>
        _handlers.TryGetValue(request.Operation, out var handler)
            ? handler.ExecuteAsync(request, cancellationToken)
            : ValueTask.FromResult(OperationResult.Fail("HANDLER_MISSING", $"No compiled handler exists for {request.Operation}."));
}
