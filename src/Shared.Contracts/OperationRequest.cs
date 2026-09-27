namespace Shared.Contracts;

public sealed record OperationRequest(Guid ScenarioId, AllowedOperation Operation, IReadOnlyDictionary<string, string> Arguments);
