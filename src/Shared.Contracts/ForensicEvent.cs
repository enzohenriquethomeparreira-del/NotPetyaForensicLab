namespace Shared.Contracts;

public sealed record ForensicEvent(
    Guid ScenarioId,
    Guid AgentId,
    long Sequence,
    DateTimeOffset TimestampUtc,
    string EventType,
    IReadOnlyDictionary<string, string> Fields,
    string PreviousHash,
    string CurrentHash);
