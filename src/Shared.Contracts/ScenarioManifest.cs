namespace Shared.Contracts;

public sealed record ScenarioManifest
{
    public required string SchemaVersion { get; init; }
    public required Guid ScenarioId { get; init; }
    public required Guid AgentId { get; init; }
    public required string VmFingerprint { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset ExpiresAtUtc { get; init; }
    public required string Nonce { get; init; }
    public required string ControllerThumbprint { get; init; }
    public required ArtifactPaths Paths { get; init; }
    public required ManifestLimits Limits { get; init; }
    public required IReadOnlyList<AllowedOperation> Operations { get; init; }
    public required IReadOnlyList<string> DocumentationAddresses { get; init; }

    public static ScenarioManifest CreateForTests(Guid id, string fingerprint, DateTimeOffset now)
    {
        if (id == Guid.Empty) throw new ArgumentException("Scenario ID is required.", nameof(id));
        if (string.IsNullOrWhiteSpace(fingerprint)) throw new ArgumentException("Fingerprint is required.", nameof(fingerprint));
        return new ScenarioManifest
        {
            SchemaVersion = "1.0",
            ScenarioId = id,
            AgentId = Guid.NewGuid(),
            VmFingerprint = fingerprint,
            IssuedAtUtc = now.AddMinutes(-1),
            ExpiresAtUtc = now.AddMinutes(30),
            Nonce = Convert.ToHexString(Guid.NewGuid().ToByteArray()),
            ControllerThumbprint = new string('A', 64),
            Paths = new ArtifactPaths("C:\\Lab", "C:\\Lab\\disk.img", "C:\\Lab\\volume.img", "C:\\Lab\\trace.pcapng", "C:\\Lab\\events.jsonl", "C:\\Lab\\escrow.json", "C:\\Lab\\timeline.json"),
            Limits = new ManifestLimits(64 * 1024 * 1024, 64, 32 * 1024 * 1024, 600),
            Operations = Enum.GetValues<AllowedOperation>(),
            DocumentationAddresses = ["192.0.2.10", "198.51.100.20"]
        };
    }
}
