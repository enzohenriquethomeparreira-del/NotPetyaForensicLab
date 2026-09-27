using Shared.Contracts;

namespace Shared.Tests;

public sealed class ContractTests
{
    [Fact]
    public void Manifest_rejects_empty_identity_fields() =>
        Assert.Throws<ArgumentException>(() => ScenarioManifest.CreateForTests(Guid.Empty, "", DateTimeOffset.UtcNow));

    [Fact]
    public void Limits_reject_negative_values() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => new ManifestLimits(-1, 1, 1, 1));

    [Fact]
    public void Allowed_operations_round_trip_as_strings()
    {
        var json = System.Text.Json.JsonSerializer.Serialize(AllowedOperation.CreateForensicVolume, ContractJson.CreateOptions());
        Assert.Equal("\"CreateForensicVolume\"", json);
        Assert.Equal(AllowedOperation.CreateForensicVolume,
            System.Text.Json.JsonSerializer.Deserialize<AllowedOperation>(json, ContractJson.CreateOptions()));
    }
}
