using WindowsLabAgent;

namespace SafetyInvariants.Tests;

public sealed class EnvironmentAttestorTests
{
    [Fact]
    public void Attestation_returns_a_structured_result()
    {
        var result = new EnvironmentAttestor().Attest();
        Assert.False(string.IsNullOrWhiteSpace(result.Code));
    }
}
