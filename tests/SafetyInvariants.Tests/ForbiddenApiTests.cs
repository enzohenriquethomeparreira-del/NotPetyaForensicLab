using LateralMovementSimulator;

namespace SafetyInvariants.Tests;

public sealed class ForbiddenApiTests
{
    [Fact]
    public void Offline_pcap_module_does_not_reference_socket_or_process_assemblies()
    {
        var references = typeof(OfflineConversationGenerator).Assembly.GetReferencedAssemblies().Select(a => a.Name).ToArray();
        Assert.DoesNotContain("System.Net.Sockets", references);
        Assert.DoesNotContain("System.Diagnostics.Process", references);
        Assert.DoesNotContain("System.Management", references);
        Assert.DoesNotContain("System.Management.Automation", references);
    }

    [Fact]
    public void Operation_registry_contains_only_approved_operations()
    {
        var expected = new[] { "CreateForensicVolume", "WriteSyntheticSectorZero", "GenerateOfflinePcap", "EncryptVirtualFiles", "RenderLockScreen", "CollectArtifacts", "RestoreFromEscrow" };
        Assert.Equal(expected.Order(), Enum.GetNames<Shared.Contracts.AllowedOperation>().Order());
    }
}
