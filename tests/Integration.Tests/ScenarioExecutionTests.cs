using System.Security.Cryptography;
using Shared.Contracts;
using WindowsLabAgent;
using WindowsLabAgent.Handlers;

namespace Integration.Tests;

public sealed class ScenarioExecutionTests
{
    [Fact]
    public async Task Fixed_handlers_generate_and_restore_regular_file_artifacts()
    {
        var root = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        await File.WriteAllTextAsync(Path.Combine(root, SafeArtifactPath.RootMarkerName), "FORENSIC-LAB-V1");
        var manifest = ScenarioManifest.CreateForTests(Guid.NewGuid(), "vm", DateTimeOffset.UtcNow) with
        {
            Paths = new ArtifactPaths(root, Path.Combine(root, "disk.img"), Path.Combine(root, "volume.img"), Path.Combine(root, "trace.pcapng"), Path.Combine(root, "events.jsonl"), Path.Combine(root, "escrow.json"), Path.Combine(root, "timeline.json")),
            Operations = [AllowedOperation.CreateForensicVolume, AllowedOperation.WriteSyntheticSectorZero, AllowedOperation.GenerateOfflinePcap, AllowedOperation.EncryptVirtualFiles, AllowedOperation.RestoreFromEscrow]
        };
        foreach (var path in new[] { manifest.Paths.DiskImage, manifest.Paths.ForensicVolume, manifest.Paths.OfflinePcap, manifest.Paths.TelemetryJsonl, manifest.Paths.RecoveryEscrow, manifest.Paths.TimelineJson })
            await File.WriteAllBytesAsync(path, Array.Empty<byte>());
        using var rsa = RSA.Create(2048);
        var state = new ScenarioRuntimeState(rsa);
        var dispatcher = HandlerFactory.Create(state);
        var args = OperationArguments.FromManifest(manifest, SHA256.HashData("manifest"u8.ToArray()));
        foreach (var operation in manifest.Operations)
            Assert.True((await dispatcher.DispatchAsync(new OperationRequest(manifest.ScenarioId, operation, args), default)).Success);
        Assert.True(File.Exists(manifest.Paths.DiskImage));
        Assert.True(File.Exists(manifest.Paths.ForensicVolume));
        Assert.True(File.Exists(manifest.Paths.OfflinePcap));
        await state.DisposeAsync();
        Directory.Delete(root, true);
    }
}
