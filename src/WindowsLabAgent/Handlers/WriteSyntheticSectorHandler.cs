using System.Buffers.Binary;
using DiskImageSimulator;
using Shared.Contracts;

namespace WindowsLabAgent.Handlers;

public sealed class WriteSyntheticSectorHandler : IOperationHandler
{
    public AllowedOperation Operation => AllowedOperation.WriteSyntheticSectorZero;

    public async ValueTask<OperationResult> ExecuteAsync(OperationRequest request, CancellationToken cancellationToken)
    {
        var hash = Convert.FromHexString(request.Arguments[OperationArguments.ManifestSha256]);
        var diskId = BinaryPrimitives.ReadUInt32LittleEndian(hash);
        var sector = SyntheticMbrBuilder.Build(request.ScenarioId, hash, diskId, "FORENSIC-LAB-SECTOR-SIGNATURE-V1"u8, "Synthetic forensic incident fixture. No physical disk was modified.");
        using var handle = SafeArtifactPath.OpenPreparedOutputFile(request.Arguments[OperationArguments.DiskImage], SyntheticMbrLayout.SectorSize);
        var result = await SectorWriter.WriteAndVerifyAsync(handle, 0, sector, cancellationToken).ConfigureAwait(false);
        return result.Verified ? OperationResult.Ok("Synthetic sector written and verified.", new Dictionary<string, string> { ["sha256"] = result.AfterSha256 })
            : OperationResult.Fail("SECTOR_VERIFY_FAILED", "Sector readback did not match.");
    }
}
