using HoneypotCrypto;
using Shared.Contracts;

namespace WindowsLabAgent.Handlers;

public sealed class CreateForensicVolumeHandler(ScenarioRuntimeState state) : IOperationHandler
{
    public AllowedOperation Operation => AllowedOperation.CreateForensicVolume;

    public async ValueTask<OperationResult> ExecuteAsync(OperationRequest request, CancellationToken cancellationToken)
    {
        if (state.Volume is not null) return OperationResult.Fail("VOLUME_EXISTS", "The runtime already owns a volume.");
        var size = long.Parse(request.Arguments[OperationArguments.MaximumVolumeBytes], System.Globalization.CultureInfo.InvariantCulture);
        var signedMaximumFiles = int.Parse(request.Arguments[OperationArguments.MaximumFiles], System.Globalization.CultureInfo.InvariantCulture);
        var fixtures = LabFixtureCatalog.Create();
        if (size < 1024 * 1024) return OperationResult.Fail("VOLUME_LIMIT_TOO_SMALL", "Signed maximumVolumeBytes is below the format minimum.");
        if (signedMaximumFiles < fixtures.Count) return OperationResult.Fail("FILE_LIMIT_TOO_SMALL", "Signed maximumFiles cannot hold the complete fixture set.");
        var maxFiles = Math.Min(signedMaximumFiles, 64);
        var handle = SafeArtifactPath.OpenPreparedOutputFile(request.Arguments[OperationArguments.ForensicVolume], size);
        try
        {
            state.Volume = await HoneypotCrypto.ForensicVolume.CreateAsync(handle, new ForensicVolumeOptions(size, 4096, maxFiles), cancellationToken).ConfigureAwait(false);
            foreach (var fixture in fixtures)
                state.Entries.Add(await state.Volume.AddVirtualFileAsync(fixture.Name, fixture.Content, cancellationToken));
            return OperationResult.Ok("Custom forensic volume created.", new Dictionary<string, string> { ["path"] = request.Arguments[OperationArguments.ForensicVolume] });
        }
        catch { handle.Dispose(); throw; }
    }
}
