namespace WindowsLabAgent.Handlers;

public static class HandlerFactory
{
    public static OperationDispatcher Create(ScenarioRuntimeState state) => new(new IOperationHandler[]
    {
        new CreateForensicVolumeHandler(state), new WriteSyntheticSectorHandler(), new GenerateOfflinePcapHandler(),
        new EncryptVirtualFilesHandler(state), new RestoreFromEscrowHandler(state), new RenderLockScreenHandler(), new CollectArtifactsHandler()
    });
}
