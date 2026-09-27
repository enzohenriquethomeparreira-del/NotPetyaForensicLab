using System.Security.Cryptography;
using HoneypotCrypto;

namespace WindowsLabAgent;

public sealed class ScenarioRuntimeState(RSA recoveryKey) : IAsyncDisposable
{
    private int _disposed;
    public RSA RecoveryKey { get; } = recoveryKey;
    public ForensicVolume? Volume { get; set; }
    public List<VirtualFileEntry> Entries { get; } = [];
    public VerifiedEscrow? Escrow { get; set; }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        if (Volume is not null) await Volume.DisposeAsync().ConfigureAwait(false);
        Volume = null;
    }
}
