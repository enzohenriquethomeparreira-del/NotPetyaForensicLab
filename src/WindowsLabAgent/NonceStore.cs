namespace WindowsLabAgent;

public interface INonceStore
{
    ValueTask<bool> TryConsumeAsync(string nonce, CancellationToken cancellationToken);
}

public sealed class MemoryNonceStore : INonceStore
{
    private readonly HashSet<string> _nonces = new(StringComparer.Ordinal);
    private readonly object _sync = new();
    public ValueTask<bool> TryConsumeAsync(string nonce, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync) return ValueTask.FromResult(_nonces.Add(nonce));
    }
}

public sealed class FileNonceStore(string storePath) : INonceStore
{
    public async ValueTask<bool> TryConsumeAsync(string nonce, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(nonce) || nonce.Length > 128 || nonce.Any(c => !char.IsAsciiHexDigit(c))) return false;
        using var handle = SafeArtifactPath.OpenPreparedOutputFile(storePath, 1024 * 1024, requireEmpty: false);
        var length = RandomAccess.GetLength(handle);
        var existing = new byte[checked((int)length)];
        var total = 0;
        while (total < existing.Length)
        {
            var read = await RandomAccess.ReadAsync(handle, existing.AsMemory(total), total, cancellationToken).ConfigureAwait(false);
            if (read == 0) throw new EndOfStreamException("Nonce store was truncated during validation.");
            total += read;
        }
        var text = System.Text.Encoding.ASCII.GetString(existing);
        if (text.Split('\n', StringSplitOptions.RemoveEmptyEntries).Contains(nonce, StringComparer.Ordinal)) return false;
        var line = System.Text.Encoding.ASCII.GetBytes(nonce + "\n");
        if (length + line.Length > 1024 * 1024) throw new IOException("Nonce store reached its fixed safety limit.");
        await RandomAccess.WriteAsync(handle, line, length, cancellationToken).ConfigureAwait(false);
        RandomAccess.FlushToDisk(handle);
        return true;
    }
}
