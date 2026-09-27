using System.Security.Cryptography;

namespace HoneypotCrypto;

public sealed class FileKeyMaterial : IDisposable
{
    public byte[] Key { get; } = RandomNumberGenerator.GetBytes(32);
    public byte[] Nonce { get; } = RandomNumberGenerator.GetBytes(12);
    public void Dispose() => CryptographicOperations.ZeroMemory(Key);
}

public static class CngKeyProvider
{
    public static FileKeyMaterial GenerateFileMaterial() => new();
}
