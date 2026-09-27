using System.Security.Cryptography;

namespace WindowsLabAgent;

public static class PinnedKeyProvider
{
    public static RSA LoadPublicKey(string pemPath)
    {
        var pem = File.ReadAllText(pemPath);
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa;
    }

    public static string ComputeThumbprint(RSA rsa) =>
        Convert.ToHexString(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo()));
}
