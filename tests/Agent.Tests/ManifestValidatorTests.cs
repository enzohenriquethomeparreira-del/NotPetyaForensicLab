using System.Security.Cryptography;
using System.Text.Json;
using Shared.Contracts;
using WindowsLabAgent;

namespace Agent.Tests;

public sealed class ManifestValidatorTests
{
    [Fact]
    public async Task Valid_signature_is_accepted_and_nonce_is_consumed()
    {
        using var rsa = RSA.Create(2048);
        var now = DateTimeOffset.UtcNow;
        var manifest = ScenarioManifest.CreateForTests(Guid.NewGuid(), "vm-test", now) with
        {
            ControllerThumbprint = PinnedKeyProvider.ComputeThumbprint(rsa)
        };
        var json = JsonSerializer.SerializeToUtf8Bytes(manifest, ContractJson.CreateOptions());
        var canonical = CanonicalJson.Canonicalize(json);
        var signature = rsa.SignData(canonical, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        var validator = new ManifestValidator(rsa, new MemoryNonceStore(), () => now, () => "vm-test");
        Assert.True((await validator.ValidateAsync(json, signature, default)).IsValid);
        Assert.Equal("NONCE_REPLAY", (await validator.ValidateAsync(json, signature, default)).Code);
    }

    [Fact]
    public void Duplicate_json_keys_are_rejected() =>
        Assert.Throws<JsonException>(() => CanonicalJson.Canonicalize("{\"a\":1,\"a\":2}"u8));

    [Fact]
    public async Task Invalid_signature_is_rejected()
    {
        using var rsa = RSA.Create(2048);
        var now = DateTimeOffset.UtcNow;
        var manifest = ScenarioManifest.CreateForTests(Guid.NewGuid(), "vm-test", now) with { ControllerThumbprint = PinnedKeyProvider.ComputeThumbprint(rsa) };
        var json = JsonSerializer.SerializeToUtf8Bytes(manifest, ContractJson.CreateOptions());
        var validator = new ManifestValidator(rsa, new MemoryNonceStore(), () => now, () => "vm-test");
        Assert.Equal("SIGNATURE_INVALID", (await validator.ValidateAsync(json, new byte[256], default)).Code);
    }

    [Fact]
    public void Integer_enum_values_are_rejected_during_deserialization()
    {
        var options = ContractJson.CreateOptions();
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<AllowedOperation>("999", options));
    }
}
