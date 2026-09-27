using System.Text.Json;
using WindowsLabAgent;

namespace SafetyInvariants.Tests;

public sealed class ManifestFuzzTests
{
    [Fact]
    public void Random_malformed_inputs_never_escape_documented_parser_failures()
    {
        var random = new Random(8675309);
        for (var i = 0; i < 500; i++)
        {
            var bytes = new byte[random.Next(0, 2048)];
            random.NextBytes(bytes);
            try { _ = CanonicalJson.Canonicalize(bytes); }
            catch (Exception ex) { Assert.True(ex is JsonException or ArgumentException, ex.GetType().FullName); }
        }
    }
}
