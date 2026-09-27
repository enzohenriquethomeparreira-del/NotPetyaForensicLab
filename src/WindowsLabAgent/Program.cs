using System.Security.Cryptography;
using WindowsLabAgent.Handlers;

namespace WindowsLabAgent;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var options = ParseArguments(args);
        if (!Required(options, "manifest", "signature", "public-key", "recovery-key", "nonce-store", "fingerprint") || options.GetValueOrDefault("confirm") != "LAB-ONLY")
        {
            Console.Error.WriteLine("Usage: WindowsLabAgent --manifest file.json --signature file.sig --public-key controller.pem --recovery-key recovery-private.pem --nonce-store prepared.jsonl --fingerprint VM-ID --confirm LAB-ONLY");
            return 64;
        }

        try
        {
            _ = SafeArtifactPath.ValidateForLab(options["nonce-store"]);
            using var controllerKey = PinnedKeyProvider.LoadPublicKey(options["public-key"]);
            using var recoveryKey = RSA.Create();
            recoveryKey.ImportFromPem(await File.ReadAllTextAsync(options["recovery-key"]));
            var validator = new ManifestValidator(controllerKey, new FileNonceStore(options["nonce-store"]), () => DateTimeOffset.UtcNow, () => options["fingerprint"]);
            await using var state = new ScenarioRuntimeState(recoveryKey);
            var host = new AgentHost(validator.ValidateAsync, new EnvironmentAttestor().Attest, _ => true, HandlerFactory.Create(state));
            return await host.RunAsync(options["manifest"], options["signature"], ConsoleCancelToken.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Agent rejected execution: {ex.Message}");
            return 20;
        }
    }

    private static Dictionary<string, string> ParseArguments(string[] args)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 0; i + 1 < args.Length; i += 2)
            if (args[i].StartsWith("--", StringComparison.Ordinal)) result[args[i][2..]] = args[i + 1];
        return result;
    }

    private static bool Required(IReadOnlyDictionary<string, string> values, params string[] names) => names.All(n => values.TryGetValue(n, out var value) && !string.IsNullOrWhiteSpace(value));

    private static class ConsoleCancelToken
    {
        private static readonly CancellationTokenSource Source = new();
        static ConsoleCancelToken() => Console.CancelKeyPress += (_, e) => { e.Cancel = true; Source.Cancel(); };
        public static CancellationToken Token => Source.Token;
    }
}
