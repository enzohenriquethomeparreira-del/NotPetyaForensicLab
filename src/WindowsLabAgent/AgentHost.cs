using System.Text.Json;
using ForensicTelemetry;
using System.Security.Cryptography;
using Shared.Contracts;

namespace WindowsLabAgent;

public sealed class AgentHost(
    Func<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>, CancellationToken, ValueTask<ValidationResult>> validateManifest,
    Func<ValidationResult> attestEnvironment,
    Func<ScenarioManifest, bool> confirmLocally,
    OperationDispatcher dispatcher)
{
    public async Task<int> RunAsync(string manifestPath, string signaturePath, CancellationToken cancellationToken)
    {
        var json = await File.ReadAllBytesAsync(manifestPath, cancellationToken).ConfigureAwait(false);
        var signature = await File.ReadAllBytesAsync(signaturePath, cancellationToken).ConfigureAwait(false);
        var provisionalId = TryReadScenarioId(json);
        var state = new AgentStateMachine(provisionalId);
        state.TryTransition(AgentState.Created, AgentState.Validating);

        var validation = await validateManifest(json, signature, cancellationToken).ConfigureAwait(false);
        if (!validation.IsValid)
        {
            LabEventSource.Log.ValidationRejected(validation.Code, validation.Message);
            state.TryTransition(AgentState.Validating, AgentState.Rejected);
            return 10;
        }

        var attestation = attestEnvironment();
        if (!attestation.IsValid)
        {
            LabEventSource.Log.ValidationRejected(attestation.Code, attestation.Message);
            state.TryTransition(AgentState.Validating, AgentState.Rejected);
            return 20;
        }

        var manifest = JsonSerializer.Deserialize<ScenarioManifest>(json, ContractJson.CreateOptions())
            ?? throw new InvalidDataException("Validated manifest could not be materialized.");
        if (!confirmLocally(manifest))
        {
            state.TryTransition(AgentState.Validating, AgentState.Rejected);
            return 10;
        }

        var preflight = ExecutionPreflight.Validate(manifest);
        if (!preflight.IsValid)
        {
            LabEventSource.Log.ValidationRejected(preflight.Code, preflight.Message);
            state.TryTransition(AgentState.Validating, AgentState.Rejected);
            return 20;
        }

        state.TryTransition(AgentState.Validating, AgentState.Ready);
        state.TryTransition(AgentState.Ready, AgentState.Executing);
        var telemetryHandle = SafeArtifactPath.OpenPreparedOutputFile(manifest.Paths.TelemetryJsonl, 16 * 1024 * 1024);
        await using var telemetry = new HashChainWriter(telemetryHandle, manifest.ScenarioId, manifest.AgentId);
        await telemetry.AppendAsync("ScenarioStarted", new Dictionary<string, string> { ["state"] = state.Current.ToString() }, cancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(manifest.Limits.MaximumRuntimeSeconds));
        var arguments = OperationArguments.FromManifest(manifest, SHA256.HashData(CanonicalJson.Canonicalize(json)));
        try
        {
            foreach (var operation in manifest.Operations)
            {
                var result = await dispatcher.DispatchAsync(new OperationRequest(manifest.ScenarioId, operation, arguments), timeout.Token).ConfigureAwait(false);
                await telemetry.AppendAsync("OperationCompleted", new Dictionary<string, string> { ["operation"] = operation.ToString(), ["code"] = result.Code, ["success"] = result.Success.ToString() }, timeout.Token);
                if (!result.Success) throw new InvalidOperationException($"{result.Code}: {result.Message}");
            }
            state.TryTransition(AgentState.Executing, AgentState.Collecting);
            state.TryTransition(AgentState.Collecting, AgentState.Completed);
            await telemetry.AppendAsync("ScenarioCompleted", new Dictionary<string, string> { ["exitCode"] = "0" }, CancellationToken.None);
            return 0;
        }
        catch (OperationCanceledException)
        {
            state.TryTransition(AgentState.Executing, AgentState.Aborted);
            state.TryTransition(AgentState.Aborted, AgentState.Collecting);
            var collected = await CollectAfterFailureAsync(dispatcher, manifest.ScenarioId, arguments).ConfigureAwait(false);
            state.TryTransition(AgentState.Collecting, AgentState.Completed);
            await telemetry.AppendAsync("ScenarioAborted", new Dictionary<string, string> { ["exitCode"] = "40", ["collectionSucceeded"] = collected.ToString() }, CancellationToken.None);
            return 40;
        }
        catch
        {
            state.TryTransition(AgentState.Executing, AgentState.Aborted);
            state.TryTransition(AgentState.Aborted, AgentState.Collecting);
            var collected = await CollectAfterFailureAsync(dispatcher, manifest.ScenarioId, arguments).ConfigureAwait(false);
            state.TryTransition(AgentState.Collecting, AgentState.Completed);
            await telemetry.AppendAsync("ScenarioFailed", new Dictionary<string, string> { ["exitCode"] = "30", ["collectionSucceeded"] = collected.ToString() }, CancellationToken.None);
            return 30;
        }
    }

    private static async ValueTask<bool> CollectAfterFailureAsync(OperationDispatcher dispatcher, Guid scenarioId, IReadOnlyDictionary<string, string> arguments)
    {
        using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            var result = await dispatcher.DispatchAsync(new OperationRequest(scenarioId, AllowedOperation.CollectArtifacts, arguments), budget.Token).ConfigureAwait(false);
            return result.Success;
        }
        catch { return false; }
    }

    private static Guid TryReadScenarioId(ReadOnlySpan<byte> json)
    {
        try
        {
            using var document = JsonDocument.Parse(json.ToArray());
            return document.RootElement.TryGetProperty("scenarioId", out var id) && id.TryGetGuid(out var value) ? value : Guid.Empty;
        }
        catch (JsonException) { return Guid.Empty; }
    }
}
