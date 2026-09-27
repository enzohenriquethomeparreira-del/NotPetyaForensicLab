using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Shared.Contracts;
using Microsoft.Win32.SafeHandles;

namespace ForensicTelemetry;

public sealed class HashChainWriter : IAsyncDisposable
{
    private static readonly string ZeroHash = new('0', 64);
    private readonly FileStream _stream;
    private readonly Guid _scenarioId;
    private readonly Guid _agentId;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private long _sequence;
    private string _previousHash = ZeroHash;

    public HashChainWriter(SafeFileHandle handle, Guid scenarioId, Guid agentId)
    {
        ArgumentNullException.ThrowIfNull(handle);
        _scenarioId = scenarioId;
        _agentId = agentId;
        _stream = new FileStream(handle, FileAccess.Write, 4096, isAsync: true);
    }

    public async ValueTask<ForensicEvent> AppendAsync(string eventType, IReadOnlyDictionary<string, string> fields, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(eventType);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var sequence = checked(_sequence + 1);
            var timestamp = DateTimeOffset.UtcNow;
            var normalized = new SortedDictionary<string, string>(StringComparer.Ordinal);
            foreach (var pair in fields) normalized.Add(pair.Key, pair.Value);
            var hash = ComputeHash(_scenarioId, _agentId, sequence, timestamp, eventType, normalized, _previousHash);
            var item = new ForensicEvent(_scenarioId, _agentId, sequence, timestamp, eventType, normalized, _previousHash, hash);
            var serialized = JsonSerializer.SerializeToUtf8Bytes(item, ContractJson.CreateOptions());
            var line = new byte[serialized.Length + 1];
            serialized.CopyTo(line, 0);
            line[^1] = (byte)'\n';
            var rollbackOffset = _stream.Position;
            try
            {
                await _stream.WriteAsync(line, cancellationToken).ConfigureAwait(false);
                await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                _stream.Flush(flushToDisk: true);
                _sequence = sequence;
                _previousHash = hash;
                return item;
            }
            catch
            {
                _stream.SetLength(rollbackOffset);
                _stream.Position = rollbackOffset;
                _stream.Flush(flushToDisk: true);
                throw;
            }
        }
        finally { _gate.Release(); }
    }

    public static async Task<bool> VerifyAsync(string path, CancellationToken cancellationToken)
    {
        string previous = ZeroHash;
        long expectedSequence = 1;
        try
        {
            using var reader = new StreamReader(path, Encoding.UTF8, detectEncodingFromByteOrderMarks: false);
            while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
            {
                var item = JsonSerializer.Deserialize<ForensicEvent>(line, ContractJson.CreateOptions());
                if (item is null || item.Sequence != expectedSequence || item.PreviousHash != previous) return false;
                var normalized = new SortedDictionary<string, string>(StringComparer.Ordinal);
                foreach (var pair in item.Fields) normalized.Add(pair.Key, pair.Value);
                var computed = ComputeHash(item.ScenarioId, item.AgentId, item.Sequence, item.TimestampUtc, item.EventType, normalized, item.PreviousHash);
                if (!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(computed), Convert.FromHexString(item.CurrentHash))) return false;
                previous = item.CurrentHash;
                expectedSequence++;
            }
            return expectedSequence > 1;
        }
        catch (Exception ex) when (ex is JsonException or FormatException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static string ComputeHash(Guid scenarioId, Guid agentId, long sequence, DateTimeOffset timestamp, string type, IEnumerable<KeyValuePair<string, string>> fields, string previous)
    {
        using var memory = new MemoryStream();
        using (var json = new Utf8JsonWriter(memory))
        {
            json.WriteStartObject();
            json.WriteString("scenarioId", scenarioId);
            json.WriteString("agentId", agentId);
            json.WriteNumber("sequence", sequence);
            json.WriteString("timestampUtc", timestamp);
            json.WriteString("eventType", type);
            json.WritePropertyName("fields");
            json.WriteStartObject();
            foreach (var pair in fields) json.WriteString(pair.Key, pair.Value);
            json.WriteEndObject();
            json.WriteString("previousHash", previous);
            json.WriteEndObject();
        }
        return Convert.ToHexString(SHA256.HashData(memory.ToArray()));
    }

    public async ValueTask DisposeAsync()
    {
        await _stream.DisposeAsync().ConfigureAwait(false);
        _gate.Dispose();
    }
}
