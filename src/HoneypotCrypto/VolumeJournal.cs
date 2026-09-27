using System.Text.Json;

namespace HoneypotCrypto;

internal sealed record VolumeJournal(string Schema, string Stage, string Operation, int EntryIndex, string OldEntry, int StagedLength, string StagedSha256)
{
    public byte[] Serialize() => JsonSerializer.SerializeToUtf8Bytes(this);
    public static VolumeJournal Parse(ReadOnlySpan<byte> data) =>
        JsonSerializer.Deserialize<VolumeJournal>(data) ?? throw new InvalidDataException("Volume journal is empty.");
}

public enum TransformCheckpoint { AfterPrepared, AfterDataWritten, AfterEntryWritten }

public sealed class SimulatedPowerLossException(TransformCheckpoint checkpoint) : IOException($"Simulated interruption at {checkpoint}.")
{
    public TransformCheckpoint Checkpoint { get; } = checkpoint;
}
