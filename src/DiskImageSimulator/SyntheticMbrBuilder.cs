using System.Buffers.Binary;
using System.Text;

namespace DiskImageSimulator;

public static class SyntheticMbrBuilder
{
    private static readonly byte[] JumpFixture = [0xEB, 0x3C, 0x90];
    private static readonly byte[] OemFixture = "FORLAB01"u8.ToArray();

    public static byte[] Build(Guid scenarioId, ReadOnlySpan<byte> manifestHash, uint diskId, ReadOnlySpan<byte> signatureFixture, string message)
    {
        if (scenarioId == Guid.Empty) throw new ArgumentException("Scenario ID is required.", nameof(scenarioId));
        if (manifestHash.Length != SyntheticMbrLayout.ManifestHashLength) throw new ArgumentException("Manifest hash must be SHA-256 (32 bytes).", nameof(manifestHash));
        if (signatureFixture.Length > SyntheticMbrLayout.SignatureMaximumLength) throw new ArgumentOutOfRangeException(nameof(signatureFixture));
        ArgumentNullException.ThrowIfNull(message);

        var sector = new byte[SyntheticMbrLayout.SectorSize];
        JumpFixture.CopyTo(sector, SyntheticMbrLayout.JumpOffset);
        OemFixture.CopyTo(sector, SyntheticMbrLayout.OemOffset);
        WriteSyntheticBpb(sector.AsSpan(SyntheticMbrLayout.BpbOffset, SyntheticMbrLayout.BpbLength));
        scenarioId.TryWriteBytes(sector.AsSpan(SyntheticMbrLayout.ScenarioIdOffset, SyntheticMbrLayout.ScenarioIdLength));
        manifestHash.CopyTo(sector.AsSpan(SyntheticMbrLayout.ManifestHashOffset, SyntheticMbrLayout.ManifestHashLength));
        signatureFixture.CopyTo(sector.AsSpan(SyntheticMbrLayout.SignatureOffset, signatureFixture.Length));
        WriteBoundedUtf8(message, sector.AsSpan(SyntheticMbrLayout.MessageOffset, SyntheticMbrLayout.MessageMaximumLength));
        BinaryPrimitives.WriteUInt32LittleEndian(sector.AsSpan(SyntheticMbrLayout.DiskIdOffset, 4), diskId);
        sector.AsSpan(SyntheticMbrLayout.PartitionTableOffset, SyntheticMbrLayout.PartitionTableLength).Clear();
        sector[SyntheticMbrLayout.BootMarkerOffset] = 0x55;
        sector[SyntheticMbrLayout.BootMarkerOffset + 1] = 0xAA;
        return sector;
    }

    private static void WriteSyntheticBpb(Span<byte> destination)
    {
        destination.Clear();
        BinaryPrimitives.WriteUInt16LittleEndian(destination[0..2], 512);
        destination[2] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(destination[3..5], 1);
        destination[5] = 0;
        BinaryPrimitives.WriteUInt16LittleEndian(destination[6..8], 0);
        destination[8] = 0xF8;
        "INERT-BPB-FIXTURE"u8.CopyTo(destination[16..]);
    }

    private static void WriteBoundedUtf8(string value, Span<byte> destination)
    {
        destination.Clear();
        var encoder = Encoding.UTF8.GetEncoder();
        encoder.Convert(value.AsSpan(), destination, flush: true, out _, out _, out _);
    }
}
