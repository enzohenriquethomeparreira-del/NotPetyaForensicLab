using System.Buffers.Binary;
using DiskImageSimulator;

namespace DiskImage.Tests;

public sealed class SyntheticMbrBuilderTests
{
    [Fact]
    public void Fields_are_written_at_exact_offsets()
    {
        var id = Guid.Parse("00112233-4455-6677-8899-aabbccddeeff");
        var hash = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var sector = SyntheticMbrBuilder.Build(id, hash, 0xA1B2C3D4, [1, 2, 3], "LAB MESSAGE");
        Assert.Equal(512, sector.Length);
        Assert.Equal(new byte[] { 0xEB, 0x3C, 0x90 }, sector[..3]);
        Assert.Equal("FORLAB01", System.Text.Encoding.ASCII.GetString(sector, 3, 8));
        Assert.Equal(id.ToByteArray(), sector[0x40..0x50]);
        Assert.Equal(hash, sector[0x50..0x70]);
        Assert.Equal(0xA1B2C3D4u, BinaryPrimitives.ReadUInt32LittleEndian(sector.AsSpan(0x1B8, 4)));
        Assert.Equal(0x55, sector[0x1FE]);
        Assert.Equal(0xAA, sector[0x1FF]);
    }

    [Fact]
    public void Oversized_signature_is_rejected() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => SyntheticMbrBuilder.Build(Guid.NewGuid(), new byte[32], 1, new byte[145], "x"));
}
