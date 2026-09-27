using System.Buffers.Binary;

namespace HoneypotCrypto;

public sealed record ForensicVolumeHeader(
    int Version,
    int BlockSize,
    int MaximumFiles,
    int FileCount,
    long DirectoryOffset,
    long DataOffset,
    long NextDataOffset,
    long DataEnd,
    long JournalOffset,
    long EscrowOffset,
    long VolumeSize)
{
    public byte[] Serialize()
    {
        var data = new byte[ForensicVolumeLayout.HeaderSize];
        ForensicVolumeLayout.Magic.CopyTo(data);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(8), Version);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(12), BlockSize);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(16), MaximumFiles);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(20), FileCount);
        BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(24), DirectoryOffset);
        BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(32), DataOffset);
        BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(40), NextDataOffset);
        BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(48), DataEnd);
        BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(56), JournalOffset);
        BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(64), EscrowOffset);
        BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(72), VolumeSize);
        return data;
    }

    public static ForensicVolumeHeader Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length != ForensicVolumeLayout.HeaderSize || !data[..8].SequenceEqual(ForensicVolumeLayout.Magic)) throw new InvalidDataException("Invalid forensic-volume header.");
        var header = new ForensicVolumeHeader(
            BinaryPrimitives.ReadInt32LittleEndian(data[8..]), BinaryPrimitives.ReadInt32LittleEndian(data[12..]),
            BinaryPrimitives.ReadInt32LittleEndian(data[16..]), BinaryPrimitives.ReadInt32LittleEndian(data[20..]),
            BinaryPrimitives.ReadInt64LittleEndian(data[24..]), BinaryPrimitives.ReadInt64LittleEndian(data[32..]),
            BinaryPrimitives.ReadInt64LittleEndian(data[40..]), BinaryPrimitives.ReadInt64LittleEndian(data[48..]),
            BinaryPrimitives.ReadInt64LittleEndian(data[56..]), BinaryPrimitives.ReadInt64LittleEndian(data[64..]),
            BinaryPrimitives.ReadInt64LittleEndian(data[72..]));
        try
        {
            var directoryEnd = checked(header.DirectoryOffset + (long)header.MaximumFiles * ForensicVolumeLayout.DirectoryEntrySize);
            if (header.Version != 1 || header.BlockSize is < 512 or > 65536 || (header.BlockSize & (header.BlockSize - 1)) != 0 ||
                header.MaximumFiles is < 1 or > 1024 || header.FileCount < 0 || header.FileCount > header.MaximumFiles ||
                header.VolumeSize is < 1048576 or > 536870912 || header.DirectoryOffset != ForensicVolumeLayout.HeaderSize ||
                directoryEnd > header.DataOffset || header.DataOffset % header.BlockSize != 0 || header.DataOffset > header.NextDataOffset ||
                header.NextDataOffset > header.DataEnd || header.DataEnd != header.JournalOffset ||
                checked(header.JournalOffset + ForensicVolumeLayout.JournalSize) != header.EscrowOffset ||
                checked(header.EscrowOffset + ForensicVolumeLayout.EscrowRegionSize) != header.VolumeSize)
                throw new InvalidDataException("Forensic-volume header invariants failed.");
        }
        catch (OverflowException ex) { throw new InvalidDataException("Forensic-volume header arithmetic overflowed.", ex); }
        return header;
    }
}
