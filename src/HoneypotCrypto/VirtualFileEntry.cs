using System.Buffers.Binary;
using System.Text;

namespace HoneypotCrypto;

public sealed record VirtualFileEntry(
    int Index,
    Guid FileId,
    string LogicalName,
    long DataOffset,
    int PlaintextLength,
    int AllocatedLength,
    byte[] OriginalSha256,
    bool Encrypted,
    byte[] Nonce,
    byte[] Tag,
    byte[] WrappedKey)
{
    public byte[] Serialize()
    {
        var data = new byte[ForensicVolumeLayout.DirectoryEntrySize];
        data[0] = 1;
        data[1] = Encrypted ? (byte)1 : (byte)0;
        FileId.TryWriteBytes(data.AsSpan(4, 16));
        BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(20), DataOffset);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(28), PlaintextLength);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(32), AllocatedLength);
        if (OriginalSha256.Length != 32) throw new InvalidDataException("Original SHA-256 length invalid.");
        OriginalSha256.CopyTo(data, 36);
        var name = Encoding.UTF8.GetBytes(LogicalName);
        if (name.Length is 0 or > 128) throw new InvalidDataException("Logical name must use 1-128 UTF-8 bytes.");
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(68), (ushort)name.Length);
        name.CopyTo(data, 70);
        if (Nonce.Length > 12 || Tag.Length > 16 || WrappedKey.Length > 256) throw new InvalidDataException("Cryptographic metadata exceeds fixed entry capacity.");
        Nonce.CopyTo(data, 198);
        Tag.CopyTo(data, 210);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(226), (ushort)WrappedKey.Length);
        WrappedKey.CopyTo(data, 228);
        return data;
    }

    public static VirtualFileEntry Parse(int index, ReadOnlySpan<byte> data)
    {
        if (data.Length != ForensicVolumeLayout.DirectoryEntrySize || data[0] != 1) throw new InvalidDataException("Invalid virtual directory entry.");
        var nameLength = BinaryPrimitives.ReadUInt16LittleEndian(data[68..]);
        var wrappedLength = BinaryPrimitives.ReadUInt16LittleEndian(data[226..]);
        if (nameLength is 0 or > 128 || wrappedLength > 256) throw new InvalidDataException("Virtual entry field length is invalid.");
        var encrypted = data[1] == 1;
        return new VirtualFileEntry(
            index,
            new Guid(data.Slice(4, 16)),
            Encoding.UTF8.GetString(data.Slice(70, nameLength)),
            BinaryPrimitives.ReadInt64LittleEndian(data[20..]),
            BinaryPrimitives.ReadInt32LittleEndian(data[28..]),
            BinaryPrimitives.ReadInt32LittleEndian(data[32..]),
            data.Slice(36, 32).ToArray(),
            encrypted,
            encrypted ? data.Slice(198, 12).ToArray() : [],
            encrypted ? data.Slice(210, 16).ToArray() : [],
            encrypted ? data.Slice(228, wrappedLength).ToArray() : []);
    }
}
