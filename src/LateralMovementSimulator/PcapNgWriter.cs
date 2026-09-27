using Microsoft.Win32.SafeHandles;
using System.Buffers.Binary;
using System.Text;

namespace LateralMovementSimulator;

public sealed class PcapNgWriter(SafeFileHandle handle)
{
    private long _offset;

    public async ValueTask WriteHeaderAsync(CancellationToken cancellationToken)
    {
        await WriteAsync(BuildSectionHeader(), cancellationToken).ConfigureAwait(false);
        await WriteAsync(BuildInterfaceDescription(), cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask WritePacketAsync(ReadOnlyMemory<byte> packet, long timestampMicroseconds, string comment, CancellationToken cancellationToken) =>
        await WriteAsync(BuildEnhancedPacket(packet.Span, timestampMicroseconds, comment), cancellationToken).ConfigureAwait(false);

    public void Flush() => RandomAccess.FlushToDisk(handle);

    private async ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        await RandomAccess.WriteAsync(handle, data, _offset, cancellationToken).ConfigureAwait(false);
        _offset = checked(_offset + data.Length);
    }

    private static byte[] BuildSectionHeader()
    {
        var data = new byte[28];
        BinaryPrimitives.WriteUInt32LittleEndian(data, 0x0A0D0D0A);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4), 28);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(8), 0x1A2B3C4D);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(12), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(14), 0);
        BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(16), -1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(24), 28);
        return data;
    }

    private static byte[] BuildInterfaceDescription()
    {
        var data = new byte[20];
        BinaryPrimitives.WriteUInt32LittleEndian(data, 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4), 20);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(8), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(12), 65535);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(16), 20);
        return data;
    }

    private static byte[] BuildEnhancedPacket(ReadOnlySpan<byte> packet, long timestampMicroseconds, string comment)
    {
        var packetPadded = (packet.Length + 3) & ~3;
        var commentBytes = Encoding.UTF8.GetBytes(comment);
        if (commentBytes.Length > ushort.MaxValue) throw new ArgumentOutOfRangeException(nameof(comment));
        var commentPadded = (commentBytes.Length + 3) & ~3;
        var totalLength = checked(32 + packetPadded + 4 + commentPadded + 4);
        var data = new byte[totalLength];
        BinaryPrimitives.WriteUInt32LittleEndian(data, 6);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4), (uint)totalLength);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(8), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(12), (uint)(timestampMicroseconds >> 32));
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(16), (uint)timestampMicroseconds);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(20), (uint)packet.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(24), (uint)packet.Length);
        packet.CopyTo(data.AsSpan(28));
        var optionOffset = 28 + packetPadded;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(optionOffset), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(optionOffset + 2), (ushort)commentBytes.Length);
        commentBytes.CopyTo(data, optionOffset + 4);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(totalLength - 4), (uint)totalLength);
        return data;
    }
}
