using System.Buffers.Binary;

namespace LateralMovementSimulator;

public static class EthernetIpv4TcpBuilder
{
    private static readonly byte[] ClientMac = [0x02, 0, 0, 0, 0, 1];
    private static readonly byte[] ServerMac = [0x02, 0, 0, 0, 0, 2];

    public static byte[] Build(DocumentationAddress source, DocumentationAddress destination, bool fromClient, uint sequence, uint acknowledgment, byte flags, ReadOnlySpan<byte> payload)
    {
        var packet = new byte[14 + 20 + 20 + payload.Length];
        var destinationMac = fromClient ? ServerMac : ClientMac;
        var sourceMac = fromClient ? ClientMac : ServerMac;
        destinationMac.CopyTo(packet, 0);
        sourceMac.CopyTo(packet, 6);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(12), 0x0800);

        var ip = packet.AsSpan(14, 20);
        ip[0] = 0x45;
        ip[1] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(ip[2..], checked((ushort)(40 + payload.Length)));
        BinaryPrimitives.WriteUInt16BigEndian(ip[4..], (ushort)(sequence & 0xFFFF));
        BinaryPrimitives.WriteUInt16BigEndian(ip[6..], 0x4000);
        ip[8] = 64;
        ip[9] = 6;
        source.ToBytes().CopyTo(ip[12..16]);
        destination.ToBytes().CopyTo(ip[16..20]);
        BinaryPrimitives.WriteUInt16BigEndian(ip[10..], Checksum(ip));

        var tcp = packet.AsSpan(34, 20 + payload.Length);
        BinaryPrimitives.WriteUInt16BigEndian(tcp, fromClient ? (ushort)49152 : (ushort)445);
        BinaryPrimitives.WriteUInt16BigEndian(tcp[2..], fromClient ? (ushort)445 : (ushort)49152);
        BinaryPrimitives.WriteUInt32BigEndian(tcp[4..], sequence);
        BinaryPrimitives.WriteUInt32BigEndian(tcp[8..], acknowledgment);
        tcp[12] = 0x50;
        tcp[13] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(tcp[14..], 64240);
        payload.CopyTo(tcp[20..]);
        BinaryPrimitives.WriteUInt16BigEndian(tcp[16..], TcpChecksum(source, destination, tcp));
        return packet;
    }

    private static ushort TcpChecksum(DocumentationAddress source, DocumentationAddress destination, ReadOnlySpan<byte> tcp)
    {
        var pseudo = new byte[12 + tcp.Length + (tcp.Length & 1)];
        source.ToBytes().CopyTo(pseudo, 0);
        destination.ToBytes().CopyTo(pseudo, 4);
        pseudo[9] = 6;
        BinaryPrimitives.WriteUInt16BigEndian(pseudo.AsSpan(10), checked((ushort)tcp.Length));
        tcp.CopyTo(pseudo.AsSpan(12));
        return Checksum(pseudo);
    }

    private static ushort Checksum(ReadOnlySpan<byte> data)
    {
        uint sum = 0;
        var i = 0;
        for (; i + 1 < data.Length; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(data[i..]);
        if (i < data.Length) sum += (uint)data[i] << 8;
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }
}
