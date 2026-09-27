using Microsoft.Win32.SafeHandles;

namespace LateralMovementSimulator;

public sealed record ConversationScenario(DocumentationAddress Client, DocumentationAddress Server, DateTimeOffset StartUtc)
{
    public static ConversationScenario CreateDefault(string client, string server) => new(DocumentationAddress.Parse(client), DocumentationAddress.Parse(server), DateTimeOffset.UnixEpoch);
}

public sealed record ConversationResult(int PacketCount, long Length, IReadOnlyList<string> Stages);

public static class OfflineConversationGenerator
{
    public static async ValueTask<ConversationResult> GenerateAsync(SafeFileHandle output, ConversationScenario scenario, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(output);
        var writer = new PcapNgWriter(output);
        await writer.WriteHeaderAsync(cancellationToken).ConfigureAwait(false);
        var timestamp = scenario.StartUtc.ToUnixTimeMilliseconds() * 1000;
        var packetCount = 0;
        var stages = new List<string>();

        async ValueTask Add(bool fromClient, uint seq, uint ack, byte flags, ReadOnlyMemory<byte> payload, string stage)
        {
            var source = fromClient ? scenario.Client : scenario.Server;
            var destination = fromClient ? scenario.Server : scenario.Client;
            var packet = EthernetIpv4TcpBuilder.Build(source, destination, fromClient, seq, ack, flags, payload.Span);
            await writer.WritePacketAsync(packet, timestamp + packetCount * 1000L, stage, cancellationToken).ConfigureAwait(false);
            stages.Add(stage);
            packetCount++;
        }

        uint clientSeq = 1000, serverSeq = 5000;
        await Add(true, clientSeq, 0, 0x02, ReadOnlyMemory<byte>.Empty, "TCP.SYN"); clientSeq++;
        await Add(false, serverSeq, clientSeq, 0x12, ReadOnlyMemory<byte>.Empty, "TCP.SYN-ACK"); serverSeq++;
        await Add(true, clientSeq, serverSeq, 0x10, ReadOnlyMemory<byte>.Empty, "TCP.ACK");

        foreach (var frame in SmbConversationModel.CreateFrames())
        {
            var payload = frame.BuildPayload(frame.MessageId);
            var fromClient = !frame.Response;
            await Add(fromClient, fromClient ? clientSeq : serverSeq, fromClient ? serverSeq : clientSeq, 0x18, payload, frame.Stage);
            if (fromClient) clientSeq = checked(clientSeq + (uint)payload.Length); else serverSeq = checked(serverSeq + (uint)payload.Length);
        }
        await Add(true, clientSeq, serverSeq, 0x11, ReadOnlyMemory<byte>.Empty, "TCP.FIN");
        writer.Flush();
        return new ConversationResult(packetCount, RandomAccess.GetLength(output), stages);
    }
}
