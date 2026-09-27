using System.Buffers.Binary;
using System.Text;

namespace LateralMovementSimulator;

public sealed record ConversationFrame(string Stage, ushort Command, bool Response, ulong MessageId, string Marker)
{
    public byte[] BuildPayload(ulong messageId)
    {
        var marker = Encoding.ASCII.GetBytes(Marker);
        var smbLength = checked(64 + marker.Length);
        var data = new byte[4 + smbLength];
        data[0] = 0;
        data[1] = (byte)(smbLength >> 16);
        data[2] = (byte)(smbLength >> 8);
        data[3] = (byte)smbLength;
        data[4] = 0xFE; data[5] = (byte)'S'; data[6] = (byte)'M'; data[7] = (byte)'B';
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(8), 64);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(16), Command);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(20), Response ? 1u : 0u);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(28), messageId);
        marker.CopyTo(data, 68);
        return data;
    }
}

public static class SmbConversationModel
{
    public static IReadOnlyList<ConversationFrame> CreateFrames() =>
    [
        new("Negotiate.Request", 0, false, 1, "LAB_NEGOTIATE_REQUEST"), new("Negotiate.Response", 0, true, 1, "LAB_NEGOTIATE_RESPONSE"),
        new("SessionSetup.Request", 1, false, 2, "LAB_IDENTITY_NON_REUSABLE"), new("SessionSetup.Response", 1, true, 2, "LAB_SESSION_ACCEPTED_FIXTURE"),
        new("TreeConnect.Request", 3, false, 3, "LAB_IPC$_TREE_CONNECT"), new("TreeConnect.Response", 3, true, 3, "LAB_TREE_ID_FIXTURE"),
        new("PipeCreate.Request", 5, false, 4, "LAB_NAMED_PIPE_FIXTURE"), new("PipeCreate.Response", 5, true, 4, "LAB_PIPE_HANDLE_INVALID"),
        new("DceRpc.Marker", 11, false, 5, "LAB_DCERPC_MARKER_NOT_A_RPC_PDU"), new("DceRpc.MarkerAck", 11, true, 5, "LAB_DCERPC_ACK_MARKER"),
        new("Service.Marker", 9, false, 6, "LAB_SERVICE_CREATE_FIXTURE"), new("Service.MarkerResult", 9, true, 6, "LAB_SERVICE_RESULT_FIXTURE"),
        new("Close.Request", 6, false, 7, "LAB_CLOSE_REQUEST"), new("Close.Response", 6, true, 7, "LAB_CLOSE_RESPONSE")
    ];
}
