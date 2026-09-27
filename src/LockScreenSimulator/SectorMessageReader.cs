using System.Text;
using DiskImageSimulator;

namespace LockScreenSimulator;

public sealed record SectorDisplayModel(Guid ScenarioId, string Message);

public static class SectorMessageReader
{
    public static SectorDisplayModel Read(string imagePath)
    {
        using var stream = new FileStream(imagePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var sector = new byte[SyntheticMbrLayout.SectorSize];
        stream.ReadExactly(sector);
        if (!sector.AsSpan(SyntheticMbrLayout.OemOffset, SyntheticMbrLayout.OemLength).SequenceEqual("FORLAB01"u8) ||
            sector[SyntheticMbrLayout.BootMarkerOffset] != 0x55 || sector[SyntheticMbrLayout.BootMarkerOffset + 1] != 0xAA)
            throw new InvalidDataException("The image does not contain a recognized synthetic laboratory sector.");
        var scenarioId = new Guid(sector.AsSpan(SyntheticMbrLayout.ScenarioIdOffset, 16));
        var messageBytes = sector.AsSpan(SyntheticMbrLayout.MessageOffset, SyntheticMbrLayout.MessageMaximumLength);
        var terminator = messageBytes.IndexOf((byte)0);
        if (terminator >= 0) messageBytes = messageBytes[..terminator];
        return new SectorDisplayModel(scenarioId, Encoding.UTF8.GetString(messageBytes));
    }
}
