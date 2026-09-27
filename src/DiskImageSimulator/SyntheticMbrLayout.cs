namespace DiskImageSimulator;

public static class SyntheticMbrLayout
{
    public const int SectorSize = 512;
    public const int JumpOffset = 0x000, JumpLength = 3;
    public const int OemOffset = 0x003, OemLength = 8;
    public const int BpbOffset = 0x00B, BpbLength = 53;
    public const int ScenarioIdOffset = 0x040, ScenarioIdLength = 16;
    public const int ManifestHashOffset = 0x050, ManifestHashLength = 32;
    public const int SignatureOffset = 0x070, SignatureMaximumLength = 0x100 - SignatureOffset;
    public const int MessageOffset = 0x100, MessageMaximumLength = 0x1B8 - MessageOffset;
    public const int DiskIdOffset = 0x1B8, DiskIdLength = 4;
    public const int PartitionTableOffset = 0x1BE, PartitionTableLength = 64;
    public const int BootMarkerOffset = 0x1FE, BootMarkerLength = 2;
}
