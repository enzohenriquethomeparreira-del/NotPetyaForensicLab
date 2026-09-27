namespace DiskImageSimulator;

public sealed record ByteChange(int Offset, byte Before, byte After);
public sealed record SectorDiff(IReadOnlyList<ByteChange> Changes, double BeforeEntropy, double AfterEntropy);

public static class SectorDiffReporter
{
    public static SectorDiff Create(ReadOnlySpan<byte> before, ReadOnlySpan<byte> after)
    {
        if (before.Length != after.Length) throw new ArgumentException("Compared buffers must have equal length.");
        var changes = new List<ByteChange>();
        for (var i = 0; i < before.Length; i++)
            if (before[i] != after[i]) changes.Add(new ByteChange(i, before[i], after[i]));
        return new SectorDiff(changes, Entropy(before), Entropy(after));
    }

    private static double Entropy(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty) return 0;
        Span<int> counts = stackalloc int[256];
        foreach (var value in bytes) counts[value]++;
        double entropy = 0;
        foreach (var count in counts)
        {
            if (count == 0) continue;
            var probability = (double)count / bytes.Length;
            entropy -= probability * Math.Log2(probability);
        }
        return entropy;
    }
}
