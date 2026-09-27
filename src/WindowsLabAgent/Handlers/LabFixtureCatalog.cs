using System.Text;

namespace WindowsLabAgent.Handlers;

public static class LabFixtureCatalog
{
    public static IReadOnlyList<(string Name, byte[] Content)> Create() =>
    [
        ("finance-report.txt", Encoding.UTF8.GetBytes("Known forensic fixture: quarterly report 2026.")),
        ("legacy-config.ini", Encoding.UTF8.GetBytes("[lab]\nmode=forensic\nnetwork=offline\n")),
        ("binary-fixture.bin", Enumerable.Range(0, 16384).Select(i => (byte)(i * 31)).ToArray())
    ];

    public static long TotalPlaintextBytes => Create().Sum(fixture => (long)fixture.Content.Length);
}
