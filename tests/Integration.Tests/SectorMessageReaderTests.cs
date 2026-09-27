using DiskImageSimulator;
using LockScreenSimulator;

namespace Integration.Tests;

public sealed class SectorMessageReaderTests
{
    [Fact]
    public void Reader_extracts_lab_message_and_scenario()
    {
        var path = Path.GetTempFileName();
        var id = Guid.NewGuid();
        File.WriteAllBytes(path, SyntheticMbrBuilder.Build(id, new byte[32], 1, "SIG"u8, "Forensic simulation"));
        var model = SectorMessageReader.Read(path);
        Assert.Equal(id, model.ScenarioId);
        Assert.Equal("Forensic simulation", model.Message);
        File.Delete(path);
    }

    [Fact]
    public void Countdown_has_no_destructive_completion_callback()
    {
        var vm = new ScenarioViewModel(Guid.NewGuid(), "test", TimeSpan.FromSeconds(1));
        vm.Tick();
        vm.Tick();
        Assert.Equal(TimeSpan.Zero, vm.Remaining);
    }
}
