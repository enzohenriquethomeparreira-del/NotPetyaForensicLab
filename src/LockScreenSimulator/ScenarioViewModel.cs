using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace LockScreenSimulator;

public sealed class ScenarioViewModel(Guid scenarioId, string message, TimeSpan remaining) : INotifyPropertyChanged
{
    public Guid ScenarioId { get; } = scenarioId;
    public string Message { get; } = message;
    public TimeSpan Remaining { get; private set; } = remaining < TimeSpan.Zero ? TimeSpan.Zero : remaining;
    public string RemainingText => Remaining.ToString(@"hh\:mm\:ss");
    public event PropertyChangedEventHandler? PropertyChanged;

    public void Tick()
    {
        if (Remaining > TimeSpan.Zero) Remaining = Remaining.Subtract(TimeSpan.FromSeconds(1));
        if (Remaining < TimeSpan.Zero) Remaining = TimeSpan.Zero;
        OnPropertyChanged(nameof(Remaining));
        OnPropertyChanged(nameof(RemainingText));
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
