using System.Diagnostics.Tracing;

namespace ForensicTelemetry;

[EventSource(Name = "ForensicLab-Agent")]
public sealed class LabEventSource : EventSource
{
    public static readonly LabEventSource Log = new();
    private LabEventSource() { }

    [Event(1, Level = EventLevel.Informational)]
    public void StateChanged(string scenarioId, string previous, string current) => WriteEvent(1, scenarioId, previous, current);

    [Event(2, Level = EventLevel.Informational)]
    public void ArtifactWritten(string scenarioId, string kind, string sha256, long length) => WriteEvent(2, scenarioId, kind, sha256, length);

    [Event(3, Level = EventLevel.Warning)]
    public void ValidationRejected(string code, string message) => WriteEvent(3, code, message);
}
