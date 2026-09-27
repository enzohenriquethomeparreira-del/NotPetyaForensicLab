using System.Threading;
using ForensicTelemetry;
using Shared.Contracts;

namespace WindowsLabAgent;

public sealed class AgentStateMachine(Guid scenarioId)
{
    private int _state = (int)AgentState.Created;
    public AgentState Current => (AgentState)Volatile.Read(ref _state);

    public bool TryTransition(AgentState expected, AgentState next)
    {
        if (!IsLegal(expected, next)) return false;
        if (Interlocked.CompareExchange(ref _state, (int)next, (int)expected) != (int)expected) return false;
        LabEventSource.Log.StateChanged(scenarioId.ToString("D"), expected.ToString(), next.ToString());
        return true;
    }

    private static bool IsLegal(AgentState from, AgentState to) => (from, to) switch
    {
        (AgentState.Created, AgentState.Validating) => true,
        (AgentState.Validating, AgentState.Ready or AgentState.Rejected) => true,
        (AgentState.Ready, AgentState.Executing) => true,
        (AgentState.Executing, AgentState.Collecting or AgentState.Aborted) => true,
        (AgentState.Aborted, AgentState.Collecting) => true,
        (AgentState.Collecting, AgentState.Completed) => true,
        _ => false
    };
}
