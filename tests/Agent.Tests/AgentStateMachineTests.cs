using Shared.Contracts;
using WindowsLabAgent;

namespace Agent.Tests;

public sealed class AgentStateMachineTests
{
    [Fact]
    public void Legal_sequence_reaches_completed()
    {
        var state = new AgentStateMachine(Guid.NewGuid());
        Assert.True(state.TryTransition(AgentState.Created, AgentState.Validating));
        Assert.True(state.TryTransition(AgentState.Validating, AgentState.Ready));
        Assert.True(state.TryTransition(AgentState.Ready, AgentState.Executing));
        Assert.True(state.TryTransition(AgentState.Executing, AgentState.Collecting));
        Assert.True(state.TryTransition(AgentState.Collecting, AgentState.Completed));
        Assert.Equal(AgentState.Completed, state.Current);
    }

    [Fact]
    public void Illegal_transition_is_rejected()
    {
        var state = new AgentStateMachine(Guid.NewGuid());
        Assert.False(state.TryTransition(AgentState.Created, AgentState.Executing));
    }
}
