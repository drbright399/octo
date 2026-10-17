"""Tests for the adapter lifecycle state machine."""

from __future__ import annotations

import pytest

from apps.octo.framework.lifecycle import (
    AdapterLifecycleState,
    StateTransitionError,
    assert_valid_transition,
    is_valid_transition,
)


def test_registered_to_configured() -> None:
    assert is_valid_transition(
        AdapterLifecycleState.REGISTERED, AdapterLifecycleState.CONFIGURED,
    )


def test_configured_to_active() -> None:
    assert is_valid_transition(
        AdapterLifecycleState.CONFIGURED, AdapterLifecycleState.ACTIVE,
    )


def test_active_to_paused_and_back() -> None:
    assert is_valid_transition(
        AdapterLifecycleState.ACTIVE, AdapterLifecycleState.PAUSED,
    )
    assert is_valid_transition(
        AdapterLifecycleState.PAUSED, AdapterLifecycleState.ACTIVE,
    )


def test_terminal_remove_blocks_resurrect() -> None:
    """REMOVED is terminal — no transitions out."""
    for state in AdapterLifecycleState:
        assert not is_valid_transition(AdapterLifecycleState.REMOVED, state)


def test_skip_configured_rejected() -> None:
    """REGISTERED → ACTIVE without going through CONFIGURED is invalid."""
    assert not is_valid_transition(
        AdapterLifecycleState.REGISTERED, AdapterLifecycleState.ACTIVE,
    )


def test_skip_active_to_remove_from_configured() -> None:
    """CONFIGURED → REMOVED is allowed (operator cancels onboarding)."""
    assert is_valid_transition(
        AdapterLifecycleState.CONFIGURED, AdapterLifecycleState.REMOVED,
    )


def test_assert_valid_transition_raises_on_invalid() -> None:
    with pytest.raises(StateTransitionError) as exc_info:
        assert_valid_transition(
            AdapterLifecycleState.REGISTERED,
            AdapterLifecycleState.ACTIVE,
            reason="test",
        )
    assert exc_info.value.from_state == AdapterLifecycleState.REGISTERED
    assert exc_info.value.to_state == AdapterLifecycleState.ACTIVE


def test_state_transition_error_message_includes_states() -> None:
    err = StateTransitionError(
        AdapterLifecycleState.REMOVED,
        AdapterLifecycleState.ACTIVE,
        message="cannot resurrect",
    )
    assert "removed" in str(err)
    assert "active" in str(err)
    assert "cannot resurrect" in str(err)


def test_pause_to_remove_allowed() -> None:
    """Operator can remove a paused adapter directly without resuming first."""
    assert is_valid_transition(
        AdapterLifecycleState.PAUSED, AdapterLifecycleState.REMOVED,
    )
