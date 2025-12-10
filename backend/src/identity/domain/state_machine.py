"""State machine infrastructure for domain entities.

This module provides proper state machine implementations with:
- Explicit Event enums for all transitions
- Transition tables mapping (State, Event) -> NewState
- Handler dispatch pattern (not elif chains)
- Observability (metrics + logging)
"""

import logging
from abc import ABC, abstractmethod
from enum import Enum
from typing import Generic, TypeVar

from opentelemetry import metrics

logger = logging.getLogger(__name__)

# OpenTelemetry metrics for state transitions
meter = metrics.get_meter("identity.state_machines")

state_transitions_total = meter.create_counter(
    name="identity_state_transitions_total",
    description="Total state transitions",
    unit="1",
)


class InvalidTransitionError(Exception):
    """Raised when an invalid state transition is attempted."""

    def __init__(self, entity_id: str, current_state: str, event: str):
        self.entity_id = entity_id
        self.current_state = current_state
        self.event = event
        super().__init__(
            f"Invalid transition: {entity_id} in state {current_state} cannot handle event {event}"
        )


S = TypeVar("S", bound=Enum)
E = TypeVar("E", bound=Enum)


class StateMachine(ABC, Generic[S, E]):
    """Base class for state machines with explicit transition tables.

    Subclasses must define:
    - TRANSITIONS: dict mapping (State, Event) -> NewState
    - _get_state() / _set_state(): access to entity's state
    - _get_entity_id(): identity for logging/metrics
    """

    TRANSITIONS: dict[tuple[S, E], S]

    @abstractmethod
    def _get_state(self) -> S:
        """Get current state."""
        ...

    @abstractmethod
    def _set_state(self, state: S) -> None:
        """Set state (internal use only)."""
        ...

    @abstractmethod
    def _get_entity_id(self) -> str:
        """Get entity ID for logging."""
        ...

    def transition(self, event: E) -> S:
        """Execute a state transition.

        Args:
            event: The event triggering the transition

        Returns:
            The new state after transition

        Raises:
            InvalidTransitionError: If no transition defined for (state, event)
        """
        current_state = self._get_state()
        entity_id = self._get_entity_id()

        key = (current_state, event)
        if key not in self.TRANSITIONS:
            logger.warning(
                "invalid_transition_attempted",
                extra={
                    "entity_id": entity_id,
                    "current_state": current_state.value,
                    "event": event.value,
                    "reason": "no_transition_defined",
                },
            )
            raise InvalidTransitionError(entity_id, current_state.value, event.value)

        new_state = self.TRANSITIONS[key]
        self._set_state(new_state)

        # Observability
        logger.info(
            "state_transition",
            extra={
                "entity_id": entity_id,
                "from_state": current_state.value,
                "to_state": new_state.value,
                "event": event.value,
            },
        )

        state_transitions_total.add(
            1,
            {
                "entity_type": self.__class__.__name__,
                "from_state": current_state.value,
                "to_state": new_state.value,
                "event": event.value,
            },
        )

        return new_state

    def can_transition(self, event: E) -> bool:
        """Check if a transition is valid without executing it."""
        return (self._get_state(), event) in self.TRANSITIONS

    def get_valid_events(self) -> list[E]:
        """Get list of events valid from current state."""
        current_state = self._get_state()
        return [event for state, event in self.TRANSITIONS.keys() if state == current_state]
