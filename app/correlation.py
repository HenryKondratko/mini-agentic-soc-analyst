"""Deterministic authentication-event correlation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Literal

from app.models import AuthenticationEvent, AuthenticationOutcome, SecurityAlert

DEFAULT_AUTH_WINDOW = timedelta(minutes=10)


@dataclass(frozen=True)
class AuthenticationCorrelation:
    correlated: bool
    status: Literal["correlated", "not_correlated", "unavailable", "contradictory"]
    failure_count: int
    success_after_failure: bool
    source: Literal["events", "aggregate"]
    reason: str


def _aggregate_correlation(alert: SecurityAlert) -> AuthenticationCorrelation:
    correlated = alert.failed_attempts >= 2 and alert.successful_login
    return AuthenticationCorrelation(
        correlated=correlated,
        status="correlated" if correlated else "not_correlated",
        failure_count=alert.failed_attempts,
        success_after_failure=alert.successful_login and alert.failed_attempts >= 1,
        source="aggregate",
        reason=(
            "aggregate fields indicate repeated failures followed by success"
            if correlated
            else "aggregate fields do not indicate repeated failures followed by success"
        ),
    )


def _event_correlation(
    events: list[AuthenticationEvent],
    *,
    window: timedelta,
) -> AuthenticationCorrelation:
    if not events:
        return AuthenticationCorrelation(
            correlated=False,
            status="unavailable",
            failure_count=0,
            success_after_failure=False,
            source="events",
            reason="no authentication events were supplied",
        )
    ordered = sorted(events, key=lambda event: event.timestamp)
    failures = [event for event in ordered if event.outcome == AuthenticationOutcome.FAILURE]
    successes = [event for event in ordered if event.outcome == AuthenticationOutcome.SUCCESS]
    for success in successes:
        prior_failures = [
            failure
            for failure in failures
            if failure.timestamp <= success.timestamp and success.timestamp - failure.timestamp <= window
        ]
        if len(prior_failures) >= 2:
            return AuthenticationCorrelation(
                correlated=True,
                status="correlated",
                failure_count=len(failures),
                success_after_failure=True,
                source="events",
                reason=f"{len(prior_failures)} failures preceded a success within {window}",
            )
    return AuthenticationCorrelation(
        correlated=False,
        status="not_correlated",
        failure_count=len(failures),
        success_after_failure=bool(successes and failures),
        source="events",
        reason=f"{len(failures)} failures and {len(successes)} successes did not form a qualifying sequence",
    )


def correlate_authentication_events(
    alert: SecurityAlert,
    *,
    window: timedelta = DEFAULT_AUTH_WINDOW,
) -> AuthenticationCorrelation:
    """Correlate repeated failures followed by a success for the alert user.

    Non-empty event data is authoritative. Aggregate fields are used only when
    event data is absent, preserving compatibility with legacy alert payloads.
    """

    if window <= timedelta(0):
        raise ValueError("window must be positive")
    if alert.events:
        expected_user = alert.username.casefold()
        if any(event.username.casefold() != expected_user for event in alert.events):
            return AuthenticationCorrelation(
                correlated=False,
                status="contradictory",
                failure_count=sum(event.outcome == AuthenticationOutcome.FAILURE for event in alert.events),
                success_after_failure=False,
                source="events",
                reason="authentication events contain a different username",
            )
        event_result = _event_correlation(alert.events, window=window)
        aggregate_result = _aggregate_correlation(alert)
        if aggregate_result.correlated and not event_result.correlated:
            return AuthenticationCorrelation(
                correlated=False,
                status="contradictory",
                failure_count=event_result.failure_count,
                success_after_failure=event_result.success_after_failure,
                source="events",
                reason="event sequence contradicts the aggregate correlation",
            )
        return event_result
    return _aggregate_correlation(alert)


def has_repeated_failed_auth_then_success(
    alert: SecurityAlert,
    *,
    window: timedelta = DEFAULT_AUTH_WINDOW,
) -> bool:
    """Boolean convenience wrapper for policy and detection callers."""

    return correlate_authentication_events(alert, window=window).correlated
