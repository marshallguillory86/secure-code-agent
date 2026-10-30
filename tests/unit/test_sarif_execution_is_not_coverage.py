"""SARIF execution success is the scanner run, not the coverage grade."""

import pytest

from secure_code_audit import sarif
from secure_code_audit.scanner_status import (
    CoverageReport,
    CoverageStatus,
    ScannerExecution,
    ScannerOutcome,
    evaluate_coverage,
)


@pytest.mark.parametrize("status", list(CoverageStatus))
def test_coverage_status_never_marks_the_scanner_execution_unsuccessful(status):
    coverage = CoverageReport(
        status=status,
        required=(),
        executions=(),
        failures=(),
    )

    invocation = sarif.emit([], coverage)["runs"][0]["invocations"][0]

    assert invocation["executionSuccessful"] is True
    assert invocation["properties"]["coverageStatus"] == status.value


def test_unread_languages_are_warning_notifications_named_by_their_coverage_entry():
    coverage = CoverageReport(
        status=CoverageStatus.PARTIAL,
        required=(),
        executions=(),
        failures=(),
        unread_languages=(
            "shell: no scanner in this floor reads it",
            "rust: no scanner that reads it ran (semgrep)",
        ),
    )

    notifications = sarif.emit([], coverage)["runs"][0]["invocations"][0][
        "toolExecutionNotifications"
    ]

    assert [notification["level"] for notification in notifications] == ["warning", "warning"]
    assert all(
        notification["descriptor"]["id"] == "scanner-coverage"
        for notification in notifications
    )
    assert all(
        entry in notification["message"]["text"]
        for entry, notification in zip(coverage.unread_languages, notifications)
    )


def test_non_required_scanner_that_did_not_cover_is_a_warning_with_reason():
    execution = ScannerExecution(
        "gosec",
        ScannerOutcome.UNAVAILABLE,
        reason="binary is not installed",
    )
    coverage = evaluate_coverage([execution], required=())

    assert coverage.status is CoverageStatus.PARTIAL
    notification = sarif.emit([], coverage)["runs"][0]["invocations"][0][
        "toolExecutionNotifications"
    ][0]

    assert notification["level"] == "warning"
    assert notification["descriptor"]["id"] == "scanner-coverage"
    assert "gosec" in notification["message"]["text"]
    assert "binary is not installed" in notification["message"]["text"]


def test_real_coverage_builder_reports_shell_as_partial_and_sarif_warning():
    coverage = evaluate_coverage(
        [ScannerExecution("bandit", ScannerOutcome.COMPLETED)],
        required=(),
        languages=["shell"],
    )

    assert coverage.status is CoverageStatus.PARTIAL
    assert coverage.unread_languages

    invocation = sarif.emit([], coverage)["runs"][0]["invocations"][0]
    notifications = invocation["toolExecutionNotifications"]

    assert invocation["executionSuccessful"] is True
    assert invocation["properties"]["coverageStatus"] == "partial"
    assert len(notifications) == len(coverage.unread_languages)
    assert notifications[0]["level"] == "warning"
    assert "shell" in notifications[0]["message"]["text"]


def test_complete_coverage_emits_no_coverage_notifications():
    coverage = CoverageReport(
        status=CoverageStatus.COMPLETE,
        required=("bandit",),
        executions=(ScannerExecution("bandit", ScannerOutcome.COMPLETED),),
        failures=(),
    )

    invocation = sarif.emit([], coverage)["runs"][0]["invocations"][0]

    assert invocation["executionSuccessful"] is True
    assert "toolExecutionNotifications" not in invocation or not invocation[
        "toolExecutionNotifications"
    ]
