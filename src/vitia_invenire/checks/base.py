"""BaseCheck abstract base class -- template method pattern for all checks."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod

from vitia_invenire.models import Category, CheckResult, Finding
from vitia_invenire.platform import has_tool, is_admin, is_windows


class BaseCheck(ABC):
    """Abstract base class for all security checks.

    Subclasses must define CHECK_ID, NAME, DESCRIPTION, CATEGORY class
    attributes and implement the run() method.

    The execute() template method handles platform checks, privilege
    validation, tool availability, timing, and error handling.
    """

    CHECK_ID: str = ""
    NAME: str = ""
    DESCRIPTION: str = ""
    CATEGORY: Category = Category.CONFIGURATION
    REQUIRES_ADMIN: bool = False
    REQUIRES_TOOLS: list[str] = []

    def __init__(self) -> None:
        self.context: dict = {}

    def execute(self) -> CheckResult:
        """Execute the check with full lifecycle management.

        1. Check if running on Windows
        2. Check admin privileges if required
        3. Check external tool availability if required
        4. Run the check with timing
        5. Handle any exceptions

        Returns:
            CheckResult with status, findings, timing, and error info.
        """
        # Platform check
        if not is_windows():
            return CheckResult(
                check_id=self.CHECK_ID,
                check_name=self.NAME,
                category=self.CATEGORY,
                status="skipped",
                error_message="Not running on Windows",
            )

        # Privilege check
        if self.REQUIRES_ADMIN and not is_admin():
            return CheckResult(
                check_id=self.CHECK_ID,
                check_name=self.NAME,
                category=self.CATEGORY,
                status="skipped",
                error_message="Requires administrator privileges",
            )

        # Tool availability check
        for tool in self.REQUIRES_TOOLS:
            if not has_tool(tool):
                return CheckResult(
                    check_id=self.CHECK_ID,
                    check_name=self.NAME,
                    category=self.CATEGORY,
                    status="skipped",
                    error_message=f"Required tool not found: {tool}",
                )

        # Execute the check
        start_time = time.monotonic()
        try:
            findings = self.run()
            duration = time.monotonic() - start_time
            status = "passed" if not findings else "failed"
            return CheckResult(
                check_id=self.CHECK_ID,
                check_name=self.NAME,
                category=self.CATEGORY,
                status=status,
                duration_seconds=round(duration, 3),
                findings=findings,
                context=self.context,
            )
        except Exception as exc:
            duration = time.monotonic() - start_time
            return CheckResult(
                check_id=self.CHECK_ID,
                check_name=self.NAME,
                category=self.CATEGORY,
                status="error",
                duration_seconds=round(duration, 3),
                error_message=f"{type(exc).__name__}: {exc}",
                context=self.context,
            )

    @abstractmethod
    def run(self) -> list[Finding]:
        """Implement the actual check logic.

        Returns:
            List of Finding objects for any issues detected.
            Empty list means the check passed.
        """
        ...
