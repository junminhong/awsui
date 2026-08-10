"""Plain and Rich rendering for awsui command-line results."""

from dataclasses import dataclass
import json

from rich import box
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.style import StyleType
from rich.table import Table
from rich.text import Text

from .bind_command import BindResult
from .cli_console import safe_text
from .context_verification import (
    AccountMismatchError,
    VerifiedContext,
    describe_principal,
)
from .doctor_command import DoctorReport
from .init_command import InitResult


@dataclass(frozen=True, slots=True)
class DoctorRenderStyles:
    """Styles for doctor output embedded in different Rich consoles."""

    value: StyleType = "awsui.value"
    muted: StyleType = "awsui.muted"
    success: StyleType = "awsui.success"
    error: StyleType = "awsui.error"
    option: StyleType = "awsui.option"
    title: StyleType = "awsui.title"
    healthy_border: StyleType = "cyan"
    unhealthy_border: StyleType = "red"


def render_init_result(result: InitResult) -> str:
    lines = [f"Created {result.config_path}", f"Project: {result.project}"]
    for environment in result.environments:
        protection = " · PROTECTED" if environment.protected else ""
        lines.append(
            f"  {environment.name}: {environment.account} · "
            f"{environment.region}{protection}"
        )
    return "\n".join(lines)


def render_init_result_rich(result: InitResult) -> RenderableType:
    """Render a structured project initialization summary."""
    table = Table(box=box.SIMPLE, show_edge=False, pad_edge=False)
    table.add_column("Environment", style="awsui.title")
    table.add_column("Account", style="awsui.value")
    table.add_column("Region", style="awsui.value")
    table.add_column("Protection")
    for environment in result.environments:
        protection = (
            Text("PROTECTED", style="awsui.protected")
            if environment.protected
            else Text("—", style="awsui.muted")
        )
        table.add_row(
            safe_text(environment.name.upper()),
            safe_text(environment.account),
            safe_text(environment.region),
            protection,
        )
    details = Text.assemble(
        ("Project  ", "awsui.label"),
        safe_text(result.project, "awsui.value"),
        "\n",
        ("Config   ", "awsui.label"),
        safe_text(result.config_path, "awsui.value"),
    )
    return Panel(
        Group(details, Text(), table),
        title=Text("✓ Project initialized", style="awsui.success"),
        border_style="cyan",
        expand=False,
    )


def render_doctor_report(report: DoctorReport) -> str:
    lines = [
        f"{'✓' if check.passed else '✗'} {check.name}: {check.detail}"
        for check in report.checks
    ]
    if report.remediations:
        lines.extend(["", "Next steps"])
        lines.extend(
            f"  {index}. {remediation}"
            for index, remediation in enumerate(report.remediations, start=1)
        )
    return "\n".join(lines)


def render_doctor_report_rich(
    report: DoctorReport,
    *,
    styles: DoctorRenderStyles = DoctorRenderStyles(),
    framed: bool = True,
) -> RenderableType:
    """Render diagnostic checks as a compact status table."""
    table = Table(
        box=box.SIMPLE,
        show_edge=False,
        pad_edge=False,
    )
    table.add_column("", width=1)
    table.add_column("Check", style=styles.value, no_wrap=True)
    table.add_column("Detail", style=styles.muted, max_width=72)
    for check in report.checks:
        status = Text(
            "✓" if check.passed else "✗",
            style=styles.success if check.passed else styles.error,
        )
        table.add_row(status, safe_text(check.name), safe_text(check.detail))
    renderables: list[RenderableType] = [table]
    if report.remediations:
        next_steps = Group(
            *(
                Text.assemble(
                    (f"{index}. ", styles.option),
                    safe_text(remediation, styles.value),
                )
                for index, remediation in enumerate(report.remediations, start=1)
            )
        )
        renderables.extend([Text(), Text("Next steps", style=styles.title), next_steps])
    body = Group(*renderables)
    if not framed:
        return body
    return Panel(
        body,
        title=Text("awsui · doctor", style=styles.title),
        border_style=(
            styles.healthy_border if report.healthy else styles.unhealthy_border
        ),
        expand=False,
    )


def render_bind_result(result: BindResult) -> str:
    binding = f"{result.project}/{result.environment} → {result.profile}"
    return f"Bound {binding}" if result.changed else f"Binding unchanged: {binding}"


def render_bind_result_rich(result: BindResult) -> RenderableType:
    """Render a local profile binding result."""
    action = "Bound" if result.changed else "Binding unchanged"
    message = Text.assemble(
        ("✓ ", "awsui.success"),
        (f"{action}  ", "awsui.success"),
        safe_text(result.project, "awsui.value"),
        (" / ", "awsui.muted"),
        safe_text(result.environment.upper(), "awsui.title"),
        ("  →  ", "awsui.muted"),
        safe_text(result.profile, "awsui.value"),
    )
    return Panel(message, border_style="green", expand=False)


def render_verified_context(verified: VerifiedContext) -> str:
    context = verified.resolved
    return "\n".join(
        [
            _context_heading(verified),
            f"Expected account: {context.expected_account}",
            f"Authenticated account: {verified.actual_account}",
            f"Region: {context.region}",
            f"Local profile: {context.profile}",
            "Status: ✓ VERIFIED",
        ]
    )


def render_verified_context_rich(verified: VerifiedContext) -> RenderableType:
    """Render a verified AWS context as a protected identity card."""
    grid = _verified_identity_grid(verified)
    checks = _verification_checks(verified, context_prepared=False)
    return Panel(
        Group(grid, Text(), checks),
        title=_context_heading_rich(verified),
        border_style="cyan",
        expand=False,
    )


def render_verified_context_json(verified: VerifiedContext) -> str:
    context = verified.resolved
    payload = {
        "project": context.project,
        "environment": context.environment,
        "expected_account": context.expected_account,
        "actual_account": verified.actual_account,
        "region": context.region,
        "profile": context.profile,
        "verified": True,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def render_account_mismatch(
    error: AccountMismatchError,
    *,
    not_started: str | None = None,
) -> str:
    lines = [
        "AWS CONTEXT MISMATCH",
        "",
        f"Project: {error.project}",
        f"Environment: {error.environment.upper()}",
        f"Expected account: {error.expected_account}",
        f"Authenticated account: {error.actual_account}",
    ]
    if not_started is not None:
        lines.extend(["", not_started])
    return "\n".join(lines)


def render_account_mismatch_rich(
    error: AccountMismatchError,
    *,
    not_started: str | None = None,
    next_step: str | None = None,
) -> RenderableType:
    """Render a fail-closed account mismatch warning."""
    grid = _context_grid()
    grid.add_row("Project", safe_text(error.project))
    grid.add_row("Environment", safe_text(error.environment.upper()))
    grid.add_row("Expected account", safe_text(error.expected_account))
    grid.add_row(
        "Authenticated account",
        safe_text(error.actual_account, "awsui.error"),
    )
    renderables: list[RenderableType] = [grid]
    if not_started is not None:
        renderables.extend([Text(), safe_text(not_started, "awsui.error")])
    if next_step is not None:
        renderables.extend(
            [
                Text(),
                Text("Next step", style="awsui.title"),
                safe_text(next_step, "awsui.value"),
            ]
        )
    return Panel(
        Group(*renderables),
        title=Text("✗ AWS CONTEXT MISMATCH", style="awsui.error"),
        border_style="red",
        expand=False,
    )


def render_launch_context(verified: VerifiedContext, launch_message: str) -> str:
    context = verified.resolved
    return "\n".join(
        [
            _context_heading(verified),
            f"Account: {verified.actual_account} ✓",
            f"Region: {context.region}",
            launch_message,
        ]
    )


def render_launch_context_rich(
    verified: VerifiedContext,
    launch_message: str,
) -> RenderableType:
    """Render the verified launch context before yielding the terminal."""
    grid = _verified_identity_grid(verified)
    checks = _verification_checks(verified, context_prepared=True)
    launch = Text.assemble(
        ("Launching  ", "awsui.label"),
        safe_text(launch_message, "awsui.value"),
        ("…", "awsui.muted"),
    )
    return Panel(
        Group(grid, Text(), checks, Text(), launch),
        title=_context_heading_rich(verified),
        border_style="cyan",
        expand=False,
    )


def render_status_rich(message: str) -> Text:
    """Render a non-animated operation status."""
    return Text.assemble(("● ", "awsui.title"), safe_text(message, "awsui.muted"))


def render_error_rich(message: str) -> Text:
    """Render a safe CLI error message."""
    return Text.assemble(("✗ ", "awsui.error"), safe_text(message, "awsui.error"))


def render_failure_rich(
    title: str,
    detail: str,
    *,
    next_step: str | None = None,
    not_started: str | None = None,
) -> RenderableType:
    """Render a structured, actionable CLI failure card."""
    renderables: list[RenderableType] = [safe_text(detail, "awsui.value")]
    if not_started is not None:
        renderables.extend([Text(), safe_text(not_started, "awsui.error")])
    if next_step is not None:
        renderables.extend(
            [
                Text(),
                Text("Next step", style="awsui.title"),
                safe_text(next_step, "awsui.value"),
            ]
        )
    return Panel(
        Group(*renderables),
        title=Text.assemble(("✗ ", "awsui.error"), safe_text(title, "awsui.error")),
        border_style="red",
        expand=False,
    )


def render_cancelled_rich(message: str) -> Text:
    """Render a safe cancellation message."""
    return Text.assemble(("! ", "awsui.warning"), safe_text(message, "awsui.warning"))


def _context_heading(verified: VerifiedContext) -> str:
    context = verified.resolved
    heading = f"{context.project} · {context.environment.upper()}"
    return f"{heading} · PROTECTED" if context.protected else heading


def _context_heading_rich(verified: VerifiedContext) -> Text:
    context = verified.resolved
    heading = Text.assemble(
        ("awsui", "awsui.title"),
        (" · ", "awsui.muted"),
        safe_text(context.project, "awsui.value"),
        (" / ", "awsui.muted"),
        safe_text(context.environment.upper(), "awsui.title"),
    )
    if context.protected:
        heading.append("  ")
        heading.append("PROTECTED", style="awsui.protected")
    return heading


def _context_grid() -> Table:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="awsui.label", no_wrap=True)
    grid.add_column(style="awsui.value")
    return grid


def _verified_identity_grid(verified: VerifiedContext) -> Table:
    context = verified.resolved
    grid = _context_grid()
    grid.add_row("Profile", safe_text(context.profile))
    grid.add_row("Account", safe_text(verified.actual_account))
    grid.add_row("Region", safe_text(context.region))
    principal = describe_principal(verified.principal_arn)
    if principal is not None:
        label, value = principal
        grid.add_row(label, safe_text(value))
    return grid


def _verification_checks(
    verified: VerifiedContext,
    *,
    context_prepared: bool,
) -> Text:
    context = verified.resolved
    checks = Text.assemble(
        ("✓ ", "awsui.success"),
        ("AWS identity verified", "awsui.success"),
        "\n",
        ("✓ ", "awsui.success"),
        (
            f"Account matches {context.project}/{context.environment}",
            "awsui.success",
        ),
    )
    if context_prepared:
        checks.append("\n")
        checks.append("✓ ", style="awsui.success")
        checks.append("AWS context prepared", style="awsui.success")
    return checks
