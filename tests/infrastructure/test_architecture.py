"""Dependency-boundary checks for framework-independent core packages."""

import ast
from pathlib import Path


CORE_PACKAGES = ("context", "profiles", "project")
FORBIDDEN_PREFIXES = ("awsui.cli", "awsui.tui")


def _import_targets(node: ast.Import | ast.ImportFrom, package: tuple[str, ...]):
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]

    if node.level:
        base = package[: len(package) - (node.level - 1)]
        module = (*base, *(node.module or "").split("."))
    else:
        module = tuple((node.module or "").split("."))
    module = tuple(part for part in module if part)
    targets = [".".join(module)] if module else []
    targets.extend(".".join((*module, alias.name)) for alias in node.names)
    return targets


def test_core_packages_do_not_depend_on_cli_or_tui():
    source_root = Path(__file__).parents[2] / "awsui"
    violations = []

    for package_name in CORE_PACKAGES:
        for source_path in (source_root / package_name).rglob("*.py"):
            relative = source_path.relative_to(source_root)
            package = ("awsui", *relative.parent.parts)
            tree = ast.parse(source_path.read_text(encoding="utf-8"), source_path.name)
            for node in ast.walk(tree):
                if not isinstance(node, (ast.Import, ast.ImportFrom)):
                    continue
                for target in _import_targets(node, package):
                    if any(
                        target == prefix or target.startswith(f"{prefix}.")
                        for prefix in FORBIDDEN_PREFIXES
                    ):
                        violations.append(f"{relative}:{node.lineno}: {target}")

    assert not violations, "Core packages import presentation layers:\n" + "\n".join(
        violations
    )
