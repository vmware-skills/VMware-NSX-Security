"""Shared input validation helpers for ops modules.

Single source of truth for resource-ID validation — previously duplicated
in dfw_policy.py, dfw_rules.py, security_group.py, and inlined in
traceflow.py.
"""

from __future__ import annotations

import re

_ID_PATTERN = re.compile(r"^[\w\-\.]+$")


def validate_id(value: str, field: str = "id") -> str:
    """Validate that an ID contains only safe characters.

    Allowed: alphanumerics, hyphens, underscores, dots.

    Args:
        value: The ID string to validate.
        field: Field name for error messages.

    Returns:
        The validated ID string.

    Raises:
        ValueError: If the ID contains disallowed characters.
    """
    if not _ID_PATTERN.match(value):
        raise ValueError(
            f"Invalid {field}: only alphanumerics, hyphens, underscores, and "
            "dots are allowed; spaces or '/' almost always mean a display "
            "name or policy path was passed instead of an id. Run the "
            "matching list tool (list_dfw_policies, list_dfw_rules, "
            f"list_groups) and copy the 'id' field. Got: '{value}'"
        )
    return value
