# What is this file?   The list of actions we write into the audit log.
# Flutter/Dart idea:   an enum of event names (like analytics event names).
"""Names of audited actions (a closed list, so logs are easy to filter)."""

from enum import StrEnum


class AuditAction(StrEnum):
    """Every action that produces an audit log entry."""

    ORG_CREATED = "organization.created"
    ORG_UPDATED = "organization.updated"
    MEMBER_ADDED = "member.added"
    MEMBER_ROLE_CHANGED = "member.role_changed"
    MEMBER_REMOVED = "member.removed"
    LOGIN_SUCCEEDED = "auth.login"
    TOKEN_REUSE_DETECTED = "auth.refresh_token_reuse_detected"
