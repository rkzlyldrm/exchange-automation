"""
Email watch request and match models for IMAP email monitoring.
"""
from dataclasses import dataclass, field
from typing import List, Optional, Set


@dataclass
class EmailWatchRequest:
    """Describes what email to look for."""
    watch_id: str
    sender_contains: str
    subject_contains: str
    body_link_pattern: Optional[str] = None
    body_code_pattern: Optional[str] = None
    max_age_seconds: int = 300
    timeout_seconds: float = 600
    exclude_uids: Set[str] = field(default_factory=set)
    min_email_time: float = 0  # Only match emails with Date >= this unix timestamp


@dataclass
class EmailMatch:
    """Result of a successful email match."""
    watch_id: str
    subject: str
    sender: str
    link: Optional[str] = None
    code: Optional[str] = None
    matched_at: float = 0.0
    email_uid: str = ""
    body: str = ""  # Raw email body for additional parsing by caller
