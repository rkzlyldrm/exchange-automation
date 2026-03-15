"""
On-demand IMAP email monitor.

Connects to IMAP only when an exchange registers a watch.
Polls for matching emails, extracts confirmation links or codes,
and resolves futures when matches are found.

IMAP credentials are loaded from the imap_settings DB table (encrypted),
falling back to env vars (IMAP_SERVER, etc.) if the table has no rows.
"""
import asyncio
import email as email_lib
import email.header
import email.utils
import imaplib
import logging
import re
import time
from typing import Dict, List, Optional, Tuple

from src.config import settings
from src.email.models import EmailMatch, EmailWatchRequest
from src.security.encryption import decrypt_data

logger = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = 7
MAX_FETCH_EMAILS = 20
# Track UIDs we've already matched so we don't re-process them
# (especially important now that we search ALL emails, not just UNSEEN)
_matched_uids: set = set()


def _load_imap_settings_from_db() -> Optional[dict]:
    """Load and decrypt IMAP settings from the DB (same pattern as _load_credentials)."""
    try:
        from sqlalchemy import create_engine, text
        engine = create_engine(settings.DATABASE_URL, pool_size=1, max_overflow=1)
        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT imap_server, imap_port, imap_email, imap_password, is_enabled "
                    "FROM imap_settings "
                    "WHERE user_id = :uid "
                    "LIMIT 1"
                ),
                {"uid": settings.PRIMARY_USER_ID},
            ).fetchone()
        engine.dispose()

        if row is None:
            return None

        # Strip spaces/non-breaking spaces from password (Google App Passwords
        # are displayed with \xa0 separators but work without them)
        raw_password = decrypt_data(row[3])
        clean_password = raw_password.replace("\xa0", "").replace(" ", "")

        return {
            "server": decrypt_data(row[0]),
            "port": row[1],
            "email": decrypt_data(row[2]),
            "password": clean_password,
            "enabled": row[4],
        }
    except Exception as e:
        logger.warning(f"Email monitor: failed to load IMAP settings from DB: {e}")
        return None


class ImapEmailMonitor:
    """On-demand IMAP email monitor — only connects when watches are active."""

    def __init__(self):
        self._watches: Dict[str, Tuple[EmailWatchRequest, asyncio.Future]] = {}
        self._poll_task: Optional[asyncio.Task] = None
        self._stopping = False
        self._imap_creds: Optional[dict] = None
        self._imap_creds_loaded_at: float = 0

    def _get_imap_creds(self) -> Optional[dict]:
        """Get IMAP credentials, refreshing from DB every 60 seconds."""
        now = time.time()
        if self._imap_creds is None or (now - self._imap_creds_loaded_at) > 60:
            db_settings = _load_imap_settings_from_db()
            if db_settings and db_settings["enabled"]:
                self._imap_creds = db_settings
                self._imap_creds_loaded_at = now
                return self._imap_creds

            # Fallback to env vars
            if settings.IMAP_ENABLED and settings.IMAP_SERVER and settings.IMAP_EMAIL:
                self._imap_creds = {
                    "server": settings.IMAP_SERVER,
                    "port": settings.IMAP_PORT,
                    "email": settings.IMAP_EMAIL,
                    "password": settings.IMAP_PASSWORD,
                    "enabled": True,
                }
                self._imap_creds_loaded_at = now
                return self._imap_creds

            return None
        return self._imap_creds

    def watch(self, request: EmailWatchRequest) -> "asyncio.Future[EmailMatch]":
        """Register a watch and return a Future that resolves with the match."""
        loop = asyncio.get_event_loop()
        future: asyncio.Future[EmailMatch] = loop.create_future()
        self._watches[request.watch_id] = (request, future)
        logger.info(f"Email monitor: registered watch '{request.watch_id}' "
                     f"(sender={request.sender_contains}, subject={request.subject_contains})")

        # Start poll loop if not already running
        if self._poll_task is None or self._poll_task.done():
            self._stopping = False
            self._poll_task = asyncio.create_task(self._poll_loop())
            logger.info("Email monitor: poll loop started")

        return future

    def cancel_watch(self, watch_id: str) -> None:
        """Cancel a specific watch."""
        entry = self._watches.pop(watch_id, None)
        if entry:
            _, future = entry
            if not future.done():
                future.cancel()
            logger.info(f"Email monitor: cancelled watch '{watch_id}'")

    async def stop(self) -> None:
        """Shut down monitor and cancel all watches."""
        self._stopping = True
        for watch_id, (_, future) in list(self._watches.items()):
            if not future.done():
                future.cancel()
        self._watches.clear()

        if self._poll_task and not self._poll_task.done():
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
        self._poll_task = None
        logger.info("Email monitor: stopped")

    # ── internal polling ──────────────────────────────────────

    async def _poll_loop(self) -> None:
        """Async loop: while watches exist, poll inbox every POLL_INTERVAL_SECONDS."""
        try:
            while self._watches and not self._stopping:
                await self._poll_inbox()
                # Clean up expired watches
                self._expire_watches()
                if self._watches:
                    await asyncio.sleep(POLL_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Email monitor: poll loop error: {e}")
        finally:
            logger.info("Email monitor: poll loop exited (no active watches)")

    def _expire_watches(self) -> None:
        """Remove watches that have exceeded their timeout."""
        expired = []
        for watch_id, (req, future) in self._watches.items():
            if future.done():
                expired.append(watch_id)
        for watch_id in expired:
            self._watches.pop(watch_id, None)

    async def _poll_inbox(self) -> None:
        """Poll IMAP inbox in a thread and resolve matching watches."""
        if not self._watches:
            return

        active_watches = {
            wid: req for wid, (req, fut) in self._watches.items() if not fut.done()
        }
        if not active_watches:
            return

        try:
            matches = await asyncio.to_thread(
                self._imap_fetch_and_match, active_watches
            )
        except Exception as e:
            logger.error(f"Email monitor: IMAP fetch error: {e}")
            return

        for watch_id, match in matches.items():
            entry = self._watches.get(watch_id)
            if entry:
                _, future = entry
                if not future.done():
                    future.set_result(match)
                    logger.info(f"Email monitor: matched email for '{watch_id}' "
                                f"(subject='{match.subject}', uid={match.email_uid})")

    # ── sync IMAP operations (run in thread) ──────────────────

    def _imap_fetch_and_match(
        self, watches: Dict[str, EmailWatchRequest]
    ) -> Dict[str, EmailMatch]:
        """
        Sync: connect IMAP_SSL, login, search UNSEEN, fetch last N,
        match against all active watches, extract links/codes,
        mark matched emails as Seen.
        """
        matches: Dict[str, EmailMatch] = {}

        creds = self._get_imap_creds()
        if not creds:
            logger.warning("Email monitor: no IMAP credentials configured")
            return matches

        try:
            imap = imaplib.IMAP4_SSL(creds["server"], creds["port"])
            imap.login(creds["email"], creds["password"])
            imap.select("INBOX")
        except Exception as e:
            logger.error(f"Email monitor: IMAP connection failed: {e}")
            return matches

        try:
            # Search ALL recent messages (not just UNSEEN) so we can match emails
            # that were already read by another client (e.g. Outlook).
            # We track matched UIDs in _matched_uids to avoid re-processing.
            status, data = imap.search(None, "ALL")
            if status != "OK" or not data[0]:
                return matches

            uid_list = data[0].split()
            # Only check the most recent N emails, newest first
            uid_list = uid_list[-MAX_FETCH_EMAILS:]
            uid_list.reverse()

            now = time.time()

            for uid in uid_list:
                uid_str = uid.decode() if isinstance(uid, bytes) else str(uid)

                # Skip UIDs we already matched in a previous poll cycle
                if uid_str in _matched_uids:
                    continue

                try:
                    status, msg_data = imap.fetch(uid, "(RFC822)")
                    if status != "OK" or not msg_data[0]:
                        continue

                    raw_email = msg_data[0][1]
                    msg = email_lib.message_from_bytes(raw_email)

                    sender = self._decode_header(msg.get("From", ""))
                    subject = self._decode_header(msg.get("Subject", ""))
                    date_str = msg.get("Date", "")
                    email_time = email_lib.utils.mktime_tz(
                        email_lib.utils.parsedate_tz(date_str)
                    ) if date_str else 0

                    body = self._extract_body(msg)

                    for watch_id, req in watches.items():
                        if watch_id in matches:
                            continue

                        # Check exclude_uids (caller-provided skip list)
                        if req.exclude_uids and uid_str in req.exclude_uids:
                            continue

                        # Check minimum email time (only match emails after API call)
                        if req.min_email_time and email_time < req.min_email_time:
                            continue

                        # Check age
                        if req.max_age_seconds and (now - email_time) > req.max_age_seconds:
                            continue

                        # Check sender
                        if req.sender_contains.lower() not in sender.lower():
                            continue

                        # Check subject
                        if req.subject_contains.lower() not in subject.lower():
                            continue

                        # Extract link if pattern given
                        link = None
                        if req.body_link_pattern and body:
                            m = re.search(req.body_link_pattern, body)
                            if m:
                                link = m.group(1) if m.lastindex else m.group(0)

                        # Extract code if pattern given
                        code = None
                        if req.body_code_pattern and body:
                            m = re.search(req.body_code_pattern, body)
                            if m:
                                code = m.group(1) if m.lastindex else m.group(0)

                        matches[watch_id] = EmailMatch(
                            watch_id=watch_id,
                            subject=subject,
                            sender=sender,
                            link=link,
                            code=code,
                            matched_at=time.time(),
                            email_uid=uid_str,
                            body=body or "",
                        )

                        # Track this UID so we don't re-match it
                        _matched_uids.add(uid_str)

                        # Also mark as Seen for cleanliness
                        try:
                            imap.store(uid, "+FLAGS", "\\Seen")
                        except Exception:
                            pass

                except Exception as e:
                    logger.warning(f"Email monitor: error processing email uid={uid}: {e}")
                    continue

        finally:
            try:
                imap.close()
                imap.logout()
            except Exception:
                pass

        return matches

    @staticmethod
    def _decode_header(value: str) -> str:
        """Decode MIME-encoded header value."""
        if not value:
            return ""
        parts = email_lib.header.decode_header(value)
        decoded = []
        for part, charset in parts:
            if isinstance(part, bytes):
                decoded.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                decoded.append(part)
        return " ".join(decoded)

    @staticmethod
    def _extract_body(msg) -> str:
        """Extract text body from a MIME message."""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        return payload.decode(charset, errors="replace")
            # Fallback to text/plain
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        return payload.decode(charset, errors="replace")
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                return payload.decode(charset, errors="replace")
        return ""


# Module-level singleton
email_monitor = ImapEmailMonitor()
