"""
Exchange Automation Service — FastAPI application entry point.
"""
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from src.utils.logger import setup_logging
from src.browser.manager import browser_manager
from src.browser.session import get_session, get_all_sessions

from src.exchanges import EXCHANGE_REGISTRY, get_exchange_automation
from src.api.routes import router, _load_credentials, _update_session_status
from src.api.middleware import ServiceKeyMiddleware
from src.config import settings
from src.email.monitor import email_monitor

setup_logging()
logger = logging.getLogger(__name__)


async def _heartbeat_loop():
    """Periodically check all sessions and auto-relogin if expired."""
    interval = settings.SESSION_HEARTBEAT_INTERVAL_SEC
    while True:
        await asyncio.sleep(interval)
        for exchange_name, session in get_all_sessions().items():
            # Fix status if we have a token but status is wrong (e.g. captcha timeout but login succeeded)
            if not session.is_logged_in and session.get_auth_token():
                logger.info(f"Session {exchange_name} has token but not marked logged in — verifying...")
                try:
                    automation = get_exchange_automation(exchange_name)
                    if await automation.check_session(session):
                        session.set_logged_in(session.captured_tokens)
                        await browser_manager.save_storage_state(exchange_name)
                        _update_session_status(exchange_name, "connected")
                        logger.info(f"Session {exchange_name} verified and marked as connected")
                except Exception as e:
                    logger.warning(f"Token verification failed for {exchange_name}: {e}")

            if not session.is_logged_in:
                continue
            try:
                automation = get_exchange_automation(exchange_name)
                is_valid = await automation.check_session(session)
                if not is_valid:
                    logger.warning(f"Session expired for {exchange_name}, auto-relogin...")
                    credentials = _load_credentials(exchange_name)
                    if credentials:
                        async with session.lock:
                            result = await automation.login(session, credentials)
                        status = "connected" if result["success"] else "error"
                        _update_session_status(
                            exchange_name, status,
                            result.get("message") if not result["success"] else None,
                        )
                        if result["success"]:
                            logger.info(f"Auto-relogin successful for {exchange_name}")
                        else:
                            logger.error(f"Auto-relogin failed for {exchange_name}: {result['message']}")
            except Exception as e:
                logger.error(f"Heartbeat error for {exchange_name}: {e}")


async def _keepalive_loop():
    """Click between tabs to keep browser pages alive."""
    interval = settings.KEEPALIVE_INTERVAL_SEC
    while True:
        await asyncio.sleep(interval)
        for exchange_name, session in get_all_sessions().items():
            if session.status != "connected":
                continue
            try:
                automation = get_exchange_automation(exchange_name)
                if session.lock.locked():
                    continue
                async with session.lock:
                    await automation.keepalive(session)
            except Exception as e:
                logger.debug(f"Keepalive error for {exchange_name}: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup / shutdown."""
    logger.info("Starting Exchange Automation Service...")

    # Launch browser
    await browser_manager.start()
    logger.info("Browser manager started")

    # Start heartbeat and keepalive
    heartbeat_task = asyncio.create_task(_heartbeat_loop())
    keepalive_task = asyncio.create_task(_keepalive_loop())

    yield

    # Shutdown
    heartbeat_task.cancel()
    keepalive_task.cancel()
    for task in (heartbeat_task, keepalive_task):
        try:
            await task
        except asyncio.CancelledError:
            pass

    # Stop email monitor
    await email_monitor.stop()

    # Close all sessions
    for session in get_all_sessions().values():
        await session.close()

    await browser_manager.stop()
    logger.info("Exchange Automation Service stopped")


app = FastAPI(
    title="Exchange Automation Service",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(ServiceKeyMiddleware)

app.include_router(router)
