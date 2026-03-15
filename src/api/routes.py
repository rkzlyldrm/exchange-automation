"""
FastAPI routes for the exchange automation service.
"""
import base64
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from src.api.models import (
    WithdrawTRYRequest,
    WithdrawTRYResponse,
    WithdrawCryptoRequest,
    WithdrawCryptoResponse,
    ConfirmDepositRequest,
    TravelRuleConfirmRequest,
    LoginResponse,
    SessionStatus,
    HealthResponse,
)
from src.browser.manager import browser_manager
from src.browser.session import get_session, get_all_sessions
from src.exchanges import get_exchange_automation, EXCHANGE_REGISTRY
from src.security.encryption import decrypt_data
from src.config import settings

import sqlalchemy as sa
from sqlalchemy import create_engine, text

logger = logging.getLogger(__name__)

router = APIRouter()

# Lazy DB engine (read-only for credentials)
_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        _engine = create_engine(settings.DATABASE_URL, pool_size=2, max_overflow=2)
    return _engine


def _load_credentials(exchange_name: str) -> Optional[dict]:
    """Load and decrypt web credentials from the main app's DB."""
    engine = _get_engine()
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT email, password, totp_secret, extra_data "
                "FROM exchange_web_credentials "
                "WHERE exchange_name = :name AND is_active = true AND user_id = :uid "
                "LIMIT 1"
            ),
            {"name": exchange_name, "uid": settings.PRIMARY_USER_ID},
        ).fetchone()

    if row is None:
        return None

    return {
        "email": decrypt_data(row[0]),
        "password": decrypt_data(row[1]),
        "totp_secret": decrypt_data(row[2]) if row[2] else None,
        "extra_data": decrypt_data(row[3]) if row[3] else None,
    }


def _update_session_status(exchange_name: str, status: str, error: Optional[str] = None):
    """Best-effort update of session_status in main DB."""
    try:
        engine = _get_engine()
        with engine.connect() as conn:
            conn.execute(
                text(
                    "UPDATE exchange_web_credentials "
                    "SET session_status = :status, last_error = :error, "
                    "    last_login_at = CASE WHEN :status = 'connected' THEN NOW() ELSE last_login_at END, "
                    "    updated_at = NOW() "
                    "WHERE exchange_name = :name AND user_id = :uid"
                ),
                {"status": status, "error": error, "name": exchange_name, "uid": settings.PRIMARY_USER_ID},
            )
            conn.commit()
    except Exception as e:
        logger.warning(f"Failed to update session status in DB: {e}")


# ── Health ─────────────────────────────────────────────────

@router.get("/health")
async def health():
    return {
        "status": "ok",
        "browser": browser_manager.get_health(),
    }


@router.get("/api/status", response_model=HealthResponse)
async def get_all_status():
    sessions = []
    for s in get_all_sessions().values():
        sessions.append(SessionStatus(**s.get_status()))
    return HealthResponse(
        status="ok",
        browser=browser_manager.get_health(),
        sessions=sessions,
    )


@router.get("/api/status/{exchange}", response_model=SessionStatus)
async def get_exchange_status(exchange: str):
    session = get_session(exchange)
    return SessionStatus(**session.get_status())


# ── Session Management ─────────────────────────────────────

@router.post("/api/session/{exchange}/login", response_model=LoginResponse)
async def login_exchange(exchange: str):
    if exchange not in EXCHANGE_REGISTRY:
        raise HTTPException(404, f"Exchange '{exchange}' not supported")

    credentials = _load_credentials(exchange)
    if not credentials:
        raise HTTPException(404, f"No credentials found for '{exchange}'")

    session = get_session(exchange)
    automation = get_exchange_automation(exchange)

    async with session.lock:
        result = await automation.login(session, credentials)

    status = "connected" if result["success"] else "error"
    _update_session_status(exchange, status, result.get("message") if not result["success"] else None)

    return LoginResponse(**result)


@router.post("/api/session/{exchange}/restart", response_model=LoginResponse)
async def restart_session(exchange: str):
    """Soft restart: close page, re-login using existing context."""
    if exchange not in EXCHANGE_REGISTRY:
        raise HTTPException(404, f"Exchange '{exchange}' not supported")

    session = get_session(exchange)
    async with session.lock:
        await session.close()

    _update_session_status(exchange, "disconnected")
    return await login_exchange(exchange)


@router.post("/api/session/{exchange}/hard-restart", response_model=LoginResponse)
async def hard_restart_session(exchange: str):
    """Hard restart: new BrowserContext + re-login."""
    if exchange not in EXCHANGE_REGISTRY:
        raise HTTPException(404, f"Exchange '{exchange}' not supported")

    session = get_session(exchange)
    async with session.lock:
        await session.close()
        await browser_manager.restart_context(exchange)

    _update_session_status(exchange, "disconnected")
    return await login_exchange(exchange)


# ── Verification Code Submission ──────────────────────────

class VerificationCodesRequest(BaseModel):
    email_code: str
    sms_code: str


@router.post("/api/session/{exchange}/submit-verification")
async def submit_verification_codes(exchange: str, req: VerificationCodesRequest):
    """Submit email + SMS verification codes. The login flow fills them + GA code + clicks confirm."""
    session = get_session(exchange)

    if session.status != "waiting_for_verification":
        raise HTTPException(400, f"Exchange '{exchange}' is not waiting for verification (status={session.status})")

    session.submit_verification_codes(req.email_code, req.sms_code)
    return {"success": True, "message": "Verification codes submitted, login continuing..."}


# ── TRY Withdrawal ─────────────────────────────────────────

@router.post("/api/withdraw/try", response_model=WithdrawTRYResponse)
async def withdraw_try(req: WithdrawTRYRequest):
    exchange = req.exchange_name
    if exchange not in EXCHANGE_REGISTRY:
        raise HTTPException(404, f"Exchange '{exchange}' not supported")

    session = get_session(exchange)
    automation = get_exchange_automation(exchange)

    # Auto-relogin if session expired
    if not session.is_logged_in:
        credentials = _load_credentials(exchange)
        if not credentials:
            raise HTTPException(404, f"No credentials for '{exchange}'")
        async with session.lock:
            login_result = await automation.login(session, credentials)
        if not login_result["success"]:
            return WithdrawTRYResponse(
                success=False,
                message=f"Auto-login failed: {login_result['message']}",
            )

    async with session.lock:
        result = await automation.withdraw_try(
            session,
            amount=req.amount,
            iban=req.iban,
            payment_account_id=req.payment_account_id,
        )

    return WithdrawTRYResponse(**result)


# ── Crypto Withdrawal (browser UI + email confirmation) ────

@router.post("/api/withdraw/crypto", response_model=WithdrawCryptoResponse)
async def withdraw_crypto(req: WithdrawCryptoRequest):
    """Execute crypto withdrawal via browser automation with email confirmation."""
    exchange = req.exchange_name
    if exchange not in EXCHANGE_REGISTRY:
        raise HTTPException(404, f"Exchange '{exchange}' not supported")

    session = get_session(exchange)
    automation = get_exchange_automation(exchange)

    # Auto-relogin if session expired
    if not session.is_logged_in:
        credentials = _load_credentials(exchange)
        if not credentials:
            raise HTTPException(404, f"No credentials for '{exchange}'")
        async with session.lock:
            login_result = await automation.login(session, credentials)
        if not login_result["success"]:
            return WithdrawCryptoResponse(
                success=False,
                message=f"Auto-login failed: {login_result['message']}",
            )

    async with session.lock:
        result = await automation.withdraw_crypto(
            session,
            asset=req.asset,
            network=req.network,
            amount=req.amount,
            address=req.address,
            phishing_code=req.phishing_code,
            receiver_platform=req.receiver_platform,
        )

    return WithdrawCryptoResponse(**result)


# ── Token Provider (Phase 1 integration) ───────────────────

@router.get("/api/token/{exchange}")
async def get_token(exchange: str):
    """Return the currently captured auth token for an exchange (Phase 1 integration)."""
    session = get_session(exchange)
    token = session.get_auth_token()
    if not token:
        raise HTTPException(404, "No token available")
    return {"exchange_name": exchange, "auth_token": token}


# ── Deposit Confirmation ───────────────────────────────────

@router.get("/api/deposit/pending/{exchange}")
async def get_pending_deposits(exchange: str):
    # Placeholder — to be implemented per exchange
    return {"exchange_name": exchange, "pending": []}


@router.post("/api/deposit/confirm/{exchange}")
async def confirm_deposit(exchange: str, req: ConfirmDepositRequest):
    if exchange not in EXCHANGE_REGISTRY:
        raise HTTPException(404, f"Exchange '{exchange}' not supported")

    session = get_session(exchange)
    automation = get_exchange_automation(exchange)

    # Some exchanges (e.g. OKX TR) confirm deposits via travel rule API calls only,
    # so they don't need session.lock. Others may need the browser lock.
    # Use lock only if the automation class says it needs browser access.
    if hasattr(automation, 'confirm_deposit_needs_browser') and automation.confirm_deposit_needs_browser:
        async with session.lock:
            result = await automation.confirm_deposit(
                session, req.platform_name, req.amount
            )
    else:
        result = await automation.confirm_deposit(
            session, req.platform_name, req.amount
        )

    return result


# ── Travel Rule ───────────────────────────────────────────

@router.get("/api/travel-rule/pending/{exchange}")
async def get_pending_travel_rules(exchange: str):
    """Get pending deposits needing travel rule verification."""
    if exchange not in EXCHANGE_REGISTRY:
        raise HTTPException(404, f"Exchange '{exchange}' not supported")

    session = get_session(exchange)
    automation = get_exchange_automation(exchange)

    if not hasattr(automation, "get_pending_travel_rules"):
        return {"exchange_name": exchange, "pending": [], "message": "Not supported"}

    # Lock needed — get_pending_travel_rules navigates the browser page.
    if session.lock.locked():
        return {"exchange_name": exchange, "success": False, "pending": [], "message": "Session busy"}
    async with session.lock:
        result = await automation.get_pending_travel_rules(session)
    return {"exchange_name": exchange, **result}


@router.post("/api/travel-rule/confirm/{exchange}")
async def confirm_travel_rule(exchange: str, req: TravelRuleConfirmRequest):
    """Confirm a specific travel rule by ID and source exchange."""
    if exchange not in EXCHANGE_REGISTRY:
        raise HTTPException(404, f"Exchange '{exchange}' not supported")

    session = get_session(exchange)
    automation = get_exchange_automation(exchange)

    if not hasattr(automation, "confirm_travel_rule"):
        return {"success": False, "message": "Not supported for this exchange"}

    # Lock needed — confirm_travel_rule now navigates browser page to get fresh context.
    if session.lock.locked():
        return {"success": False, "message": "Session busy (login or other operation in progress)"}
    async with session.lock:
        result = await automation.confirm_travel_rule(
            session,
            travel_rule_id=req.travel_rule_id,
            source_exchange=req.source_exchange,
        )

    return result


# ── Debug & Captcha Solving ────────────────────────────────

@router.get("/api/debug/screenshot/{exchange}")
async def get_screenshot(exchange: str):
    if exchange not in EXCHANGE_REGISTRY:
        raise HTTPException(404, f"Exchange '{exchange}' not supported")

    session = get_session(exchange)
    automation = get_exchange_automation(exchange)

    screenshot = await automation.get_screenshot(session)
    if not screenshot:
        raise HTTPException(500, "Failed to take screenshot")

    return {"exchange_name": exchange, "screenshot_base64": base64.b64encode(screenshot).decode()}


@router.get("/api/debug/html/{exchange}")
async def get_html(exchange: str):
    if exchange not in EXCHANGE_REGISTRY:
        raise HTTPException(404, f"Exchange '{exchange}' not supported")

    session = get_session(exchange)
    automation = get_exchange_automation(exchange)

    html = await automation.get_page_html(session)
    if not html:
        raise HTTPException(500, "Failed to get HTML")

    return {"exchange_name": exchange, "html": html}


# ── Debug navigate ─────────────────────────────────────────

@router.get("/api/debug/navigate/{exchange}")
async def debug_navigate(exchange: str, url: str):
    """Navigate exchange page to a URL and return screenshot."""
    session = get_session(exchange)
    page = await session.get_page()
    async with session.lock:
        await page.goto(url, wait_until="domcontentloaded", timeout=15000)
        await page.wait_for_timeout(2000)
        screenshot = await page.screenshot(full_page=False)
    return {"exchange_name": exchange, "url": page.url, "screenshot_base64": base64.b64encode(screenshot).decode()}


class DebugActionRequest(BaseModel):
    action: str  # "click", "js", "screenshot", "click_text", "fill", "type", "press"
    selector: Optional[str] = None
    js_code: Optional[str] = None
    text: Optional[str] = None
    wait_ms: int = 2000


@router.post("/api/debug/action/{exchange}")
async def debug_action(exchange: str, req: DebugActionRequest):
    """Execute an action on the exchange page and return screenshot."""
    session = get_session(exchange)
    page = await session.get_page()
    result_data = {}
    async with session.lock:
        try:
            if req.action == "click" and req.selector:
                await page.click(req.selector, timeout=5000)
            elif req.action == "click_text" and req.text:
                await page.get_by_text(req.text, exact=False).first.click(timeout=5000)
            elif req.action == "fill" and req.selector and req.text:
                await page.fill(req.selector, req.text, timeout=5000)
            elif req.action == "type" and req.text:
                await page.keyboard.type(req.text, delay=50)
            elif req.action == "press" and req.text:
                await page.keyboard.press(req.text)
            elif req.action == "js" and req.js_code:
                js_result = await page.evaluate(req.js_code)
                result_data["js_result"] = str(js_result)[:5000] if js_result else None
            elif req.action == "screenshot":
                pass  # Just take screenshot
            else:
                return {"success": False, "message": "Invalid action or missing params"}
            await page.wait_for_timeout(req.wait_ms)
        except Exception as e:
            result_data["error"] = str(e)
        screenshot = await page.screenshot(full_page=False)
    return {
        "success": True,
        "exchange_name": exchange,
        "url": page.url,
        "screenshot_base64": base64.b64encode(screenshot).decode(),
        **result_data,
    }


# ── Captcha Solving (click forwarding) ────────────────────


class ClickRequest(BaseModel):
    x: float
    y: float


@router.get("/api/captcha/{exchange}/screenshot")
async def get_captcha_screenshot(exchange: str):
    """Return a cropped screenshot showing only the captcha area.
    Also returns the crop offset so frontend can map clicks to full-page coords."""
    session = get_session(exchange)
    page = await session.get_page()

    try:
        # Use JS to find all captcha-related elements and compute a bounding box
        # that covers the OKX modal + reCAPTCHA checkbox + reCAPTCHA challenge panel
        crop_box = await page.evaluate("""() => {
            const boxes = [];

            // 1. Find all visible iframes (reCAPTCHA uses iframes)
            document.querySelectorAll('iframe').forEach(iframe => {
                const r = iframe.getBoundingClientRect();
                if (r.width > 30 && r.height > 30 && r.top < window.innerHeight && r.left < window.innerWidth) {
                    const src = iframe.src || '';
                    const title = iframe.title || '';
                    if (src.includes('recaptcha') || title.toLowerCase().includes('recaptcha')) {
                        boxes.push({ x: r.x, y: r.y, w: r.width, h: r.height });
                    }
                }
            });

            // 2. Find captcha modal by text content (OKX, CoinTR slider, generic)
            const captchaTexts = [
                'Güvenlik Doğrulaması', 'Ben robot değilim',
                'Bulmacayı tamamlamak', 'kaydırın',
                'Slide to', 'slider', 'puzzle'
            ];
            const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
            while (walker.nextNode()) {
                const text = walker.currentNode.textContent.trim();
                const matched = captchaTexts.some(t => text.includes(t));
                if (matched) {
                    let node = walker.currentNode.parentElement;
                    for (let i = 0; i < 15; i++) {
                        if (!node) break;
                        const style = window.getComputedStyle(node);
                        if ((style.position === 'fixed' || style.position === 'absolute') &&
                            node.getBoundingClientRect().width > 100) {
                            const r = node.getBoundingClientRect();
                            boxes.push({ x: r.x, y: r.y, w: r.width, h: r.height });
                            break;
                        }
                        node = node.parentElement;
                    }
                }
            }

            // 3. Find any div that looks like a reCAPTCHA challenge overlay
            //    (Google creates divs with high z-index for the challenge)
            document.querySelectorAll('div').forEach(div => {
                const style = window.getComputedStyle(div);
                const zIndex = parseInt(style.zIndex) || 0;
                if (zIndex >= 2000000000) {  // reCAPTCHA uses very high z-index
                    const r = div.getBoundingClientRect();
                    if (r.width > 200 && r.height > 200) {
                        boxes.push({ x: r.x, y: r.y, w: r.width, h: r.height });
                    }
                }
            });

            if (boxes.length === 0) return null;

            // Compute union bounding box of all found elements
            let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
            boxes.forEach(b => {
                minX = Math.min(minX, b.x);
                minY = Math.min(minY, b.y);
                maxX = Math.max(maxX, b.x + b.w);
                maxY = Math.max(maxY, b.y + b.h);
            });

            const pad = 15;
            return {
                x: Math.max(0, minX - pad),
                y: Math.max(0, minY - pad),
                width: Math.min(1280, (maxX - minX) + pad * 2),
                height: Math.min(800, (maxY - minY) + pad * 2),
            };
        }""")

        if not crop_box or crop_box["width"] < 50:
            # Fallback: full page screenshot so user can see everything
            crop_box = {"x": 0, "y": 0, "width": 1280, "height": 800}

        # Clamp to viewport
        crop_box["x"] = max(0, crop_box["x"])
        crop_box["y"] = max(0, crop_box["y"])
        crop_box["width"] = min(crop_box["width"], 1280 - crop_box["x"])
        crop_box["height"] = min(crop_box["height"], 800 - crop_box["y"])

        screenshot = await page.screenshot(clip=crop_box)
        return {
            "screenshot_base64": base64.b64encode(screenshot).decode(),
            "crop": crop_box,
        }
    except Exception as e:
        logger.error(f"Captcha screenshot failed: {e}")
        raise HTTPException(500, f"Screenshot failed: {e}")


@router.post("/api/captcha/{exchange}/click")
async def forward_click(exchange: str, req: ClickRequest):
    """Forward a mouse click from the frontend to the browser page at (x, y).
    Coordinates are relative to the page viewport (1280x800)."""
    session = get_session(exchange)
    page = await session.get_page()

    try:
        await page.mouse.click(req.x, req.y)
        logger.info(f"Forwarded click to {exchange} at ({req.x}, {req.y})")
        # Wait for page to react
        await page.wait_for_timeout(2500)

        # Signal 1: If auth token was just captured, login succeeded
        if session.get_auth_token():
            session.notify_captcha_solved()
            logger.info(f"Captcha solved for {exchange} — auth token captured")
            return {"success": True, "captcha_still_visible": False}

        # Signal 2: Page navigated away from login
        current_url = page.url
        if "/login" not in current_url and "/account/login" not in current_url and "giris" not in current_url and "/signin" not in current_url:
            session.notify_captcha_solved()
            logger.info(f"Captcha solved for {exchange} — page navigated away from login")
            return {"success": True, "captcha_still_visible": False}

        # Signal 3: Check if captcha UI is still visible
        still_visible = await page.evaluate("""() => {
            // Check reCAPTCHA challenge iframe first (most reliable)
            const iframes = document.querySelectorAll('iframe');
            for (const iframe of iframes) {
                const src = iframe.src || '';
                if (src.includes('recaptcha') && iframe.offsetParent !== null) {
                    const r = iframe.getBoundingClientRect();
                    if (r.width > 50 && r.height > 50) return true;
                }
            }
            // Check high z-index overlay divs (reCAPTCHA challenge panel)
            const divs = document.querySelectorAll('div');
            for (const div of divs) {
                const z = parseInt(window.getComputedStyle(div).zIndex) || 0;
                if (z >= 2000000000) {
                    const r = div.getBoundingClientRect();
                    if (r.width > 200 && r.height > 200) return true;
                }
            }
            // Check captcha modal text (OKX, CoinTR slider, generic)
            const texts = ['Güvenlik Doğrulaması', 'Security Verification', 'Ben robot değilim', 'Bulmacayı tamamlamak', 'kaydırın'];
            for (const t of texts) {
                const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
                while (walker.nextNode()) {
                    if (walker.currentNode.textContent.trim().includes(t)) {
                        const el = walker.currentNode.parentElement;
                        if (el && el.offsetParent !== null) {
                            const rect = el.getBoundingClientRect();
                            if (rect.width > 0 && rect.height > 0) return true;
                        }
                    }
                }
            }
            return false;
        }""")

        if not still_visible:
            session.notify_captcha_solved()
            logger.info(f"Captcha no longer visible for {exchange}, notified login flow")

        return {"success": True, "captcha_still_visible": still_visible}
    except Exception as e:
        logger.error(f"Click forwarding failed: {e}")
        return {"success": False, "message": str(e)}


class DragRequest(BaseModel):
    start_x: float
    start_y: float
    end_x: float
    end_y: float
    steps: int = 25


@router.post("/api/captcha/{exchange}/drag")
async def forward_drag(exchange: str, req: DragRequest):
    """Forward a mouse drag from (start_x, start_y) to (end_x, end_y).
    Used for slider captchas. Coordinates are relative to the page viewport."""
    session = get_session(exchange)
    page = await session.get_page()

    try:
        import random
        import math

        # Human-like drag: hover first, then press and drag with easing
        # 1. Move to start position with a slight offset, then to exact start
        await page.mouse.move(req.start_x - random.uniform(5, 15), req.start_y + random.uniform(-5, 5))
        await page.wait_for_timeout(random.randint(80, 200))
        await page.mouse.move(req.start_x, req.start_y)
        await page.wait_for_timeout(random.randint(100, 300))

        # 2. Press down
        await page.mouse.down()
        await page.wait_for_timeout(random.randint(50, 150))

        # 3. Drag with human-like easing (slow-fast-slow curve)
        steps = max(req.steps, 15)
        for i in range(1, steps + 1):
            t = i / steps
            # Ease-out cubic: fast start, slow end (how humans drag)
            eased_t = 1 - (1 - t) ** 3

            # Vertical wobble: stronger in middle, less at edges
            wobble_amplitude = 2.0 * math.sin(t * math.pi)
            wobble_y = random.uniform(-wobble_amplitude, wobble_amplitude)

            ix = req.start_x + (req.end_x - req.start_x) * eased_t
            iy = req.start_y + (req.end_y - req.start_y) * eased_t + wobble_y
            await page.mouse.move(ix, iy)

            # Variable timing: slower at start/end, faster in middle
            if t < 0.15 or t > 0.85:
                delay = random.randint(20, 50)
            else:
                delay = random.randint(8, 22)
            await page.wait_for_timeout(delay)

        # 4. Small pause at end before release (human hesitation)
        await page.wait_for_timeout(random.randint(50, 200))
        await page.mouse.up()
        logger.info(f"Forwarded drag to {exchange} from ({req.start_x},{req.start_y}) to ({req.end_x},{req.end_y})")

        await page.wait_for_timeout(2500)

        # Check if captcha solved
        if session.get_auth_token():
            session.notify_captcha_solved()
            return {"success": True, "captcha_still_visible": False}

        current_url = page.url
        if "/login" not in current_url and "/account/login" not in current_url and "/giris" not in current_url and "/signin" not in current_url:
            session.notify_captcha_solved()
            return {"success": True, "captcha_still_visible": False}

        return {"success": True, "captcha_still_visible": True}
    except Exception as e:
        logger.error(f"Drag forwarding failed: {e}")
        return {"success": False, "message": str(e)}


class TypeRequest(BaseModel):
    text: str
    field_selector: str = ""  # optional CSS selector to click first


@router.post("/api/captcha/{exchange}/type")
async def forward_type(exchange: str, req: TypeRequest):
    """Type text into the browser page. Optionally click a field first via selector."""
    session = get_session(exchange)
    page = await session.get_page()

    try:
        if req.field_selector:
            field = page.locator(req.field_selector).first
            await field.click(force=True, timeout=5000)
            await page.wait_for_timeout(300)
            await field.fill(req.text)
        else:
            # Try to auto-find a visible code/text input to focus first
            focused = await page.evaluate("""() => {
                // Check if something is already focused
                const active = document.activeElement;
                if (active && (active.tagName === 'INPUT' || active.tagName === 'TEXTAREA')) {
                    return 'already_focused';
                }
                // Try to find a visible code input (pin inputs, OTP fields, etc.)
                const selectors = [
                    'input[autocomplete="one-time-code"]:not([disabled])',
                    'input[class*="pin-inner-input"]:not([disabled])',
                    'input[type="text"]:not([disabled]):not([readonly])',
                    'input[type="tel"]:not([disabled]):not([readonly])',
                    'input[type="number"]:not([disabled]):not([readonly])',
                ];
                for (const sel of selectors) {
                    const els = document.querySelectorAll(sel);
                    for (const el of els) {
                        if (el.offsetParent !== null && el.getBoundingClientRect().width > 10) {
                            el.focus();
                            el.click();
                            return 'auto_focused: ' + sel;
                        }
                    }
                }
                return 'no_input_found';
            }""")
            logger.info(f"Type focus state for {exchange}: {focused}")
            await page.wait_for_timeout(200)

            # Type each character individually (works better with pin inputs)
            for char in req.text:
                await page.keyboard.press(char)
                await page.wait_for_timeout(80)

        logger.info(f"Typed {len(req.text)} chars into {exchange} (selector={req.field_selector or 'focused'})")
        await page.wait_for_timeout(500)
        return {"success": True}
    except Exception as e:
        logger.error(f"Type forwarding failed: {e}")
        return {"success": False, "message": str(e)}


@router.post("/api/captcha/{exchange}/solved")
async def mark_captcha_solved(exchange: str):
    """Manually mark captcha as solved (if auto-detection misses it)."""
    session = get_session(exchange)
    session.notify_captcha_solved()
    return {"success": True, "message": "Captcha marked as solved"}
