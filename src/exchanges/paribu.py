"""
Paribu browser automation — login, token capture, TRY withdrawal.
"""
import asyncio
import json
import os
import time
import logging
from typing import Dict, Any, Optional

import aiohttp
from playwright.async_api import Page, Request

from src.exchanges.base import BaseExchangeAutomation
from src.browser.session import ExchangeSession
from src.browser.manager import browser_manager
from src.security.totp import generate_totp_code

logger = logging.getLogger(__name__)

LOGIN_URL = "https://www.paribu.com/auth/sign-in"
WITHDRAW_URL = "https://web.paribu.com/v2/withdraws"
USER_ME_URL = "https://web.paribu.com/v2/users/me"

DEBUG_DIR = "/app/data/debug"


class ParibuAutomation(BaseExchangeAutomation):
    exchange_name = "paribu"

    # ── debug helper ──────────────────────────────────────────

    async def _debug_screenshot(self, page: Page, label: str) -> None:
        """Save a debug screenshot with label."""
        try:
            os.makedirs(DEBUG_DIR, exist_ok=True)
            path = os.path.join(DEBUG_DIR, f"paribu_{label}.png")
            await page.screenshot(path=path, full_page=False)
            logger.info(f"Paribu: [DEBUG] screenshot saved: {label}.png (url={page.url})")
        except Exception as e:
            logger.warning(f"Paribu: [DEBUG] screenshot failed for {label}: {e}")

    # ── login ──────────────────────────────────────────────────

    async def login(self, session: ExchangeSession, credentials: Dict[str, str], _retry_count: int = 0) -> dict:
        """
        Paribu login flow with debug screenshots at every step:
        1. Navigate to sign-in page, dismiss cookie consent
        2. Fill phone number + password (same page), click "Giriş yap"
        3. Handle captcha if present (pause-and-wait)
        4. Enter TOTP code (Google Authenticator)
        5. Wait for redirect, capture tokens, save storage state
        """
        session.status = "logging_in"
        page = await session.get_page()

        try:
            # Set up token interceptor before navigation
            self._setup_request_interceptor(page, session)

            # Check if browser is already logged in
            try:
                current_url = page.url
                token = session.get_auth_token()
                if token and "/auth/sign-in" not in current_url and "about:blank" not in current_url:
                    logger.info(f"Paribu: browser already on {current_url} with token — verifying session")
                    if await self.check_session(session):
                        session.set_logged_in(session.captured_tokens)
                        logger.info("Paribu: already logged in — skipping login flow")
                        return {"success": True, "message": "Already logged in"}
                    else:
                        logger.info("Paribu: token expired, proceeding with fresh login")
            except Exception:
                pass

            # ── Navigate to login page ──
            logger.info("Paribu: navigating to login page")
            await page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_timeout(4000)
            await self._debug_screenshot(page, "01_page_loaded")

            # ── Dismiss cookie consent (may appear lazily) ──
            await self._dismiss_cookie_consent(page)
            await self._debug_screenshot(page, "02_after_cookie_dismiss")

            # Check if cookies caused auto-redirect (already logged in)
            current_url = page.url
            if "/auth/sign-in" not in current_url:
                logger.info(f"Paribu: cookies auto-logged in — redirected to {current_url}")
                await page.wait_for_timeout(3000)
                token = session.get_auth_token()
                if token:
                    session.set_logged_in(session.captured_tokens)
                    await browser_manager.save_storage_state(self.exchange_name)
                    return {"success": True, "message": "Auto-login via saved cookies, token captured"}
                else:
                    try:
                        await page.goto("https://www.paribu.com/wallet", wait_until="domcontentloaded", timeout=15000)
                        await page.wait_for_timeout(3000)
                    except Exception:
                        pass
                    token = session.get_auth_token()
                    if token:
                        session.set_logged_in(session.captured_tokens)
                        await browser_manager.save_storage_state(self.exchange_name)
                        return {"success": True, "message": "Auto-login via saved cookies, token captured"}
                    else:
                        session.set_logged_in()
                        return {"success": True, "message": "Auto-login via cookies but no API token captured yet"}

            # ── Step 1: Fill phone number ──

            phone = credentials["email"]  # phone number stored in email column
            # Strip country code prefix — Paribu's input has a built-in +90 prefix
            phone_digits = phone.lstrip("+")
            if phone_digits.startswith("90") and len(phone_digits) > 10:
                phone_digits = phone_digits[2:]  # Remove country code, keep 5xxxxxxxxx
            logger.info(f"Paribu: entering phone number ***{phone_digits[-4:]}")

            phone_input = page.locator("input#phoneNumber")
            await phone_input.wait_for(state="visible", timeout=10000)
            await phone_input.click(force=True)
            await phone_input.fill(phone_digits)
            await page.wait_for_timeout(500)
            await self._debug_screenshot(page, "03_phone_entered")

            # ── Step 2: Fill password ──

            logger.info("Paribu: entering password")
            password_input = page.locator("input#password")
            await password_input.wait_for(state="visible", timeout=5000)
            await password_input.click(force=True)
            await password_input.fill(credentials["password"])
            await page.wait_for_timeout(500)
            await self._debug_screenshot(page, "04_password_entered")

            # ── Step 3: Dismiss cookie (may have appeared) and click submit ──

            # Cookie modal appears lazily — dismiss it before submit
            await self._dismiss_cookie_consent(page)
            await self._debug_screenshot(page, "04b_before_submit")

            # Submit via JS to bypass any remaining overlay
            await page.evaluate("""() => {
                const btn = document.querySelector('button[type="submit"]');
                if (btn) btn.click();
            }""")
            logger.info("Paribu: clicked 'Giriş yap' via JS")
            await page.wait_for_timeout(5000)
            await self._debug_screenshot(page, "05_after_submit")

            # ── Step 4: Handle device approval modal ──

            device_approval = await page.evaluate("""() => {
                return document.body.innerText.includes('Bu cihazla giriş yapabilmek');
            }""")

            if device_approval:
                await self._debug_screenshot(page, "06_device_approval")
                logger.info("Paribu: device approval required — clicking Tamam and starting email watch")
                # Click "Tamam" to dismiss the info modal
                try:
                    tamam_btn = page.locator('button:has-text("Tamam"), a:has-text("Tamam")').first
                    await tamam_btn.click(force=True, timeout=5000)
                except Exception:
                    await page.evaluate("""() => {
                        const btns = document.querySelectorAll('button, a');
                        for (const b of btns) {
                            if (b.textContent.trim() === 'Tamam') { b.click(); break; }
                        }
                    }""")
                await page.wait_for_timeout(2000)
                await self._debug_screenshot(page, "06b_after_tamam")

                # Automated device approval via IMAP
                from src.email.monitor import email_monitor
                from src.email.models import EmailWatchRequest

                if not email_monitor._get_imap_creds():
                    session.set_error("Device approval required — check email and click the approval link, then retry login")
                    return {"success": False, "message": "Device approval required — configure IMAP settings in the frontend, or check email and click the approval link within 2 hours, then retry login"}

                if _retry_count >= 1:
                    session.set_error("Device approval still required after email confirmation — manual intervention needed")
                    return {"success": False, "message": "Device approval still required after email confirmation — manual intervention needed"}

                watch_id = f"paribu_device_approval_{int(time.time())}"
                request = EmailWatchRequest(
                    watch_id=watch_id,
                    sender_contains="noreply@paribu.com",
                    subject_contains="cihaz",
                    body_link_pattern=r'(https?://www\.paribu\.com/verify/device/approve/[^\s"<>]+)',
                    max_age_seconds=300,
                    timeout_seconds=600,
                )

                session.status = "waiting_for_email_approval"
                logger.info(f"Paribu: watching for device approval email (watch_id={watch_id})")

                try:
                    email_future = email_monitor.watch(request)
                    match = await asyncio.wait_for(email_future, timeout=600)
                    logger.info(f"Paribu: device approval email matched — opening link in browser")

                    if not match.link:
                        session.set_error("Device approval email found but no approval link extracted")
                        return {"success": False, "message": "Device approval email found but no approval link"}

                    # Open approval link in the browser (Paribu's approval page is a JS SPA
                    # that requires client-side rendering — a simple HTTP GET won't work)
                    await page.goto(match.link, wait_until="domcontentloaded", timeout=30000)
                    await page.wait_for_timeout(8000)
                    await self._debug_screenshot(page, "07_approval_page")

                    # Check if the page shows success/approval confirmation
                    page_text = await page.evaluate("() => document.body.innerText")
                    logger.info(f"Paribu: approval page text (first 200 chars): {page_text[:200]}")

                    # Wait a bit more for Paribu server to process
                    await page.wait_for_timeout(3000)
                    logger.info("Paribu: device approved — restarting login flow")
                    return await self.login(session, credentials, _retry_count + 1)
                except asyncio.TimeoutError:
                    email_monitor.cancel_watch(watch_id)
                    session.set_error("Device approval email not received within timeout")
                    return {"success": False, "message": "Device approval email not received within 10 minutes — check inbox manually"}
                except Exception as e:
                    email_monitor.cancel_watch(watch_id)
                    session.set_error(f"Device approval email handling failed: {e}")
                    return {"success": False, "message": f"Device approval failed: {e}"}

            # ── Step 4b: Handle captcha if present ──

            captcha_detected = await self._check_captcha_visible(page)
            if captcha_detected:
                await self._debug_screenshot(page, "06_captcha_detected")
                logger.info("Paribu: captcha detected — waiting for human to solve via frontend")
                solved = await session.wait_for_captcha_solved(timeout=300)
                if not solved:
                    current_url = page.url
                    token = session.get_auth_token()
                    if token and "/auth/sign-in" not in current_url:
                        solved = True
                    elif token:
                        if await self.check_session(session):
                            session.set_logged_in(session.captured_tokens)
                            await browser_manager.save_storage_state(self.exchange_name)
                            return {"success": True, "message": "Login successful (detected after captcha)"}
                    if not solved:
                        session.set_error("Captcha not solved in time")
                        return {"success": False, "message": "Captcha not solved — open the frontend and click the captcha"}
                await page.wait_for_timeout(5000)
                await self._debug_screenshot(page, "07_after_captcha")

            # ── Step 5: TOTP (Google Authenticator) ──

            totp_secret = credentials.get("totp_secret")
            if totp_secret:
                logger.info("Paribu: waiting for TOTP prompt")
                await self._debug_screenshot(page, "08_before_totp")

                try:
                    # Check if we're still on the login form with no new UI
                    phone_visible = await page.locator("input#phoneNumber").is_visible()
                    page_text = await page.evaluate("() => document.body.innerText")
                    has_totp_prompt = any(t in page_text for t in ["Doğrulama", "doğrulama", "Authenticator", "kod"])

                    if phone_visible and "/auth/sign-in" in page.url and not has_totp_prompt:
                        await self._debug_screenshot(page, "08b_still_on_login")
                        logger.warning("Paribu: still on login page after submit — check credentials")
                        session.set_error("Login form did not progress — check phone number and password")
                        return {"success": False, "message": "Login form did not progress — check credentials"}

                    # Paribu uses 6 separate single-digit input boxes for TOTP
                    # Wait for the TOTP page to appear (has "doğrulama" text)
                    await page.wait_for_timeout(2000)
                    await self._debug_screenshot(page, "09_totp_page")

                    code = generate_totp_code(totp_secret)
                    logger.info(f"Paribu: entering TOTP code {code[:2]}****")

                    # Type digits one by one — each keystroke auto-advances to next box
                    first_input = page.locator('input[inputmode="numeric"]:not(#phoneNumber), input[maxlength="1"]').first
                    await first_input.wait_for(state="visible", timeout=15000)
                    await first_input.click(force=True)
                    for digit in code:
                        await page.keyboard.press(digit)
                        await page.wait_for_timeout(100)

                    await page.wait_for_timeout(1500)
                    await self._debug_screenshot(page, "10_totp_entered")

                    # Click "Doğrula" button
                    try:
                        confirm_btn = page.locator(
                            'button:has-text("Doğrula"):visible, '
                            'button:has-text("Onayla"):visible, '
                            'button[type="submit"]:visible'
                        ).first
                        await confirm_btn.click(force=True, timeout=3000)
                        logger.info("Paribu: clicked TOTP confirm button")
                    except Exception:
                        pass  # may auto-submit after 6th digit
                    await page.wait_for_timeout(3000)
                    await self._debug_screenshot(page, "11_after_totp_submit")

                except Exception as e:
                    logger.warning(f"Paribu: TOTP step issue: {e}")
                    await self._debug_screenshot(page, "08c_totp_error")
                    if "/auth/" not in page.url:
                        logger.info("Paribu: already past login page — TOTP may not be required")

            # ── Step 6: Handle passkey prompt and wait for redirect ──

            # Check for passkey enrollment prompt ("Daha sonra" = skip)
            try:
                skip_btn = page.locator('button:has-text("Daha sonra"), a:has-text("Daha sonra")').first
                await skip_btn.wait_for(state="visible", timeout=5000)
                await skip_btn.click(force=True)
                logger.info("Paribu: skipped passkey enrollment (clicked 'Daha sonra')")
                await page.wait_for_timeout(3000)
                await self._debug_screenshot(page, "12_after_passkey_skip")
            except Exception:
                logger.debug("Paribu: no passkey prompt found")

            logger.info("Paribu: waiting for login redirect...")
            try:
                await page.wait_for_url(
                    lambda url: "/auth/" not in url,
                    timeout=15000,
                )
            except Exception:
                current_url = page.url
                logger.warning(f"Paribu: URL after wait: {current_url}")
                await self._debug_screenshot(page, "12_redirect_timeout")
                # If we already have the token, consider it a success
                token = session.get_auth_token()
                if token:
                    logger.info("Paribu: have token despite URL not changing — navigating to wallet")
                    try:
                        await page.goto("https://www.paribu.com/wallet", wait_until="domcontentloaded", timeout=15000)
                        await page.wait_for_timeout(3000)
                    except Exception:
                        pass
                elif "/auth/" in current_url:
                    session.set_error("Login redirect timed out — may need captcha or additional verification")
                    return {"success": False, "message": session.last_error}

            await page.wait_for_timeout(3000)
            await self._debug_screenshot(page, "13_after_redirect")

            # ── Step 7: Verify token capture ──

            token = session.get_auth_token()
            if token:
                session.set_logged_in(session.captured_tokens)
                await browser_manager.save_storage_state(self.exchange_name)
                logger.info(f"Paribu: login successful, auth token captured ({len(token)} chars)")
                await self._debug_screenshot(page, "14_success")
                return {"success": True, "message": "Login successful, token captured"}
            else:
                logger.info("Paribu: no token captured yet, navigating to wallet page")
                try:
                    await page.goto("https://www.paribu.com/wallet", wait_until="domcontentloaded", timeout=15000)
                    await page.wait_for_timeout(3000)
                except Exception:
                    pass

                await self._debug_screenshot(page, "15_wallet_page")
                token = session.get_auth_token()
                if token:
                    session.set_logged_in(session.captured_tokens)
                    await browser_manager.save_storage_state(self.exchange_name)
                    logger.info(f"Paribu: token captured after wallet page ({len(token)} chars)")
                    return {"success": True, "message": "Login successful, token captured"}
                else:
                    session.set_logged_in()
                    await browser_manager.save_storage_state(self.exchange_name)
                    logger.warning("Paribu: logged in but no auth token captured yet")
                    return {"success": True, "message": "Login successful but no API token captured yet"}

        except Exception as e:
            error_msg = f"Login failed: {str(e)}"
            logger.error(f"Paribu: {error_msg}")
            await self._debug_screenshot(page, "99_error")
            try:
                await page.close()
            except Exception:
                pass
            session._page = None
            session.set_error(error_msg)
            return {"success": False, "message": error_msg}

    # ── cookie consent ────────────────────────────────────────

    async def _dismiss_cookie_consent(self, page: Page) -> None:
        """Dismiss Paribu cookie consent modal and wait until it's gone."""
        # Check if cookie modal exists in DOM (even if not yet visible)
        has_modal = await page.evaluate("""() => {
            return !!document.querySelector('.cookie-modal');
        }""")

        if not has_modal:
            logger.debug("Paribu: no cookie modal in DOM")
            return

        logger.info("Paribu: cookie modal found in DOM, dismissing via JS")

        # Click accept and remove overlay
        result = await page.evaluate("""() => {
            // Click the accept button
            const modal = document.querySelector('.cookie-modal');
            if (modal) {
                const buttons = modal.querySelectorAll('button');
                for (const btn of buttons) {
                    if (btn.textContent.includes('kabul')) {
                        btn.click();
                        break;
                    }
                }
            }
            // Also remove the overlay that blocks pointer events
            const overlays = document.querySelectorAll('.p-overlay');
            overlays.forEach(el => {
                // Only remove if it's the cookie overlay (covers full page)
                const style = window.getComputedStyle(el);
                if (style.position === 'fixed' || el.style.position === 'fixed') {
                    el.remove();
                }
            });
            // Remove the modal itself after a moment
            setTimeout(() => {
                const m = document.querySelector('.cookie-modal');
                if (m) m.remove();
            }, 500);
            return true;
        }""")
        logger.info(f"Paribu: cookie dismiss JS executed: {result}")
        await page.wait_for_timeout(1500)

        # Verify modal is gone
        still_there = await page.evaluate("() => !!document.querySelector('.cookie-modal')")
        if still_there:
            await page.evaluate("""() => {
                document.querySelectorAll('.cookie-modal').forEach(el => el.remove());
                document.querySelectorAll('.p-overlay').forEach(el => el.remove());
            }""")
            logger.info("Paribu: force-removed remaining cookie modal elements")

    # ── captcha detection ────────────────────────────────────

    async def _check_captcha_visible(self, page: Page) -> bool:
        """Check if a captcha / security verification is visible."""
        search_texts = [
            "robot",
            "captcha",
            "Güvenlik Doğrulaması",
            "Security Verification",
            "Ben robot değilim",
            "I'm not a robot",
        ]
        for text in search_texts:
            try:
                loc = page.get_by_text(text, exact=False)
                if await loc.first.is_visible():
                    logger.info(f"Paribu: captcha detected via text '{text}'")
                    return True
            except Exception:
                pass

        try:
            iframe = page.locator('iframe[src*="recaptcha"], iframe[title*="reCAPTCHA"], iframe[src*="captcha"]').first
            if await iframe.is_visible():
                logger.info("Paribu: captcha detected via iframe")
                return True
        except Exception:
            pass

        logger.debug("Paribu: no captcha detected")
        return False

    # ── request interceptor ────────────────────────────────────

    def _setup_request_interceptor(self, page: Page, session: ExchangeSession) -> None:
        """Capture authorization and pragma-cache-local headers from Paribu API requests."""

        def on_request(request: Request) -> None:
            url = request.url
            if "paribu.com" not in url:
                return

            headers = request.headers
            auth = headers.get("authorization")
            pragma = headers.get("pragma-cache-local")

            if auth and auth != session.captured_tokens.get("authorization"):
                session.captured_tokens["authorization"] = auth
                logger.info(f"Paribu: captured fresh auth token ({len(auth)} chars)")

            if pragma and pragma != session.captured_tokens.get("pragma-cache-local"):
                session.captured_tokens["pragma-cache-local"] = pragma
                logger.info(f"Paribu: captured fresh pragma-cache-local ({len(pragma)} chars)")

        page.on("request", on_request)

    # ── session check ──────────────────────────────────────────

    async def check_session(self, session: ExchangeSession) -> bool:
        """Check if session is still valid by calling an authenticated endpoint."""
        token = session.get_auth_token()
        if not token:
            return False

        pragma = session.captured_tokens.get("pragma-cache-local", "")

        try:
            async with aiohttp.ClientSession() as http:
                async with http.get(
                    USER_ME_URL,
                    headers={
                        "authorization": token,
                        "pragma-cache-local": pragma,
                        "device": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36",
                        "platform": "Android",
                    },
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("payload") or data.get("data") or isinstance(data, dict):
                            return True
                    return False
        except Exception as e:
            logger.warning(f"Paribu session check failed: {e}")
            return False

    # ── keepalive ──────────────────────────────────────────────

    async def keepalive(self, session: ExchangeSession) -> None:
        """Navigate between tabs to keep the SPA alive."""
        try:
            page = await session.get_page()
            current_url = page.url
            if "/login" in current_url or "about:blank" in current_url:
                return

            if "/wallet" in current_url:
                url = "https://www.paribu.com/markets"
                label = "Piyasalar"
            else:
                url = "https://www.paribu.com/wallet"
                label = "Cüzdan"

            await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            logger.info(f"Paribu: keepalive — switched to {label}")
        except Exception as e:
            logger.debug(f"Paribu: keepalive error: {e}")

    # ── TRY withdrawal ─────────────────────────────────────────

    async def withdraw_try(
        self,
        session: ExchangeSession,
        amount: float,
        iban: str,
        payment_account_id: str,
    ) -> dict:
        """
        Execute TRY withdrawal via the Paribu API using captured auth tokens.
        payment_account_id is not used for Paribu (uses IBAN directly).
        """
        token = session.get_auth_token()
        if not token:
            return {"success": False, "order_id": None, "message": "No auth token available"}

        pragma = session.captured_tokens.get("pragma-cache-local", "")

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "authorization": token,
            "pragma-cache-local": pragma,
            "device": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36",
            "platform": "Android",
        }

        payload = {
            "amount": str(int(amount)),
            "address": iban,
            "network": "banktr",
            "currency": "tl",
        }

        try:
            async with aiohttp.ClientSession() as http:
                async with http.post(
                    WITHDRAW_URL,
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    try:
                        data = await resp.json()
                    except Exception:
                        text = await resp.text()
                        logger.error(f"Paribu response parse error: {text[:500]}")
                        return {"success": False, "order_id": None, "message": f"Response parse error: {text[:200]}"}

                    logger.info(f"Paribu withdraw response (amount={amount}): {json.dumps(data)}")

                    if isinstance(data, dict):
                        msg = data.get("message")
                        if isinstance(msg, dict) and msg.get("severity") == "success":
                            uid = data.get("payload", {}).get("uid", "N/A")
                            return {
                                "success": True,
                                "order_id": uid,
                                "message": "Withdrawal submitted",
                            }
                        else:
                            if isinstance(msg, dict):
                                error_text = msg.get("title", {}).get("langkey", "Unknown error")
                            else:
                                error_text = str(msg)
                            return {
                                "success": False,
                                "order_id": None,
                                "message": f"Paribu error: {error_text}",
                            }

                    return {
                        "success": False,
                        "order_id": None,
                        "message": f"Unexpected response: {str(data)[:200]}",
                    }

        except Exception as e:
            error_msg = f"Withdrawal request failed: {str(e)}"
            logger.error(f"Paribu: {error_msg}")
            return {"success": False, "order_id": None, "message": error_msg}

    # ── screenshots / debug ────────────────────────────────────

    async def get_screenshot(self, session: ExchangeSession) -> Optional[bytes]:
        """Take a screenshot of the current page."""
        page = await session.get_page()
        try:
            return await page.screenshot(full_page=False, timeout=10000)
        except Exception as e:
            logger.error(f"Screenshot failed: {e}")
            try:
                await page.close()
            except Exception:
                pass
            session._page = None
            return None

    async def get_page_html(self, session: ExchangeSession) -> Optional[str]:
        """Return the current page's HTML content."""
        page = await session.get_page()
        try:
            return await page.content()
        except Exception as e:
            logger.error(f"Get HTML failed: {e}")
            return None
