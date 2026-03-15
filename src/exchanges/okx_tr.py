"""
OKX TR browser automation — login, token capture, TRY withdrawal.
"""
import asyncio
import json
import time
import uuid
import logging
from typing import Dict, Any, Optional

import aiohttp
from playwright.async_api import Page, Request

from src.exchanges.base import BaseExchangeAutomation
from src.browser.session import ExchangeSession
from src.browser.manager import browser_manager
from src.security.totp import generate_totp_code

logger = logging.getLogger(__name__)

LOGIN_URL = "https://tr.okx.com/account/login"
WITHDRAW_URL = "https://tr.okx.com/priapi/v3/b2c/fiat/order/submit"


class OKXTRAutomation(BaseExchangeAutomation):
    exchange_name = "okx_tr"

    # ── login ──────────────────────────────────────────────────

    async def login(self, session: ExchangeSession, credentials: Dict[str, str]) -> dict:
        """
        Full OKX TR login flow:
        1. Navigate to login page
        2. Fill email, click continue
        3. Fill password, submit
        4. Generate & fill TOTP code
        5. Wait for successful redirect
        6. Set up request interceptor to capture auth tokens
        """
        session.status = "logging_in"
        page = await session.get_page()

        try:
            # Disable WebAuthn/passkeys to prevent native browser dialog from blocking login
            try:
                cdp = await page.context.new_cdp_session(page)
                await cdp.send("WebAuthn.enable")
                await cdp.send("WebAuthn.addVirtualAuthenticator", {
                    "options": {
                        "protocol": "ctap2",
                        "transport": "internal",
                        "hasResidentKey": True,
                        "hasUserVerification": True,
                        "isUserVerified": False,   # will reject passkey prompts
                    }
                })
                logger.info("OKX TR: disabled native WebAuthn/passkey dialogs via CDP")
            except Exception as e:
                logger.debug(f"OKX TR: CDP WebAuthn override skipped: {e}")

            # Set up token interceptor before navigation
            self._setup_request_interceptor(page, session)

            # Check if browser is already logged in (don't destroy an active session)
            try:
                current_url = page.url
                token = session.get_auth_token()
                if token and "/login" not in current_url and "about:blank" not in current_url:
                    logger.info(f"OKX TR: browser already on {current_url} with token — verifying session")
                    if await self.check_session(session):
                        session.set_logged_in(session.captured_tokens)
                        logger.info("OKX TR: already logged in — skipping login flow")
                        return {"success": True, "message": "Already logged in"}
                    else:
                        logger.info("OKX TR: token expired, proceeding with fresh login")
            except Exception:
                pass  # page may not be navigated yet

            logger.info("OKX TR: navigating to login page")
            await page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_timeout(3000)

            # Check if cookies caused auto-redirect (already logged in)
            current_url = page.url
            if "/login" not in current_url and "/account/login" not in current_url:
                logger.info(f"OKX TR: cookies auto-logged in — redirected to {current_url}")
                # Wait for API calls to fire (token capture)
                await page.wait_for_timeout(3000)
                token = session.get_auth_token()
                if token:
                    session.set_logged_in(session.captured_tokens)
                    await browser_manager.save_storage_state(self.exchange_name)
                    logger.info(f"OKX TR: auto-login successful, token captured ({len(token)} chars)")
                    return {"success": True, "message": "Auto-login via saved cookies, token captured"}
                else:
                    # Navigate to assets to trigger API calls
                    try:
                        await page.goto("https://tr.okx.com/asset", wait_until="domcontentloaded", timeout=15000)
                        await page.wait_for_timeout(3000)
                    except Exception:
                        pass
                    token = session.get_auth_token()
                    if token:
                        session.set_logged_in(session.captured_tokens)
                        await browser_manager.save_storage_state(self.exchange_name)
                        logger.info(f"OKX TR: auto-login successful after assets page ({len(token)} chars)")
                        return {"success": True, "message": "Auto-login via saved cookies, token captured"}
                    else:
                        session.set_logged_in()
                        logger.warning("OKX TR: auto-logged in but no token captured yet")
                        return {"success": True, "message": "Auto-login via cookies but no API token captured yet"}

            # Dismiss cookie consent popup if present
            try:
                cookie_btn = page.locator(
                    'button:has-text("Tüm Tanımlama Bilgilerini Kabul Et"), '
                    'button:has-text("Accept All"), '
                    'button:has-text("Kabul Et")'
                ).first
                await cookie_btn.click(timeout=3000)
                logger.info("OKX TR: dismissed cookie consent")
                await page.wait_for_timeout(1000)
            except Exception:
                pass  # No cookie popup

            # Switch to Email tab (default is Phone Number)
            try:
                email_tab = page.locator('[data-pane-id="email"]')
                await email_tab.click(timeout=5000)
                logger.info("OKX TR: switched to email login tab")
                await page.wait_for_timeout(1000)
            except Exception as e:
                logger.warning(f"OKX TR: could not switch to email tab: {e}")

            # Step 1: Email — use the visible input inside the active tab panel
            email = credentials["email"]
            logger.info(f"OKX TR: entering email {email[:3]}***")

            # After clicking email tab, find the visible text input with login-input-input class
            email_input = page.locator('input.login-input-input[type="text"]:visible').first
            await email_input.wait_for(state="visible", timeout=15000)
            await email_input.click()
            await email_input.fill("")
            await email_input.type(email, delay=50)
            await email_input.evaluate("el => { el.dispatchEvent(new Event('input', {bubbles:true})); el.dispatchEvent(new Event('change', {bubbles:true})); el.blur(); }")
            await page.wait_for_timeout(1000)

            # OKX defaults to passwordless flow. Click "Devam Et" first, then
            # click "Şifre ile Giriş Yap" link that appears while it loads.
            # Step 1a: Click Devam Et / Continue
            try:
                await page.wait_for_function(
                    """() => {
                        const btns = [...document.querySelectorAll('button[type="submit"]')];
                        const btn = btns.find(b => b.offsetParent !== null);
                        return btn && !btn.disabled;
                    }""",
                    timeout=10000,
                )
                submit_btn = page.locator('button[type="submit"]:visible').first
                await submit_btn.click()
                logger.info("OKX TR: clicked Devam Et")
            except Exception as e:
                logger.warning(f"OKX TR: Devam Et button issue: {e}, trying Enter")
                await email_input.press("Enter")
            await page.wait_for_timeout(2000)

            # Step 1b: Dismiss passkey/WebAuthn popup if it appears
            # OKX may prompt a browser passkey dialog — click Cancel/İptal to dismiss
            try:
                passkey_cancel = page.locator(
                    'button:has-text("İptal"), '
                    'button:has-text("Cancel"), '
                    'button:has-text("Değil"), '
                    'button:has-text("Not now"), '
                    '[data-testid="cancel"], '
                    'button.okui-dialog-cancel'
                ).first
                await passkey_cancel.click(timeout=3000)
                logger.info("OKX TR: dismissed passkey popup")
                await page.wait_for_timeout(1000)
            except Exception:
                pass  # No passkey popup

            # Step 1c: Click "Şifre ile Giriş Yap" (Login with Password) link
            # This is a <div role="button"> containing <span>Şifre ile Giriş Yap</span>
            try:
                password_login_link = page.locator(
                    'span.login-hyperlink-text:has-text("Şifre ile Giriş"), '
                    '[role="button"]:has-text("Şifre ile Giriş"), '
                    'span:has-text("Login with Password")'
                ).first
                await password_login_link.wait_for(state="visible", timeout=10000)
                await password_login_link.click()
                logger.info("OKX TR: clicked 'Login with Password' link")
                await page.wait_for_timeout(2000)
            except Exception as e:
                logger.warning(f"OKX TR: no password login link found: {e}")
                # Might already be on password page, continue

            # Step 1d: Dismiss passkey popup again (may appear after password link click)
            try:
                passkey_cancel2 = page.locator(
                    'button:has-text("İptal"), '
                    'button:has-text("Cancel"), '
                    'button:has-text("Değil"), '
                    'button:has-text("Not now"), '
                    '[data-testid="cancel"], '
                    'button.okui-dialog-cancel'
                ).first
                await passkey_cancel2.click(timeout=3000)
                logger.info("OKX TR: dismissed passkey popup (after password link)")
                await page.wait_for_timeout(1000)
            except Exception:
                pass  # No passkey popup

            # Step 2: Password — the visible password input
            logger.info("OKX TR: entering password")
            password_input = page.locator(
                'input[type="password"]:visible'
            ).first
            await password_input.wait_for(state="visible", timeout=15000)
            await password_input.click()
            await password_input.fill("")
            await password_input.type(credentials["password"], delay=30)
            await password_input.evaluate("el => { el.dispatchEvent(new Event('input', {bubbles:true})); }")
            await page.wait_for_timeout(500)

            # Click login/submit button ("Giriş Yap" or "Log In")
            # Use JS to find the correct submit button (not the header nav "Giriş Yap")
            try:
                clicked = await page.evaluate("""() => {
                    // 1. Try button[type="submit"] that's near the password form
                    const submits = document.querySelectorAll('button[type="submit"]');
                    for (const btn of submits) {
                        if (btn.offsetParent !== null && btn.offsetWidth > 200) {
                            btn.click();
                            return 'submit-type';
                        }
                    }
                    // 2. Try large "Giriş Yap" button (not the small header one)
                    const allBtns = document.querySelectorAll('button');
                    for (const btn of allBtns) {
                        if (btn.textContent.trim() === 'Giriş Yap' && btn.offsetWidth > 200) {
                            btn.click();
                            return 'giris-yap';
                        }
                    }
                    // 3. Try any visible submit button
                    for (const btn of submits) {
                        if (btn.offsetParent !== null) {
                            btn.click();
                            return 'any-submit';
                        }
                    }
                    return null;
                }""")
                if clicked:
                    logger.info(f"OKX TR: clicked login submit button via JS ({clicked})")
                else:
                    logger.warning("OKX TR: no submit button found via JS, trying Enter key")
                    await password_input.press("Enter")
            except Exception as e:
                logger.warning(f"OKX TR: login submit issue: {e}, trying Enter")
                await password_input.press("Enter")
            await page.wait_for_timeout(3000)

            # Retry submit if still on login form (reCAPTCHA may need time to load)
            try:
                pw_still = page.locator('input[type="password"]:visible').first
                if await pw_still.is_visible():
                    logger.info("OKX TR: still on password form, retrying submit after 3s...")
                    await page.wait_for_timeout(3000)
                    await page.evaluate("""() => {
                        const btn = document.querySelector('button[type="submit"]');
                        if (btn && btn.offsetParent !== null) btn.click();
                    }""")
                    await page.wait_for_timeout(5000)
            except Exception:
                pass

            # Step 2b: Check what happened after clicking submit
            # Could be: TOTP, reCAPTCHA, device verification, or still on login form
            session.status = "waiting_for_captcha"

            # Check for TOTP pin inputs FIRST (page stays on /login URL during TOTP)
            # Wait up to 10s for TOTP inputs to appear — they show after form submit
            totp_secret = credentials.get("totp_secret")
            totp_entered = False
            if totp_secret:
                try:
                    pin_input = page.locator(
                        'input[autocomplete="one-time-code"]:visible, '
                        'input[class*="pin-inner-input"]:visible'
                    ).first
                    await pin_input.wait_for(state="visible", timeout=10000)
                    if await pin_input.is_visible():
                        logger.info("OKX TR: TOTP pin inputs detected after submit")
                        code = generate_totp_code(totp_secret)
                        logger.info(f"OKX TR: entering TOTP code {code[:2]}****")
                        await pin_input.click()
                        await page.wait_for_timeout(300)
                        for digit in code:
                            await page.keyboard.press(digit)
                            await page.wait_for_timeout(100)
                        logger.info("OKX TR: TOTP code entered")
                        totp_entered = True
                        await page.wait_for_timeout(3000)
                except Exception:
                    pass  # Not on TOTP page yet

            if not totp_entered:
                # Check for visible reCAPTCHA
                captcha_detected = await self._check_captcha_visible(page)

                # Check for "Verify with trusted device" screen
                device_detected = False
                device_texts = [
                    "Verify with a trusted device",
                    "Güvenilir bir cihazla onayla",
                    "trusted device",
                    "güvenilir bir cihaz",
                ]
                for dt in device_texts:
                    try:
                        loc = page.get_by_text(dt, exact=False).first
                        if await loc.is_visible():
                            device_detected = True
                            logger.info(f"OKX TR: detected '{dt}' on page")
                            break
                    except Exception:
                        pass

                # Check if still on login page (form didn't progress)
                still_on_login = "/login" in page.url

                if device_detected:
                    logger.info("OKX TR: 'Verify with trusted device' screen — clicking Continue")
                    try:
                        continue_btn = page.locator(
                            'button:has-text("Continue"), '
                            'button:has-text("Devam"), '
                            'button:has-text("Devam Et"), '
                            'button[type="submit"]:visible'
                        ).first
                        await continue_btn.click(timeout=5000)
                        logger.info("OKX TR: clicked Continue on device verification")
                        await page.wait_for_timeout(3000)
                    except Exception as e:
                        logger.warning(f"OKX TR: could not click Continue button: {e}")

                    logger.info("OKX TR: waiting for device verification (up to 120s)")
                    solved = await session.wait_for_captcha_solved(timeout=120)
                    if not solved:
                        current_url = page.url
                        token = session.get_auth_token()
                        if "/login" not in current_url or token:
                            logger.info("OKX TR: device verification appears completed")
                        else:
                            logger.warning("OKX TR: device verification timed out")
                    await page.wait_for_timeout(2000)

                elif captcha_detected:
                    logger.info("OKX TR: reCAPTCHA detected — waiting for human to solve via frontend")
                    solved = await session.wait_for_captcha_solved(timeout=300)
                    if not solved:
                        current_url = page.url
                        token = session.get_auth_token()
                        if token and ("/login" not in current_url):
                            logger.info("OKX TR: captcha timeout but already logged in with token")
                        elif token:
                            if await self.check_session(session):
                                session.set_logged_in(session.captured_tokens)
                                await browser_manager.save_storage_state(self.exchange_name)
                                return {"success": True, "message": "Login successful (detected after captcha)"}
                        else:
                            session.set_error("Captcha not solved in time")
                            return {"success": False, "message": "Captcha not solved — open the frontend captcha modal"}
                    await page.wait_for_timeout(5000)
                    logger.info(f"OKX TR: post-captcha URL: {page.url}")

                elif still_on_login:
                    # Form didn't progress — show browser to user and wait
                    logger.info("OKX TR: still on login page after submit — showing browser view to user (up to 120s)")
                    solved = await session.wait_for_captcha_solved(timeout=120)
                    if not solved:
                        current_url = page.url
                        token = session.get_auth_token()
                        if token and "/login" not in current_url:
                            logger.info("OKX TR: login completed while waiting")
                        elif "/login" in current_url:
                            session.set_error("Login stuck — check the browser view in frontend")
                            return {"success": False, "message": session.last_error}
                    await page.wait_for_timeout(2000)

                    # After user interaction, check if TOTP appeared
                    if totp_secret and not totp_entered:
                        try:
                            pin_check = page.locator(
                                'input[autocomplete="one-time-code"]:visible, '
                                'input[class*="pin-inner-input"]:visible'
                            ).first
                            if await pin_check.is_visible():
                                logger.info("OKX TR: TOTP appeared after user interaction")
                                code = generate_totp_code(totp_secret)
                                logger.info(f"OKX TR: entering TOTP code {code[:2]}****")
                                await pin_check.click()
                                await page.wait_for_timeout(300)
                                for digit in code:
                                    await page.keyboard.press(digit)
                                    await page.wait_for_timeout(100)
                                logger.info("OKX TR: TOTP code entered after interaction")
                                totp_entered = True
                                await page.wait_for_timeout(3000)
                        except Exception:
                            pass

            # Step 3: TOTP (if not already entered above)
            session.status = "logging_in"
            if totp_secret and not totp_entered:
                logger.info("OKX TR: waiting for TOTP prompt")
                try:
                    # OKX TR uses 6 separate pin inputs with class "index_pin-inner-input"
                    # or autocomplete="one-time-code". Also check for single input fallback.
                    pin_input = page.locator(
                        'input[autocomplete="one-time-code"]:visible, '
                        'input[class*="pin-inner-input"]:visible, '
                        'input[placeholder*="code"]:visible, '
                        'input[placeholder*="authenticator"]:visible, '
                        'input[placeholder*="doğrulama"]:visible, '
                        'input[type="tel"]:visible, '
                        'input[maxlength="6"]:visible'
                    ).first
                    await pin_input.wait_for(state="visible", timeout=20000)

                    code = generate_totp_code(totp_secret)
                    logger.info(f"OKX TR: entering TOTP code {code[:2]}****")

                    # Click the first pin input to focus it
                    await pin_input.click()
                    await page.wait_for_timeout(300)

                    # Type each digit — OKX auto-advances between pin inputs
                    for digit in code:
                        await page.keyboard.press(digit)
                        await page.wait_for_timeout(100)

                    logger.info("OKX TR: TOTP code entered")
                    await page.wait_for_timeout(2000)

                    # OKX usually auto-submits after 6 digits; try clicking confirm anyway
                    try:
                        confirm_btn = page.locator(
                            'button:has-text("Confirm"), '
                            'button:has-text("Onayla"), '
                            'button:has-text("Verify"), '
                            'button:has-text("Doğrula"), '
                            'button[type="submit"]'
                        ).first
                        await confirm_btn.click(timeout=3000)
                    except Exception:
                        pass  # auto-submitted

                except Exception as e:
                    logger.warning(f"OKX TR: TOTP step skipped or not required: {e}")

            # Step 4: Wait for redirect away from login
            logger.info("OKX TR: waiting for login redirect...")
            try:
                await page.wait_for_url(
                    lambda url: "/login" not in url and "/account/login" not in url,
                    timeout=30000,
                )
            except Exception:
                # Check if we're already logged in despite URL
                current_url = page.url
                logger.warning(f"OKX TR: URL after wait: {current_url}")
                if "/login" in current_url:
                    session.set_error("Login redirect timed out — may need captcha or SMS verification")
                    return {"success": False, "message": session.last_error}

            # Wait a moment for API calls to fire (token capture)
            await page.wait_for_timeout(3000)

            # Verify we captured a token
            token = session.get_auth_token()
            if token:
                session.set_logged_in(session.captured_tokens)
                await browser_manager.save_storage_state(self.exchange_name)
                logger.info(f"OKX TR: login successful, auth token captured ({len(token)} chars)")
                return {"success": True, "message": "Login successful, token captured"}
            else:
                # Navigate to a page that triggers API calls
                logger.info("OKX TR: no token captured yet, navigating to assets page")
                try:
                    await page.goto("https://tr.okx.com/asset", wait_until="domcontentloaded", timeout=15000)
                    await page.wait_for_timeout(3000)
                except Exception:
                    pass

                token = session.get_auth_token()
                if token:
                    session.set_logged_in(session.captured_tokens)
                    await browser_manager.save_storage_state(self.exchange_name)
                    logger.info(f"OKX TR: token captured after assets page ({len(token)} chars)")
                    return {"success": True, "message": "Login successful, token captured"}
                else:
                    session.set_logged_in()
                    await browser_manager.save_storage_state(self.exchange_name)
                    logger.warning("OKX TR: logged in but no auth token captured yet")
                    return {"success": True, "message": "Login successful but no API token captured yet"}

        except Exception as e:
            error_msg = f"Login failed: {str(e)}"
            logger.error(f"OKX TR: {error_msg}")
            try:
                await page.close()
            except Exception:
                pass
            session._page = None
            session.set_error(error_msg)
            return {"success": False, "message": error_msg}

    # ── captcha detection ────────────────────────────────────

    async def _check_captcha_visible(self, page: Page) -> bool:
        """Check if a reCAPTCHA / security verification popup is visible."""
        search_texts = [
            "Güvenlik Doğrulaması",
            "Security Verification",
            "Ben robot değilim",
            "I'm not a robot",
        ]
        for text in search_texts:
            try:
                loc = page.get_by_text(text, exact=False)
                if await loc.first.is_visible():
                    logger.info(f"OKX TR: captcha detected via text '{text}'")
                    return True
            except Exception:
                pass

        # Also check for reCAPTCHA iframe
        try:
            iframe = page.locator('iframe[src*="recaptcha"], iframe[title*="reCAPTCHA"]').first
            if await iframe.is_visible():
                logger.info("OKX TR: captcha detected via reCAPTCHA iframe")
                return True
        except Exception:
            pass

        logger.debug("OKX TR: no captcha detected")
        return False

    # ── request interceptor ────────────────────────────────────

    def _setup_request_interceptor(self, page: Page, session: ExchangeSession) -> None:
        """Capture authorization headers and full browser headers from OKX TR API requests."""

        def on_request(request: Request) -> None:
            url = request.url
            if "tr.okx.com" not in url:
                return
            auth = request.headers.get("authorization")
            if auth and auth != session.captured_tokens.get("authorization"):
                session.captured_tokens["authorization"] = auth
                logger.debug(f"OKX TR: captured fresh auth token ({len(auth)} chars)")

            # Capture full headers from POST requests for replay in travel rule etc.
            if request.method == "POST" and auth:
                hdrs = dict(request.headers)
                # Remove per-request headers that shouldn't be replayed
                for skip in ("content-length", "content-type", ":method", ":authority", ":scheme", ":path"):
                    hdrs.pop(skip, None)
                session.captured_tokens["_browser_headers"] = hdrs

            # Log onboarding/travel-rule related requests for debugging
            if "notabene" in url or "travel-rule" in url or "onboarding" in url:
                logger.info(f"OKX TR INTERCEPT: {request.method} {url}")
                logger.info(f"OKX TR INTERCEPT headers: {dict(request.headers)}")

        page.on("request", on_request)

    # ── session check ──────────────────────────────────────────

    async def check_session(self, session: ExchangeSession) -> bool:
        """Check if session is still valid by calling an authenticated endpoint."""
        token = session.get_auth_token()
        if not token:
            return False

        try:
            async with aiohttp.ClientSession() as http:
                async with http.get(
                    "https://tr.okx.com/priapi/v1/asset/balance?ccy=TRY",
                    headers={"authorization": token},
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        # OKX returns error codes in body even with 200
                        code = data.get("code", data.get("error_code", ""))
                        if str(code) == "0":
                            return True
                    return False
        except Exception as e:
            logger.warning(f"OKX TR session check failed: {e}")
            return False

    # ── keepalive ──────────────────────────────────────────────

    async def keepalive(self, session: ExchangeSession) -> None:
        """Navigate between account tabs to keep the SPA alive."""
        try:
            page = await session.get_page()
            current_url = page.url
            if "/login" in current_url or "about:blank" in current_url:
                return

            if "/account/users" in current_url:
                url = "https://tr.okx.com/account/setting"
                label = "Tercihler"
            else:
                url = "https://tr.okx.com/account/users"
                label = "Genel Bakış"

            await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            logger.info(f"OKX TR: keepalive — switched to {label}")
        except Exception as e:
            logger.debug(f"OKX TR: keepalive error: {e}")

    # ── TRY withdrawal ─────────────────────────────────────────

    async def withdraw_try(
        self,
        session: ExchangeSession,
        amount: float,
        iban: str,
        payment_account_id: str,
    ) -> dict:
        """
        Execute TRY withdrawal via the OKX TR API using captured auth token.
        Same endpoint as main app's fiat_withdrawals.py withdraw_okx_tr().
        """
        token = session.get_auth_token()
        if not token:
            return {"success": False, "order_id": None, "message": "No auth token available"}

        timestamp = str(int(time.time() * 1000))

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "authorization": token,
        }

        payload = {
            "version": "6.23",
            "successUrl": "",
            "failUrl": "",
            "requestId": str(uuid.uuid4()),
            "depositName": "TR Withdraw Banks",
            "depositPlatformCode": "1007",
            "paymentAccountId": payment_account_id,
            "paymentMethodType": "TR_HAVALE",
            "requestAmount": str(int(amount)),
            "requestCurrency": "TRY",
            "splitEnabled": False,
            "tradeType": "withdraw",
        }

        try:
            async with aiohttp.ClientSession() as http:
                async with http.post(
                    f"{WITHDRAW_URL}?t={timestamp}",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    data = await resp.json()
                    logger.info(f"OKX TR withdraw response (amount={amount}): {json.dumps(data)}")

                    error_code = data.get("error_code", data.get("code", ""))
                    if str(error_code) == "0":
                        order_no = data.get("data", {}).get("orderNo", "N/A")
                        return {
                            "success": True,
                            "order_id": order_no,
                            "message": "Withdrawal submitted",
                        }
                    else:
                        error_msg = data.get("error_message", data.get("msg", str(data)))
                        return {
                            "success": False,
                            "order_id": None,
                            "message": f"OKX error: {error_msg}",
                        }

        except Exception as e:
            error_msg = f"Withdrawal request failed: {str(e)}"
            logger.error(f"OKX TR: {error_msg}")
            return {"success": False, "order_id": None, "message": error_msg}

    # ── travel rule ──────────────────────────────────────────

    # Exchange info codes for travel rule form (source exchange → OKX code)
    TRAVEL_RULE_EXCHANGE_CODES = {
        "binance_tr": "118",
        "binance_global": "33",
        "paribu": "103",
        "btcturk": "102",
        "cointr": "306",
        "whitebit_tr": "342",
        "kucoin_tr": "322",
        "htx": "115",
        "okx_global": "37",
    }

    # Display names as they appear in the OKX TR travel rule dropdown.
    # NOTE: other exchanges' deposit travel rule forms may use different names.
    TRAVEL_RULE_EXCHANGE_NAMES = {
        "binance_tr": "Binance TR",
        "binance_global": "Binance",
        "paribu": "Paribu",
        "btcturk": "BTCTurk",
        "cointr": "CoinTR",
        "whitebit_tr": "Whitebit-Tr",
        "kucoin_tr": "Kucoin TR",
        "htx": "Huobi",
        "okx_global": "OKX",
    }

    async def get_pending_travel_rules(self, session: ExchangeSession) -> dict:
        """
        Fetch frozen assets that need travel rule verification from OKX TR API.
        Uses /v2/asset/accounts/frozen-assets-summary which returns frozenDeposits
        with travelRuleId for each deposit needing verification.
        NOTE: Only uses stored token, never touches the browser page.
        """
        token = session.get_auth_token()
        if not token:
            return {"success": False, "pending": [], "message": "No auth token"}

        try:
            ts = str(int(time.time() * 1000))
            async with aiohttp.ClientSession() as http:
                async with http.get(
                    f"https://tr.okx.com/v2/asset/accounts/frozen-assets-summary"
                    f"?valuationUnit=TRY&cedefiLimit=false&t={ts}",
                    headers={"authorization": token},
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    data = await resp.json()

            if str(data.get("code", "")) != "0":
                msg = data.get("msg", data.get("error_message", str(data)))
                return {"success": False, "pending": [], "message": f"API error: {msg}"}

            frozen_deposits = data.get("data", {}).get("frozenDeposits", [])
            pending = []
            for item in frozen_deposits:
                # Only include items that have a travelRuleId (need verification)
                travel_rule_id = item.get("travelRuleId")
                if not travel_rule_id:
                    continue
                pending.append({
                    "travel_rule_id": str(travel_rule_id),
                    "deposit_id": str(item.get("id", "")),
                    "currency": item.get("currencySymbol", ""),
                    "amount": item.get("amount", ""),
                    "travel_rule_status": item.get("travelRuleStatus", ""),
                    "internal_transfer": item.get("internalTransfer", False),
                })

            logger.info(f"OKX TR: found {len(pending)} pending travel rule items")
            return {"success": True, "pending": pending}

        except Exception as e:
            logger.error(f"OKX TR: failed to fetch travel rules: {e}")
            return {"success": False, "pending": [], "message": str(e)}

    async def confirm_travel_rule(
        self,
        session: ExchangeSession,
        travel_rule_id: str,
        source_exchange: str,
    ) -> dict:
        """
        Complete the travel rule verification form for a frozen deposit
        by clicking through the actual UI form in the browser.

        OKX TR blocks direct API POST requests to the notabene/onboarding
        endpoint (error 805 / token verification failed), even from within
        the browser via fetch(). The only reliable approach is to interact
        with the SPA form via UI clicks, which uses OKX TR's own React
        state management and request mechanisms.

        Steps:
        1. Navigate to frozen-assets page
        2. Click "Ayrıntılara Göz At" (View Details)
        3. Select "Borsa veya Platform" → click "İleri"
        4. Open exchange dropdown, search & select source → click "İleri"
        5. Select "Evet, kendi hesabımdan gönderiyorum" → click "İleri"
        6. Open purpose dropdown, select purpose → click "İleri"
        """
        exchange_display = self.TRAVEL_RULE_EXCHANGE_NAMES.get(source_exchange)
        if not exchange_display:
            return {
                "success": False,
                "message": f"Unknown source exchange: {source_exchange}. "
                           f"Supported: {list(self.TRAVEL_RULE_EXCHANGE_NAMES.keys())}",
            }

        try:
            page = await session.get_page()
            current_url = page.url
            if "/login" in current_url or "about:blank" in current_url:
                return {"success": False, "message": "Browser not logged in (on login page)"}
        except Exception as e:
            return {"success": False, "message": f"Failed to get page: {e}"}

        logger.info(f"OKX TR: starting UI-based travel rule confirm for {travel_rule_id} "
                     f"(source={source_exchange}, display={exchange_display})")

        try:
            # Step 1: Navigate to frozen-assets page
            logger.info("OKX TR travel rule step 1: navigating to frozen-assets")
            await page.goto(
                "https://tr.okx.com/balance/frozen-assets",
                wait_until="domcontentloaded",
                timeout=15000,
            )
            await page.wait_for_timeout(2000)

            # Step 2: Click "Ayrıntılara Göz At" (View Details)
            logger.info("OKX TR travel rule step 2: clicking View Details")
            details_link = page.get_by_text("Ayrıntılara Göz At", exact=False).first
            await details_link.click(timeout=5000)
            await page.wait_for_timeout(2000)

            # Step 3: Select "Borsa veya Platform" (Exchange or Platform) → Next
            logger.info("OKX TR travel rule step 3: selecting Exchange/Platform")
            await page.get_by_text("Borsa veya Platform", exact=False).first.click(timeout=5000)
            await page.wait_for_timeout(500)
            await page.get_by_text("İleri", exact=True).first.click(timeout=5000)
            await page.wait_for_timeout(2000)

            # Step 4: Select source exchange from dropdown → Next
            logger.info(f"OKX TR travel rule step 4: selecting exchange '{exchange_display}'")
            await page.click("[role=combobox]", timeout=5000)
            await page.wait_for_timeout(500)
            await page.fill('input[placeholder="Ara"]', exchange_display, timeout=5000)
            await page.wait_for_timeout(1000)
            # Click the exact match in the dropdown list
            await page.get_by_text(exchange_display, exact=True).first.click(timeout=5000)
            await page.wait_for_timeout(500)
            await page.get_by_text("İleri", exact=True).first.click(timeout=5000)
            await page.wait_for_timeout(2000)

            # Step 5: Confirm own account → Next
            logger.info("OKX TR travel rule step 5: confirming own account")
            await page.get_by_text("kendi hesabımdan", exact=False).first.click(timeout=5000)
            await page.wait_for_timeout(500)
            await page.get_by_text("İleri", exact=True).first.click(timeout=5000)
            await page.wait_for_timeout(2000)

            # Step 6: Select purpose → Next
            logger.info("OKX TR travel rule step 6: selecting purpose")
            await page.click("[role=combobox]", timeout=5000)
            await page.wait_for_timeout(500)
            await page.get_by_text("borsa platformu", exact=False).first.click(timeout=5000)
            await page.wait_for_timeout(500)
            await page.get_by_text("İleri", exact=True).first.click(timeout=5000)
            await page.wait_for_timeout(3000)

            # Check result: if we got redirected away from frozen-assets, it worked
            final_url = page.url
            logger.info(f"OKX TR travel rule: final URL = {final_url}")

            if "frozen-assets" not in final_url:
                logger.info(f"OKX TR: travel rule COMPLETED for {travel_rule_id} "
                           f"(source={source_exchange}, redirected to {final_url})")
                return {
                    "success": True,
                    "message": f"Travel rule verified: {source_exchange} → OKX TR",
                    "travel_rule_id": travel_rule_id,
                }
            else:
                # Still on frozen-assets — might have failed
                screenshot = await page.screenshot(full_page=False)
                logger.warning(f"OKX TR: travel rule may have failed — still on frozen-assets page")
                return {
                    "success": False,
                    "message": "Travel rule form did not complete — still on frozen assets page",
                }

        except Exception as e:
            error_msg = f"Travel rule UI automation failed: {e}"
            logger.error(f"OKX TR: {error_msg}")
            # Take screenshot for debugging
            try:
                screenshot = await page.screenshot(full_page=False)
                logger.info(f"OKX TR: saved debug screenshot after travel rule failure")
            except Exception:
                pass
            return {"success": False, "message": error_msg}

    async def confirm_deposit(
        self,
        session: ExchangeSession,
        platform_name: str,
        amount: Optional[float] = None,
    ) -> dict:
        """Confirm deposit via travel rule. platform_name is the source exchange."""
        # First get pending travel rules to find the right one
        pending = await self.get_pending_travel_rules(session)
        if not pending["success"] or not pending["pending"]:
            return {
                "success": False,
                "message": pending.get("message", "No pending travel rules found"),
            }

        # If amount is provided, try to match by amount
        target = None
        for item in pending["pending"]:
            if amount:
                try:
                    item_amount = float(item.get("amount", 0))
                    if abs(item_amount - amount) / max(amount, 1) < 0.01:
                        target = item
                        break
                except (ValueError, TypeError):
                    pass
            else:
                # No amount filter — take first pending
                target = item
                break

        if not target:
            # Fallback: take first pending item
            target = pending["pending"][0]

        return await self.confirm_travel_rule(
            session,
            travel_rule_id=target["travel_rule_id"],
            source_exchange=platform_name,
        )

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
