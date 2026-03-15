"""
Binance TR browser automation — login, token capture, TRY withdrawal.
"""
import asyncio
import json
import os
import logging
from typing import Dict, Any, Optional

import aiohttp
from playwright.async_api import Page, Request

from src.exchanges.base import BaseExchangeAutomation
from src.browser.session import ExchangeSession
from src.browser.manager import browser_manager
from src.security.totp import generate_totp_code

logger = logging.getLogger(__name__)

LOGIN_URL = "https://www.binance.tr/account/signin"
WITHDRAW_URL = "https://www.binance.tr/v1/fiat/withdraws"
USER_INFO_URL = "https://www.binance.tr/v1/private/account/user/base-detail"

DEBUG_DIR = "/app/data/debug"


class BinanceTRAutomation(BaseExchangeAutomation):
    exchange_name = "binance_tr"
    confirm_deposit_needs_browser = True

    TRAVEL_RULE_URL = "https://www.binance.tr/en/usercenter/travel-rule/transfer-declaration-list"

    TRAVEL_RULE_EXCHANGE_NAMES = {
        "binance_global": "Binance",
        "paribu": "Paribu",
        "btcturk": "BTCTurk",
        "cointr": "CoinTR",
        "okx_tr": "OKX",
        "whitebit_tr": "WhiteBIT",
        "kucoin_tr": "KuCoin",
        "htx": "HTX",
    }

    # ── debug helper ──────────────────────────────────────────

    async def _debug_screenshot(self, page: Page, label: str) -> None:
        """Save a debug screenshot with label."""
        try:
            os.makedirs(DEBUG_DIR, exist_ok=True)
            path = os.path.join(DEBUG_DIR, f"binance_tr_{label}.png")
            await page.screenshot(path=path, full_page=False)
            logger.info(f"BinanceTR: [DEBUG] screenshot saved: {label}.png (url={page.url})")
        except Exception as e:
            logger.warning(f"BinanceTR: [DEBUG] screenshot failed for {label}: {e}")

    # ── login ──────────────────────────────────────────────────

    async def login(self, session: ExchangeSession, credentials: Dict[str, str]) -> dict:
        """
        Binance TR login flow:
        1. Navigate to login page
        2. Fill email + password, click 'Giriş Yap'
        3. Handle slider captcha if present
        4. Handle possible extra security verification (email+SMS for first IP login)
        5. Enter TOTP code (Google Authenticator)
        6. Wait for redirect, capture cid cookie, save storage state
        """
        session.status = "logging_in"
        page = await session.get_page()

        try:
            # Set up interceptors
            self._setup_request_interceptor(page, session)

            # Check if already logged in
            try:
                current_url = page.url
                token = session.get_auth_token()
                if token and "/signin" not in current_url and "about:blank" not in current_url:
                    logger.info(f"BinanceTR: browser already on {current_url} with token — verifying session")
                    if await self.check_session(session):
                        session.set_logged_in(session.captured_tokens)
                        logger.info("BinanceTR: already logged in — skipping login flow")
                        return {"success": True, "message": "Already logged in"}
                    else:
                        logger.info("BinanceTR: token expired, proceeding with fresh login")
            except Exception:
                pass

            # ── Navigate to login page ──
            logger.info("BinanceTR: navigating to login page")
            await page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_timeout(4000)
            await self._debug_screenshot(page, "01_page_loaded")

            # ── Dismiss cookie consent ──
            await self._dismiss_cookie_consent(page)
            await self._debug_screenshot(page, "02_after_cookie")

            # Check if cookies caused auto-redirect (already logged in)
            current_url = page.url
            if "/signin" not in current_url and "/login" not in current_url:
                logger.info(f"BinanceTR: cookies auto-logged in — redirected to {current_url}")
                await page.wait_for_timeout(3000)
                await self._capture_cid_cookie(page, session)
                token = session.get_auth_token()
                if token:
                    session.set_logged_in(session.captured_tokens)
                    await browser_manager.save_storage_state(self.exchange_name)
                    return {"success": True, "message": "Auto-login via saved cookies, token captured"}
                session.set_logged_in()
                await browser_manager.save_storage_state(self.exchange_name)
                return {"success": True, "message": "Auto-login via cookies but no cid token captured yet"}

            # ── Step 1: Fill email ──
            email = credentials["email"]
            logger.info(f"BinanceTR: entering email {email[:3]}***")

            # Binance TR uses Vue.js with dynamic inputs - try multiple selectors
            email_input = page.locator(
                'input[name="email"], '
                'input[type="text"][autocomplete="username"], '
                'div.input-model input[type="text"], '
                'input[placeholder*="E-posta" i], '
                'input[placeholder*="email" i]'
            ).first
            await email_input.wait_for(state="visible", timeout=10000)
            await email_input.click(force=True)
            await email_input.fill(email)
            await page.wait_for_timeout(500)
            await self._debug_screenshot(page, "03_email_entered")

            # ── Step 2: Fill password ──
            logger.info("BinanceTR: entering password")
            password_input = page.locator(
                'input[type="password"], '
                'input[name="password"]'
            ).first
            await password_input.wait_for(state="visible", timeout=5000)
            await password_input.click(force=True)
            await password_input.fill(credentials["password"])
            await page.wait_for_timeout(500)
            await self._debug_screenshot(page, "04_password_entered")

            # ── Step 3: Click submit ──
            submit_btn = page.locator(
                'button:has-text("Giriş Yap"), '
                'button:has-text("Giriş yap"), '
                'button.sensors-login, '
                'button[type="submit"]'
            ).first
            await submit_btn.click(force=True, timeout=5000)
            logger.info("BinanceTR: clicked 'Giriş Yap'")
            await page.wait_for_timeout(4000)
            await self._debug_screenshot(page, "05_after_submit")

            # ── Step 4: Handle captcha if present (loop for multiple rounds) ──
            for captcha_round in range(3):
                captcha_detected = await self._check_captcha_visible(page)
                if not captcha_detected:
                    break
                await self._debug_screenshot(page, f"06_captcha_detected_round{captcha_round + 1}")
                logger.info(f"BinanceTR: captcha detected (round {captcha_round + 1}) — waiting for human to solve")
                solved = await session.wait_for_captcha_solved(timeout=300)
                if not solved:
                    token = session.get_auth_token()
                    if token:
                        session.set_logged_in(session.captured_tokens)
                        await browser_manager.save_storage_state(self.exchange_name)
                        return {"success": True, "message": "Login successful (detected after captcha)"}
                    session.set_error("Captcha not solved in time")
                    return {"success": False, "message": "Captcha not solved — open the frontend and solve the captcha"}
                await page.wait_for_timeout(5000)
                await self._debug_screenshot(page, f"07_after_captcha_round{captcha_round + 1}")
                # Check if we advanced past login — if so, break out
                if "/signin" not in page.url and "/login" not in page.url:
                    logger.info(f"BinanceTR: advanced past login after captcha round {captcha_round + 1}")
                    break

            # ── Step 5: TOTP (Google Authenticator) — comes right after captcha ──
            totp_secret = credentials.get("totp_secret")
            await page.wait_for_timeout(3000)
            await self._debug_screenshot(page, "08_before_totp")

            if totp_secret:
                logger.info("BinanceTR: waiting for TOTP prompt")

                try:
                    totp_selector = (
                        'input[placeholder*="Google" i], '
                        'input[placeholder*="Authenticator" i], '
                        'input[placeholder*="doğrulama" i], '
                        'input[placeholder*="kod" i], '
                        'input[placeholder*="code" i], '
                        'input[maxlength="6"], '
                        'input[inputmode="numeric"]'
                    )
                    totp_field = page.locator(totp_selector).first
                    await totp_field.wait_for(state="visible", timeout=15000)
                    await self._debug_screenshot(page, "09_totp_found")

                    code = generate_totp_code(totp_secret)
                    logger.info(f"BinanceTR: entering TOTP code {code[:2]}****")

                    maxlen = await totp_field.get_attribute("maxlength")
                    if maxlen and int(maxlen) == 1:
                        await totp_field.click(force=True)
                        for digit in code:
                            await page.keyboard.press(digit)
                            await page.wait_for_timeout(100)
                    else:
                        await totp_field.click(force=True)
                        await totp_field.fill(code)

                    await page.wait_for_timeout(1500)
                    await self._debug_screenshot(page, "10_totp_entered")

                    # Click confirm
                    try:
                        confirm_btn = page.locator(
                            'button:has-text("Onayla"):visible, '
                            'button:has-text("Gönder"):visible, '
                            'button:has-text("Submit"):visible, '
                            'button:has-text("Confirm"):visible, '
                            'button[type="submit"]:visible'
                        ).first
                        await confirm_btn.click(force=True, timeout=3000)
                        logger.info("BinanceTR: clicked TOTP confirm button")
                    except Exception:
                        pass
                    await page.wait_for_timeout(5000)
                    await self._debug_screenshot(page, "11_after_totp")

                except Exception as e:
                    logger.warning(f"BinanceTR: TOTP step issue: {e}")
                    await self._debug_screenshot(page, "09_totp_error")
                    if "/signin" not in page.url and "/login" not in page.url:
                        logger.info("BinanceTR: already past login page — TOTP may not be required")
                    elif "/signin" in page.url or "/login" in page.url:
                        # Still on login — likely captcha blocked progress
                        captcha_still = await self._check_captcha_visible(page)
                        if captcha_still:
                            logger.info("BinanceTR: captcha still blocking login after TOTP timeout — waiting again")
                            solved = await session.wait_for_captcha_solved(timeout=300)
                            if solved:
                                await page.wait_for_timeout(5000)
                                # Retry TOTP after captcha resolved
                                try:
                                    totp_field2 = page.locator(totp_selector).first
                                    await totp_field2.wait_for(state="visible", timeout=15000)
                                    code2 = generate_totp_code(totp_secret)
                                    logger.info(f"BinanceTR: entering TOTP code (retry) {code2[:2]}****")
                                    maxlen2 = await totp_field2.get_attribute("maxlength")
                                    if maxlen2 and int(maxlen2) == 1:
                                        await totp_field2.click(force=True)
                                        for digit in code2:
                                            await page.keyboard.press(digit)
                                            await page.wait_for_timeout(100)
                                    else:
                                        await totp_field2.click(force=True)
                                        await totp_field2.fill(code2)
                                    await page.wait_for_timeout(1500)
                                    try:
                                        confirm_btn2 = page.locator(
                                            'button:has-text("Onayla"):visible, '
                                            'button:has-text("Gönder"):visible, '
                                            'button:has-text("Submit"):visible, '
                                            'button:has-text("Confirm"):visible, '
                                            'button[type="submit"]:visible'
                                        ).first
                                        await confirm_btn2.click(force=True, timeout=3000)
                                        logger.info("BinanceTR: clicked TOTP confirm button (retry)")
                                    except Exception:
                                        pass
                                    await page.wait_for_timeout(5000)
                                    await self._debug_screenshot(page, "11_after_totp_retry")
                                except Exception as e2:
                                    logger.warning(f"BinanceTR: TOTP retry also failed: {e2}")

            # ── Step 6: Check for new-device verification (email code, possibly SMS) ──
            # URL: /account/confirm-new-device-login
            # Shows "Yeni cihaz girişini onayla" with 6-digit email code input boxes
            # After email code, may ask for SMS code on same or next screen
            await page.wait_for_timeout(2000)
            await self._debug_screenshot(page, "12_after_totp_settle")

            current_url = page.url
            needs_device_confirm = "confirm-new-device" in current_url

            if not needs_device_confirm:
                # Also check page text in case URL hasn't updated yet
                for _attempt in range(3):
                    try:
                        page_text = await page.evaluate("() => document.body.innerText")
                        if "yeni cihaz" in page_text.lower() or "confirm-new-device" in page.url or "e-posta doğrulama kodu" in page_text.lower():
                            needs_device_confirm = True
                            break
                    except Exception:
                        pass
                    await page.wait_for_timeout(2000)

            if needs_device_confirm:
                logger.info("BinanceTR: new device confirmation page detected — waiting for email code from user")
                await self._debug_screenshot(page, "13_device_confirm_page")

                # Wait for user to submit codes via frontend "Enter Codes" button
                got_codes = await session.wait_for_verification_codes(timeout=300)
                if not got_codes:
                    session.set_error("Email verification code not submitted in time")
                    return {"success": False, "message": "Verification timed out — click 'Enter Codes' and submit the email code"}

                email_code = session.verification_codes.get("email_code", "")
                sms_code = session.verification_codes.get("sms_code", "")
                logger.info(f"BinanceTR: received codes: email={email_code[:2]}****")

                # The page uses 6 separate single-digit input boxes for the email code
                # Click the first box and type digit by digit
                try:
                    first_input = page.locator('input[maxlength="1"]').first
                    await first_input.wait_for(state="visible", timeout=5000)
                    await first_input.click(force=True)
                    for digit in email_code.strip():
                        await page.keyboard.press(digit)
                        await page.wait_for_timeout(100)
                    logger.info("BinanceTR: entered email verification code digit by digit")
                except Exception as e:
                    logger.warning(f"BinanceTR: email code digit entry failed: {e}")
                    # Fallback: try a single input field
                    try:
                        single_input = page.locator(
                            'input[placeholder*="E-posta" i], '
                            'input[placeholder*="email" i], '
                            'input[placeholder*="doğrulama" i]'
                        ).first
                        if await single_input.is_visible():
                            await single_input.click(force=True)
                            await single_input.fill(email_code.strip())
                            logger.info("BinanceTR: filled email code in single input field")
                    except Exception as e2:
                        logger.warning(f"BinanceTR: fallback email input failed: {e2}")

                await page.wait_for_timeout(1000)
                await self._debug_screenshot(page, "14_email_code_entered")

                # Click Gönder / Submit if present
                try:
                    submit_btn = page.locator(
                        'button:has-text("Gönder"), '
                        'button:has-text("Onayla"), '
                        'button:has-text("Submit"), '
                        'button[type="submit"]'
                    ).first
                    await submit_btn.click(force=True, timeout=5000)
                    logger.info("BinanceTR: clicked submit on email verification")
                except Exception as e:
                    logger.warning(f"BinanceTR: submit click failed (may auto-submit): {e}")

                await page.wait_for_timeout(5000)
                await self._debug_screenshot(page, "15_after_email_code")

                # Check if SMS verification is now required
                current_url = page.url
                try:
                    page_text = await page.evaluate("() => document.body.innerText")
                    needs_sms = (
                        "telefon" in page_text.lower() or
                        "sms" in page_text.lower() or
                        "phone" in page_text.lower()
                    ) and (
                        "confirm-new-device" in current_url or
                        "/account/" in current_url
                    )
                except Exception:
                    needs_sms = False

                if needs_sms and sms_code:
                    logger.info("BinanceTR: SMS verification also needed, entering SMS code")
                    try:
                        sms_input = page.locator('input[maxlength="1"]').first
                        await sms_input.wait_for(state="visible", timeout=5000)
                        await sms_input.click(force=True)
                        for digit in sms_code.strip():
                            await page.keyboard.press(digit)
                            await page.wait_for_timeout(100)
                        logger.info("BinanceTR: entered SMS code digit by digit")
                    except Exception as e:
                        logger.warning(f"BinanceTR: SMS code entry failed: {e}")

                    await page.wait_for_timeout(1000)

                    try:
                        submit_btn = page.locator(
                            'button:has-text("Gönder"), '
                            'button:has-text("Onayla"), '
                            'button:has-text("Submit"), '
                            'button[type="submit"]'
                        ).first
                        await submit_btn.click(force=True, timeout=5000)
                        logger.info("BinanceTR: clicked submit on SMS verification")
                    except Exception:
                        pass

                    await page.wait_for_timeout(5000)
                    await self._debug_screenshot(page, "16_after_sms_code")
                elif needs_sms and not sms_code:
                    # Need SMS but user didn't provide it — wait again
                    logger.info("BinanceTR: SMS code needed but not provided — waiting for user")
                    got_codes2 = await session.wait_for_verification_codes(timeout=300)
                    if got_codes2:
                        sms_code2 = session.verification_codes.get("sms_code", "")
                        if sms_code2:
                            try:
                                sms_input = page.locator('input[maxlength="1"]').first
                                await sms_input.click(force=True)
                                for digit in sms_code2.strip():
                                    await page.keyboard.press(digit)
                                    await page.wait_for_timeout(100)
                            except Exception as e:
                                logger.warning(f"BinanceTR: SMS code entry failed: {e}")

                            try:
                                submit_btn = page.locator(
                                    'button:has-text("Gönder"), '
                                    'button:has-text("Submit"), '
                                    'button[type="submit"]'
                                ).first
                                await submit_btn.click(force=True, timeout=5000)
                            except Exception:
                                pass
                            await page.wait_for_timeout(5000)
                            await self._debug_screenshot(page, "16_after_sms_code")

            # ── Step 7: Wait for redirect to authenticated page ──
            logger.info("BinanceTR: waiting for login redirect...")

            def _is_auth_page(url: str) -> bool:
                """Check if URL is still part of the auth flow."""
                auth_paths = ["/signin", "/login", "/authenticate", "/confirm-new-device"]
                return any(p in url for p in auth_paths)

            try:
                await page.wait_for_url(
                    lambda url: not _is_auth_page(url),
                    timeout=30000,
                )
            except Exception:
                current_url = page.url
                logger.warning(f"BinanceTR: URL after wait: {current_url}")
                await self._debug_screenshot(page, "17_redirect_timeout")
                if _is_auth_page(current_url):
                    session.set_error("Login redirect timed out — still on auth page")
                    return {"success": False, "message": session.last_error}

            await page.wait_for_timeout(3000)
            await self._debug_screenshot(page, "17_after_redirect")

            # ── Step 8: Capture cid cookie ──
            await self._capture_cid_cookie(page, session)

            token = session.get_auth_token()
            if token:
                session.set_logged_in(session.captured_tokens)
                await browser_manager.save_storage_state(self.exchange_name)
                logger.info(f"BinanceTR: login successful, cid cookie captured ({len(token)} chars)")
                await self._debug_screenshot(page, "18_success")
                return {"success": True, "message": "Login successful, token captured"}
            else:
                # Try navigating to a page that triggers cookie setting
                try:
                    await page.goto("https://www.binance.tr/", wait_until="domcontentloaded", timeout=15000)
                    await page.wait_for_timeout(3000)
                except Exception:
                    pass

                await self._capture_cid_cookie(page, session)
                await self._debug_screenshot(page, "19_home_page")
                token = session.get_auth_token()
                if token:
                    session.set_logged_in(session.captured_tokens)
                    await browser_manager.save_storage_state(self.exchange_name)
                    logger.info(f"BinanceTR: cid captured after home page ({len(token)} chars)")
                    return {"success": True, "message": "Login successful, token captured"}
                else:
                    session.set_logged_in()
                    await browser_manager.save_storage_state(self.exchange_name)
                    logger.warning("BinanceTR: logged in but no cid cookie captured yet")
                    return {"success": True, "message": "Login successful but no cid cookie captured yet"}

        except Exception as e:
            error_msg = f"Login failed: {str(e)}"
            logger.error(f"BinanceTR: {error_msg}")
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
        """Dismiss Binance TR cookie consent banner."""
        try:
            btn = page.locator(
                'button:has-text("Kabul Et"), '
                'button:has-text("Accept"), '
                'button:has-text("Tümünü Kabul Et")'
            ).first
            await btn.wait_for(state="visible", timeout=3000)
            await btn.click(force=True, timeout=3000)
            logger.info("BinanceTR: dismissed cookie consent")
            await page.wait_for_timeout(1000)
        except Exception:
            logger.debug("BinanceTR: no cookie consent found")

    # ── captcha detection ────────────────────────────────────

    async def _check_captcha_visible(self, page: Page) -> bool:
        """Check if a captcha is visible (including slider captcha).
        Excludes the TOTP/authenticator page which also contains 'Doğrulama'."""
        # First check if we're on the TOTP/authenticate page — NOT a captcha
        if "/authenticate" in page.url:
            logger.debug("BinanceTR: on /authenticate page — not a captcha")
            return False
        for totp_text in ["Google Authenticator", "Authenticator kodu", "doğrulama kodu girin"]:
            try:
                loc = page.get_by_text(totp_text, exact=False)
                if await loc.first.is_visible():
                    logger.debug(f"BinanceTR: '{totp_text}' visible — this is TOTP page, not captcha")
                    return False
            except Exception:
                pass

        for text in ["robot", "captcha", "Güvenlik", "Security", "puzzle", "Doğrulama", "Bulmacayı", "kaydırın", "slide", "drag"]:
            try:
                loc = page.get_by_text(text, exact=False)
                if await loc.first.is_visible():
                    logger.info(f"BinanceTR: captcha detected via text '{text}'")
                    return True
            except Exception:
                pass
        try:
            iframe = page.locator('iframe[src*="captcha"], iframe[src*="recaptcha"], iframe[src*="geetest"]').first
            if await iframe.is_visible():
                logger.info("BinanceTR: captcha detected via iframe")
                return True
        except Exception:
            pass
        return False

    # ── cid cookie capture ────────────────────────────────────

    async def _capture_cid_cookie(self, page: Page, session: ExchangeSession) -> None:
        """Extract cid cookie from the browser context."""
        try:
            ctx = page.context
            cookies = await ctx.cookies(["https://www.binance.tr"])
            for cookie in cookies:
                if cookie["name"] == "cid":
                    value = cookie["value"]
                    if value and value != session.captured_tokens.get("cid"):
                        session.captured_tokens["cid"] = value
                        logger.info(f"BinanceTR: captured cid cookie ({len(value)} chars)")
                    return
        except Exception as e:
            logger.warning(f"BinanceTR: cid cookie capture failed: {e}")

    # ── request interceptor ────────────────────────────────────

    def _setup_request_interceptor(self, page: Page, session: ExchangeSession) -> None:
        """Watch Binance TR requests and capture cid cookie when it appears."""

        def on_response(response) -> None:
            """Check response cookies for cid updates."""
            if "binance.tr" not in response.url:
                return
            # Response headers may include Set-Cookie with updated cid
            # We rely on _capture_cid_cookie for the actual capture,
            # but log API activity for debugging
            try:
                if response.status == 401 or response.status == 403:
                    logger.warning(f"BinanceTR: got {response.status} from {response.url}")
            except Exception:
                pass

        page.on("response", on_response)

    # ── session check ──────────────────────────────────────────

    async def check_session(self, session: ExchangeSession) -> bool:
        """Check if session is still valid using browser cookies."""
        try:
            page = await session.get_page()
            result = await page.evaluate("""
                async () => {
                    try {
                        const resp = await fetch('https://www.binance.tr/v1/private/account/user/base-detail', {
                            headers: { 'Accept': 'application/json' },
                            credentials: 'include',
                        });
                        const data = await resp.json();
                        return { status: resp.status, code: data.code };
                    } catch (e) {
                        return { status: 0, error: e.message };
                    }
                }
            """)
            if result.get("status") == 200 and result.get("code") == 0:
                return True
            return False
        except Exception as e:
            logger.warning(f"BinanceTR session check failed: {e}")
            return False

    # ── keepalive ──────────────────────────────────────────────

    async def keepalive(self, session: ExchangeSession) -> None:
        """Navigate between tabs to keep the SPA alive."""
        try:
            page = await session.get_page()
            current_url = page.url
            if "/login" in current_url or "about:blank" in current_url:
                return

            if "/markets" in current_url:
                url = "https://www.binance.tr/en/trade/BTC_TRY"
                label = "Trade"
            else:
                url = "https://www.binance.tr/en/markets/overview"
                label = "Markets"

            await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            logger.info(f"BinanceTR: keepalive — switched to {label}")
        except Exception as e:
            logger.debug(f"BinanceTR: keepalive error: {e}")

    # ── TRY withdrawal ─────────────────────────────────────────

    async def withdraw_try(
        self,
        session: ExchangeSession,
        amount: float,
        iban: str,
        payment_account_id: str,
    ) -> dict:
        """
        Execute TRY withdrawal via Binance TR API.
        Uses the browser page's fetch() so all cookies (cid + session cookies) are sent.
        payment_account_id is not used for Binance TR (uses IBAN directly).
        """
        page = await session.get_page()

        payload = {
            "asset": "TRY",
            "bankAccountNo": iban,
            "amount": str(int(amount)),
        }

        try:
            # Use the browser's fetch API to send all cookies automatically
            result = await page.evaluate("""
                async (payload) => {
                    try {
                        const resp = await fetch('https://www.binance.tr/v1/fiat/withdraws', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                            body: JSON.stringify(payload),
                            credentials: 'include',
                        });
                        const data = await resp.json();
                        return { status: resp.status, data: data };
                    } catch (e) {
                        return { status: 0, error: e.message };
                    }
                }
            """, payload)

            if result.get("error"):
                error_msg = f"Browser fetch failed: {result['error']}"
                logger.error(f"BinanceTR: {error_msg}")
                return {"success": False, "order_id": None, "message": error_msg}

            data = result.get("data", {})
            logger.info(f"BinanceTR withdraw response (amount={amount}): {json.dumps(data)}")

            if isinstance(data, dict) and data.get("code") == 0:
                withdraw_id = data.get("data", {}).get("withdrawId", "N/A")
                return {
                    "success": True,
                    "order_id": str(withdraw_id),
                    "message": "Withdrawal submitted",
                }
            else:
                error_msg = data.get("msg", str(data)) if isinstance(data, dict) else str(data)
                return {
                    "success": False,
                    "order_id": None,
                    "message": f"BinanceTR error: {error_msg}",
                }

        except Exception as e:
            error_msg = f"Withdrawal request failed: {str(e)}"
            logger.error(f"BinanceTR: {error_msg}")
            return {"success": False, "order_id": None, "message": error_msg}

    # ── screenshots / debug ────────────────────────────────────

    async def get_screenshot(self, session: ExchangeSession) -> Optional[bytes]:
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
        page = await session.get_page()
        try:
            return await page.content()
        except Exception as e:
            logger.error(f"Get HTML failed: {e}")
            return None

    # ── travel rule / deposit confirmation ─────────────────────

    async def get_pending_travel_rules(self, session: ExchangeSession) -> dict:
        """
        Scrape pending deposits needing travel rule verification from Binance TR
        Transaction Declaration page via browser.

        Page: /en/usercenter/travel-rule/transfer-declaration-list
        Table columns: Date | Coin | Amount | Sender Address | Action (Submit button)
        """
        try:
            page = await session.get_page()
            current_url = page.url
            if "/signin" in current_url or "about:blank" in current_url:
                return {"success": False, "pending": [], "message": "Not logged in"}
        except Exception as e:
            return {"success": False, "pending": [], "message": f"Failed to get page: {e}"}

        try:
            logger.info("BinanceTR: navigating to travel rule declaration list")
            await page.goto(
                self.TRAVEL_RULE_URL,
                wait_until="domcontentloaded",
                timeout=20000,
            )
            await page.wait_for_timeout(3000)
            await self._debug_screenshot(page, "tr_01_declaration_list")

            # Check if page loaded correctly (not "page not found")
            page_text = await page.evaluate("() => document.body.innerText")
            if "could not be found" in page_text.lower():
                logger.warning("BinanceTR: travel rule page not found — may not be logged in")
                return {"success": False, "pending": [], "message": "Travel rule page not found"}

            # Scrape the Transaction Declaration table
            # Table structure: <tr> with <td> cells for Date, Coin, Amount, Sender Address, Action
            rows = await page.evaluate("""() => {
                const results = [];
                const tableRows = document.querySelectorAll('table tbody tr, table tr');
                for (const row of tableRows) {
                    const cells = row.querySelectorAll('td');
                    if (cells.length < 4) continue;  // skip header or malformed rows

                    // Check if this row has a Submit button (pending action)
                    const hasSubmit = row.querySelector('button') !== null ||
                                     row.textContent.toLowerCase().includes('submit');
                    if (!hasSubmit) continue;

                    // Extract: Date | Coin | Amount | Sender Address
                    const date = cells[0] ? cells[0].textContent.trim() : '';
                    const coin = cells[1] ? cells[1].textContent.trim() : '';
                    const amount = cells[2] ? cells[2].textContent.trim() : '';
                    const address = cells[3] ? cells[3].textContent.trim() : '';

                    // Try to extract transactionId from the Submit button link
                    let transactionId = '';
                    const btn = row.querySelector('button, a');
                    if (btn) {
                        const href = btn.getAttribute('href') || '';
                        const match = href.match(/transactionId=(\\d+)/);
                        if (match) transactionId = match[1];
                    }
                    // Also check onclick or data attributes
                    if (!transactionId) {
                        const allLinks = row.querySelectorAll('a[href*="transactionId"]');
                        for (const a of allLinks) {
                            const m = a.href.match(/transactionId=(\\d+)/);
                            if (m) { transactionId = m[1]; break; }
                        }
                    }

                    results.push({
                        date: date,
                        currency: coin,
                        amount: amount.replace(',', '.'),
                        address: address,
                        transactionId: transactionId,
                        rowIndex: results.length
                    });
                }
                return results;
            }""")

            pending = []
            for i, row in enumerate(rows or []):
                tid = row.get("transactionId") or str(i)
                pending.append({
                    "travel_rule_id": tid,
                    "currency": row.get("currency", ""),
                    "amount": row.get("amount", "0"),
                    "status": "pending_declaration",
                    "address": row.get("address", ""),
                })

            logger.info(f"BinanceTR: found {len(pending)} pending travel rule items")
            return {"success": True, "pending": pending}

        except Exception as e:
            logger.error(f"BinanceTR: failed to fetch pending travel rules: {e}")
            try:
                await self._debug_screenshot(page, "tr_99_pending_error")
            except Exception:
                pass
            return {"success": False, "pending": [], "message": str(e)}

    async def confirm_travel_rule(
        self,
        session: ExchangeSession,
        travel_rule_id: str,
        source_exchange: str,
    ) -> dict:
        """
        Complete the travel rule verification for a pending Binance TR deposit.

        Actual flow observed on Binance TR:
        1. Navigate to /en/usercenter/travel-rule/transfer-declaration-list
        2. Click "Submit" button on the matching deposit row
           → Navigates to /en/usercenter/travel-rule/saved-list?transactionId=XXX&transactionType=1
        3. On the saved-list page, click the pre-registered originator card
           (PAİREXTR company card with "Diğer" VASP — already configured)
        4. Verify success / handle result
        """
        try:
            page = await session.get_page()
            current_url = page.url
            if "/signin" in current_url or "about:blank" in current_url:
                return {"success": False, "message": "Browser not logged in (on login page)"}
        except Exception as e:
            return {"success": False, "message": f"Failed to get page: {e}"}

        logger.info(f"BinanceTR: starting travel rule confirm for id={travel_rule_id} "
                     f"(source={source_exchange})")

        try:
            # Step 1: Navigate to the declaration list page
            logger.info("BinanceTR travel rule step 1: navigating to declaration list")
            await page.goto(
                self.TRAVEL_RULE_URL,
                wait_until="domcontentloaded",
                timeout=20000,
            )
            await page.wait_for_timeout(3000)
            await self._debug_screenshot(page, "tr_02_declaration_list")

            # Step 2: Click the Submit button for the matching row
            # If travel_rule_id is a transactionId, we could match by that,
            # but the table rows just have sequential Submit buttons.
            # For now, click the first Submit button (or nth based on row index).
            logger.info("BinanceTR travel rule step 2: clicking Submit button")
            submit_clicked = False

            # Try clicking by row index if travel_rule_id is a small number (row index)
            row_index = 0
            try:
                row_index = int(travel_rule_id)
                # If it looks like a transactionId (large number), treat as first row
                if row_index > 100:
                    row_index = 0
            except (ValueError, TypeError):
                row_index = 0

            # Find all Submit buttons in the table
            submit_buttons = page.locator('table button:has-text("Submit"), table a:has-text("Submit")')
            count = await submit_buttons.count()
            logger.info(f"BinanceTR: found {count} Submit buttons in table")

            if count > row_index:
                await submit_buttons.nth(row_index).click(timeout=5000)
                submit_clicked = True
                logger.info(f"BinanceTR: clicked Submit button at index {row_index}")
            elif count > 0:
                await submit_buttons.first.click(timeout=5000)
                submit_clicked = True
                logger.info("BinanceTR: clicked first Submit button")
            else:
                # Fallback: try any button with Submit text on the page
                try:
                    btn = page.get_by_text("Submit", exact=False).first
                    await btn.click(timeout=5000)
                    submit_clicked = True
                    logger.info("BinanceTR: clicked Submit via text match")
                except Exception:
                    pass

            if not submit_clicked:
                await self._debug_screenshot(page, "tr_02_no_submit_button")
                return {
                    "success": False,
                    "message": "No Submit button found on declaration list page",
                }

            await page.wait_for_timeout(3000)
            await self._debug_screenshot(page, "tr_03_saved_list")

            # Step 3: We should now be on the saved-list page
            # URL: /en/usercenter/travel-rule/saved-list?transactionId=XXX&transactionType=1
            # This page shows a pre-registered originator card.
            # Click the card to select it and submit.
            logger.info("BinanceTR travel rule step 3: selecting saved originator")
            current_url = page.url

            if "saved-list" in current_url:
                # The saved originator card is a clickable div/card element
                # Look for the card containing the company name or "Corporate Entity"
                card_clicked = False

                # Try clicking the card element containing the originator info
                for card_selector in [
                    'div:has-text("Corporate Entity") >> xpath=ancestor::div[contains(@class, "card") or contains(@class, "Card") or contains(@class, "item") or contains(@class, "Item") or contains(@class, "originator") or contains(@class, "saved")]',
                    '[class*="card"]:has-text("Corporate Entity")',
                    '[class*="Card"]:has-text("Corporate Entity")',
                    '[class*="item"]:has-text("Corporate Entity")',
                    '[class*="saved"]:has-text("Corporate Entity")',
                ]:
                    try:
                        card = page.locator(card_selector).first
                        if await card.is_visible(timeout=2000):
                            await card.click(timeout=5000)
                            card_clicked = True
                            logger.info(f"BinanceTR: clicked originator card via '{card_selector}'")
                            break
                    except Exception:
                        continue

                if not card_clicked:
                    # Fallback: click the first substantial clickable div in the content area
                    try:
                        card = page.locator('text=Corporate Entity').first
                        if await card.is_visible(timeout=2000):
                            await card.click(timeout=5000)
                            card_clicked = True
                            logger.info("BinanceTR: clicked on 'Corporate Entity' text")
                    except Exception:
                        pass

                if not card_clicked:
                    # Try clicking "PAİREXTR" or company name
                    try:
                        card = page.locator('text=/PAİREXTR/i').first
                        if await card.is_visible(timeout=2000):
                            await card.click(timeout=5000)
                            card_clicked = True
                            logger.info("BinanceTR: clicked on company name text")
                    except Exception:
                        pass

                await page.wait_for_timeout(3000)
                await self._debug_screenshot(page, "tr_04_declaration_preview")

                # Step 4: We are now on the "Declaration Preview" page
                # URL: /saved-info-preview?transactionId=XXX&transactionType=1
                # Fields (pre-filled from saved originator):
                #   - "I am receiving the funds from:" → Diğer (read-only)
                #   - "Are you receiving the funds from yourself or another beneficiary?" → read-only
                #   - "Description of the transaction (Required)" → textarea, min 20 chars
                # The Submit button is disabled until description is filled.
                logger.info("BinanceTR travel rule step 4: filling description textarea")

                description_text = "başka fiyattan işlem yapmak için yatırdım"
                desc_filled = False

                # Try textarea first (most likely)
                for desc_selector in [
                    'textarea',
                    'textarea[placeholder*="Minimum" i]',
                    'textarea[placeholder*="character" i]',
                    'input[placeholder*="Minimum" i]',
                ]:
                    try:
                        desc_field = page.locator(desc_selector).first
                        if await desc_field.is_visible(timeout=2000):
                            await desc_field.click(force=True)
                            await desc_field.fill(description_text)
                            desc_filled = True
                            logger.info(f"BinanceTR: filled description via '{desc_selector}'")
                            break
                    except Exception:
                        continue

                if not desc_filled:
                    # Fallback: use JS to fill
                    try:
                        await page.evaluate("""(text) => {
                            const ta = document.querySelector('textarea');
                            if (ta) {
                                const nativeSetter = Object.getOwnPropertyDescriptor(
                                    window.HTMLTextAreaElement.prototype, 'value'
                                ).set;
                                nativeSetter.call(ta, text);
                                ta.dispatchEvent(new Event('input', {bubbles: true}));
                                ta.dispatchEvent(new Event('change', {bubbles: true}));
                                return true;
                            }
                            return false;
                        }""", description_text)
                        desc_filled = True
                        logger.info("BinanceTR: filled description via JS evaluate")
                    except Exception as e:
                        logger.warning(f"BinanceTR: JS fill description failed: {e}")

                await page.wait_for_timeout(1000)
                await self._debug_screenshot(page, "tr_05_description_filled")

                if not desc_filled:
                    logger.warning("BinanceTR: could not fill description textarea")
                    return {
                        "success": False,
                        "message": "Could not fill required description field on Declaration Preview",
                    }

                # Step 5: Click the Submit button (should now be enabled)
                logger.info("BinanceTR travel rule step 5: clicking Submit")
                submitted = False
                try:
                    submit_btn = page.locator('button:has-text("Submit")').first
                    await submit_btn.wait_for(state="visible", timeout=5000)
                    await submit_btn.click(timeout=5000)
                    submitted = True
                    logger.info("BinanceTR: clicked Submit on Declaration Preview")
                except Exception:
                    # Fallback: try other button texts
                    for btn_text in ["Gönder", "Onayla", "Confirm"]:
                        try:
                            btn = page.get_by_text(btn_text, exact=False).first
                            if await btn.is_visible(timeout=1000):
                                await btn.click(timeout=5000)
                                submitted = True
                                logger.info(f"BinanceTR: clicked '{btn_text}' button")
                                break
                        except Exception:
                            continue

            elif "new-declaration" in current_url or "declaration-form" in current_url:
                # Ended up on a new declaration form instead of saved-list
                # This shouldn't happen normally, but handle it
                logger.warning("BinanceTR: ended up on new declaration form instead of saved-list")
                await self._debug_screenshot(page, "tr_03_unexpected_form")
                return {
                    "success": False,
                    "message": "Unexpected form page instead of saved originator list",
                }

            await page.wait_for_timeout(3000)
            await self._debug_screenshot(page, "tr_06_after_submit")

            # Step 6: Verify result
            try:
                page_text = await page.evaluate("() => document.body.innerText")
                page_text_lower = page_text.lower()
                final_url = page.url

                success_indicators = [
                    "success", "başarılı", "completed", "tamamlandı",
                    "submitted", "gönderildi", "verified", "doğrulandı",
                    "declaration submitted",
                ]
                failure_indicators = [
                    "error", "hata", "failed", "başarısız",
                    "try again", "tekrar dene",
                ]

                is_success = any(ind in page_text_lower for ind in success_indicators)
                is_failure = any(ind in page_text_lower for ind in failure_indicators)

                # If we navigated back to the declaration list, check if the row is gone
                if "transfer-declaration-list" in final_url:
                    logger.info("BinanceTR: returned to declaration list — checking if item was processed")
                    is_success = True  # Being returned to the list implies success

                if is_success and not is_failure:
                    logger.info(f"BinanceTR: travel rule COMPLETED for {travel_rule_id}")
                    return {
                        "success": True,
                        "message": f"Travel rule declaration submitted for Binance TR",
                        "travel_rule_id": travel_rule_id,
                    }
                elif is_failure:
                    logger.warning("BinanceTR: travel rule submission may have failed")
                    return {
                        "success": False,
                        "message": "Travel rule form submitted but error detected on page",
                    }
                else:
                    logger.info(f"BinanceTR: travel rule form processed for {travel_rule_id} "
                               "(no explicit success/failure detected)")
                    return {
                        "success": True,
                        "message": f"Travel rule declaration processed (verify in deposit history)",
                        "travel_rule_id": travel_rule_id,
                    }

            except Exception as e:
                logger.warning(f"BinanceTR: result check failed: {e}")
                return {
                    "success": True,
                    "message": f"Travel rule form submitted for {travel_rule_id} (result check failed)",
                    "travel_rule_id": travel_rule_id,
                }

        except Exception as e:
            error_msg = f"Travel rule UI automation failed: {e}"
            logger.error(f"BinanceTR: {error_msg}")
            try:
                await self._debug_screenshot(page, "tr_99_error")
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
                    item_amount = float(item.get("amount", "0").replace(",", "."))
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
