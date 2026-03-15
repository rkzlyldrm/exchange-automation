"""
BTCTurk browser automation — login, token capture, TRY withdrawal, crypto withdrawal.
"""
import asyncio
import json
import os
import re
import time
import logging
from typing import Dict, Any, Optional

from playwright.async_api import Page, Request

from src.exchanges.base import BaseExchangeAutomation
from src.browser.session import ExchangeSession
from src.browser.manager import browser_manager
from src.security.totp import generate_totp_code

logger = logging.getLogger(__name__)

LOGIN_URL = "https://pro.btcturk.com/en/user/login"
WITHDRAW_URL = "https://api.btcturk.com/api/v2/withdrawals/fiat/bank"
WALLETS_URL = "https://pro-bff.btcturk.com/v1/user-wallets"

DEBUG_DIR = "/app/data/debug"


class BTCTurkAutomation(BaseExchangeAutomation):
    exchange_name = "btcturk"
    confirm_deposit_needs_browser = True

    PENDING_DECLARATIONS_URL = "https://kripto.btcturk.com/para-yatir/beyan-bekleyen-islemler"

    # Map source exchange keys to BTCTurk "Borsa Adı" <select> option values
    # Format: "index: id" from the dropdown (e.g. "4: 8" = Binance TR)
    # "17: 0" = Diğer (Other) — requires filling a text input with the exchange name
    TRAVEL_RULE_EXCHANGE_VALUES = {
        "binance_tr": "4: 8",       # Binance TR
        "binance_global": "3: 3",   # Binance
        "paribu": "8: 7",           # Paribu
        "okx_tr": "11: 11",         # OKX
        "kucoin_tr": "13: 13",      # KuCoin
        "htx": "14: 14",            # HTX
        "cointr": "17: 0",          # Diğer (CoinTR not in list)
        "whitebit_tr": "17: 0",     # Diğer (WhiteBIT not in list)
    }

    # Display names for "Diğer" (Other) — used when exchange is not in the dropdown
    TRAVEL_RULE_EXCHANGE_DISPLAY = {
        "cointr": "CoinTR",
        "whitebit_tr": "WhiteBIT",
    }

    # Crypto withdrawal page URLs
    # Pattern: https://kripto.btcturk.com/para-cek/kripto-transferi/{slug}
    CRYPTO_WITHDRAW_URLS = {
        ("USDT", "TRON"):  "https://kripto.btcturk.com/para-cek/kripto-transferi/trc20usdt",
        ("USDT", "TRC20"): "https://kripto.btcturk.com/para-cek/kripto-transferi/trc20usdt",
        ("USDT", "AVAXC"): "https://kripto.btcturk.com/para-cek/kripto-transferi/arc20usdt",
        ("USDT", "ARC20"): "https://kripto.btcturk.com/para-cek/kripto-transferi/arc20usdt",
    }

    # Email sender for BTCTurk
    BTCTURK_EMAIL_SENDER = "btcturk"

    # Confirmation link regex — UUID-based URL
    CONFIRM_LINK_RE = r"(https://kripto\.btcturk\.com/para-cek/kripto-cekme-onayi/[0-9a-f\-]+)"

    # ── debug helper ──────────────────────────────────────────

    async def _debug_screenshot(self, page: Page, label: str) -> None:
        """Save a debug screenshot with label."""
        try:
            os.makedirs(DEBUG_DIR, exist_ok=True)
            path = os.path.join(DEBUG_DIR, f"btcturk_{label}.png")
            await page.screenshot(path=path, full_page=False)
            logger.info(f"BTCTurk: [DEBUG] screenshot saved: {label}.png (url={page.url})")
        except Exception as e:
            logger.warning(f"BTCTurk: [DEBUG] screenshot failed for {label}: {e}")

    # ── login ──────────────────────────────────────────────────

    async def login(self, session: ExchangeSession, credentials: Dict[str, str]) -> dict:
        """
        BTCTurk login flow:
        1. Navigate to login page (pro.btcturk.com redirects to kripto.btcturk.com or sso.btcturk.com)
        2. Enter phone number / email + password
        3. Handle captcha if present
        4. Enter TOTP code (Google Authenticator)
        5. Wait for redirect, capture auth token, save storage state
        """
        session.status = "logging_in"
        page = await session.get_page()

        try:
            # Set up interceptors to capture authorization token
            self._setup_request_interceptor(page, session)

            # Check if already logged in
            try:
                current_url = page.url
                token = session.get_auth_token()
                if token and "/login" not in current_url and "/sign-in" not in current_url and "about:blank" not in current_url:
                    logger.info(f"BTCTurk: browser already on {current_url} with token — verifying session")
                    if await self.check_session(session):
                        session.set_logged_in(session.captured_tokens)
                        logger.info("BTCTurk: already logged in — skipping login flow")
                        return {"success": True, "message": "Already logged in"}
                    else:
                        logger.info("BTCTurk: token expired, proceeding with fresh login")
            except Exception:
                pass

            # ── Navigate to login page ──
            logger.info("BTCTurk: navigating to login page")
            await page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_timeout(4000)
            await self._debug_screenshot(page, "01_page_loaded")

            # ── Dismiss cookie consent ──
            await self._dismiss_cookie_consent(page)
            await self._debug_screenshot(page, "02_after_cookie")

            # Check if cookies caused auto-redirect (already logged in)
            current_url = page.url
            if "/login" not in current_url and "/sign-in" not in current_url and "sso.btcturk" not in current_url and "hesap.btcturk" not in current_url:
                logger.info(f"BTCTurk: cookies auto-logged in — redirected to {current_url}")
                await page.wait_for_timeout(3000)
                token = session.get_auth_token()
                if token:
                    session.set_logged_in(session.captured_tokens)
                    await browser_manager.save_storage_state(self.exchange_name)
                    return {"success": True, "message": "Auto-login via saved cookies, token captured"}
                # Try to trigger API calls to capture token
                try:
                    await page.goto("https://pro.btcturk.com/en/wallet", wait_until="domcontentloaded", timeout=15000)
                    await page.wait_for_timeout(3000)
                except Exception:
                    pass
                token = session.get_auth_token()
                if token:
                    session.set_logged_in(session.captured_tokens)
                    await browser_manager.save_storage_state(self.exchange_name)
                    return {"success": True, "message": "Auto-login via saved cookies"}
                session.set_logged_in()
                return {"success": True, "message": "Auto-login via cookies but no auth token captured yet"}

            # ── Step 1: Fill phone/email ──
            phone_or_email = credentials["email"]
            logger.info(f"BTCTurk: entering login credential {phone_or_email[:3]}***")

            # BTCTurk SSO may redirect — wait for the login form
            await page.wait_for_timeout(2000)
            await self._debug_screenshot(page, "03_login_form")

            # Try multiple selectors for the username field
            username_selectors = [
                'input[name="Username"]',
                'input[name="username"]',
                'input[type="email"]',
                'input[type="text"]',
                'input[placeholder*="E-Posta" i]',
                'input[placeholder*="mail" i]',
                'input[placeholder*="Kimlik" i]',
                'input[placeholder*="Telefon" i]',
                'input[placeholder*="phone" i]',
            ]
            username_input = None
            for sel in username_selectors:
                try:
                    el = page.locator(sel).first
                    if await el.is_visible(timeout=2000):
                        username_input = el
                        logger.info(f"BTCTurk: found username input via '{sel}'")
                        break
                except Exception:
                    continue

            if not username_input:
                await self._debug_screenshot(page, "03b_no_username_input")
                session.set_error("Could not find username input field")
                return {"success": False, "message": "Could not find username input field on login page"}

            await username_input.click(force=True)
            await username_input.fill(phone_or_email)
            await page.wait_for_timeout(500)
            await self._debug_screenshot(page, "04_username_entered")

            # ── Step 2: Click Continue to go to password step ──
            continue_selectors = [
                'button:has-text("Continue")',
                'button:has-text("Devam")',
                'button:has-text("Devam Et")',
                'button:has-text("İleri")',
                'button[type="submit"]',
            ]
            for sel in continue_selectors:
                try:
                    btn = page.locator(sel).first
                    if await btn.is_visible(timeout=2000):
                        await btn.click(force=True, timeout=5000)
                        logger.info(f"BTCTurk: clicked continue via '{sel}'")
                        break
                except Exception:
                    continue
            await page.wait_for_timeout(3000)
            await self._debug_screenshot(page, "05_after_continue")

            # ── Step 3: Fill password ──
            # BTCTurk uses individual digit boxes for password (like a PIN entry)
            logger.info("BTCTurk: waiting for password field")

            # Try standard password input first
            password_filled = False
            try:
                password_input = page.locator('input[type="password"]').first
                await password_input.wait_for(state="visible", timeout=5000)
                logger.info("BTCTurk: found standard password input")
                await password_input.click(force=True)
                await password_input.fill(credentials["password"])
                password_filled = True
            except Exception:
                logger.info("BTCTurk: no standard password input — trying digit boxes")

            if not password_filled:
                # Look for individual digit/character input boxes (maxlength=1)
                digit_boxes = page.locator('input[maxlength="1"]')
                count = await digit_boxes.count()

                if count == 0:
                    # Try other patterns
                    digit_boxes = page.locator('input[type="tel"], input[inputmode="numeric"]')
                    count = await digit_boxes.count()

                if count > 0:
                    logger.info(f"BTCTurk: found {count} digit boxes for password entry")
                    password = credentials["password"]

                    # Use nativeInputValueSetter with React _valueTracker reset.
                    # React tracks input values internally via _valueTracker. If we don't
                    # reset it, React ignores our dispatched events (thinks value unchanged).
                    fill_result = await page.evaluate("""(pw) => {
                        const boxes = document.querySelectorAll('input[maxlength="1"]');
                        if (boxes.length === 0) return {ok: false, reason: 'no boxes'};
                        const nativeSetter = Object.getOwnPropertyDescriptor(
                            window.HTMLInputElement.prototype, 'value'
                        ).set;
                        const results = [];
                        for (let i = 0; i < Math.min(pw.length, boxes.length); i++) {
                            const box = boxes[i];
                            box.focus();
                            box.click();

                            // Reset React's _valueTracker so React sees the change
                            const tracker = box._valueTracker;
                            if (tracker) {
                                tracker.setValue('');
                            }

                            // Set value via native setter (bypasses React's override)
                            nativeSetter.call(box, pw[i]);

                            // Fire full event sequence that React listens to
                            box.dispatchEvent(new Event('input', { bubbles: true }));
                            box.dispatchEvent(new Event('change', { bubbles: true }));

                            results.push({i: i, val: box.value});
                        }
                        // Verify all values after setting
                        const verify = [];
                        for (let i = 0; i < boxes.length; i++) {
                            verify.push(boxes[i].value ? '*' : '_');
                        }
                        return {ok: true, filled: results.length, total: boxes.length, verify: verify.join('')};
                    }""", password)
                    logger.info(f"BTCTurk: nativeInputValueSetter result: {fill_result}")
                    password_filled = True
                else:
                    # Last resort: click in the password area and type
                    logger.info("BTCTurk: trying to type password via keyboard into focused area")
                    await page.keyboard.press("Tab")
                    await page.wait_for_timeout(300)
                    await page.keyboard.type(credentials["password"], delay=120)
                    password_filled = True
                    logger.info("BTCTurk: typed password via keyboard fallback")

            await page.wait_for_timeout(500)
            await self._debug_screenshot(page, "06_password_entered")

            # ── Step 4: Click Continue to submit password ──
            password_url = page.url
            await page.wait_for_timeout(1000)

            # Debug: check button state before clicking
            btn_info = await page.evaluate("""() => {
                const buttons = document.querySelectorAll('button');
                const info = [];
                for (const b of buttons) {
                    info.push({text: b.textContent.trim(), disabled: b.disabled, type: b.type, classes: b.className});
                }
                return info;
            }""")
            logger.info(f"BTCTurk: buttons on page: {btn_info}")

            # There may be multiple Continue buttons (one per login step).
            # We need to click the ENABLED one, not a disabled leftover from step 1.
            clicked = await page.evaluate("""() => {
                const buttons = document.querySelectorAll('button');
                for (const b of buttons) {
                    const text = b.textContent.trim().toLowerCase();
                    const isTarget = (
                        text === 'continue' || text === 'devam' || text === 'devam et' ||
                        text === 'giriş yap' || text === 'giris yap' || text === 'login'
                    );
                    if (isTarget && !b.disabled) {
                        b.click();
                        return {clicked: text, disabled: b.disabled};
                    }
                }
                // Fallback: any non-disabled submit button
                const submits = document.querySelectorAll('button[type="submit"]:not([disabled])');
                if (submits.length > 0) {
                    submits[submits.length - 1].click();
                    return {clicked: 'submit-last', disabled: false};
                }
                return null;
            }""")
            if clicked:
                logger.info(f"BTCTurk: clicked password submit button: {clicked}")
            else:
                # Last resort: press Enter
                logger.info("BTCTurk: no enabled submit button found, pressing Enter")
                await page.keyboard.press("Enter")

            # Wait for page to change (password page → TOTP page or captcha or redirect)
            logger.info("BTCTurk: waiting for page to advance past password...")
            try:
                await page.wait_for_url(
                    lambda url: url != password_url,
                    timeout=15000,
                )
                logger.info(f"BTCTurk: page advanced to {page.url}")
            except Exception:
                logger.warning(f"BTCTurk: page did not advance after password submit, URL still: {page.url}")

            await page.wait_for_timeout(2000)
            await self._debug_screenshot(page, "07_after_submit")

            # ── Step 5: Handle captcha if present (skip on MFA page) ──
            current_url = page.url
            on_mfa_page = "/Account/Mfa" in current_url or "/mfa" in current_url.lower()
            if not on_mfa_page:
                captcha_detected = await self._check_captcha_visible(page)
                if captcha_detected:
                    await self._debug_screenshot(page, "07_captcha_detected")
                    logger.info("BTCTurk: captcha detected — waiting for human to solve via frontend")
                    solved = await session.wait_for_captcha_solved(timeout=300)
                    if not solved:
                        token = session.get_auth_token()
                        if token:
                            session.set_logged_in(session.captured_tokens)
                            await browser_manager.save_storage_state(self.exchange_name)
                            return {"success": True, "message": "Login successful (detected after captcha)"}
                        session.set_error("Captcha not solved in time")
                        return {"success": False, "message": "Captcha not solved — open the frontend and click the captcha"}
                    await page.wait_for_timeout(5000)
                    await self._debug_screenshot(page, "07b_after_captcha")
            else:
                logger.info("BTCTurk: on MFA page — skipping captcha detection")

            # ── Step 6: TOTP code ──
            totp_secret = credentials.get("totp_secret")
            await page.wait_for_timeout(1000)
            await self._debug_screenshot(page, "08_before_totp")

            if totp_secret:
                logger.info(f"BTCTurk: looking for TOTP input on {page.url}")

                # TOTP page is at /Account/Mfa with 6 digit boxes
                try:
                    # On the MFA page, digit boxes are ready immediately
                    digit_boxes = page.locator('input[maxlength="1"]')
                    dcount = await digit_boxes.count()

                    if dcount >= 6 and page.url != password_url:
                        totp_field = digit_boxes.first
                        logger.info(f"BTCTurk: found {dcount} TOTP digit boxes on MFA page")
                    else:
                        # Try specific TOTP selectors as fallback
                        totp_selector = (
                            'input[name="AuthCode"], '
                            'input[placeholder*="Authenticator" i], '
                            'input[placeholder*="code" i], '
                            'input[maxlength="6"]'
                        )
                        totp_field = page.locator(totp_selector).first
                        await totp_field.wait_for(state="visible", timeout=10000)

                    await self._debug_screenshot(page, "09_totp_found")

                    code = generate_totp_code(totp_secret)
                    logger.info(f"BTCTurk: entering TOTP code {code[:2]}****")

                    # Check if single-digit input boxes (maxlength=1)
                    maxlen = await totp_field.get_attribute("maxlength")
                    if maxlen and int(maxlen) == 1:
                        # Use nativeInputValueSetter with _valueTracker reset for React
                        totp_fill = await page.evaluate("""(code) => {
                            const boxes = document.querySelectorAll('input[maxlength="1"]');
                            if (boxes.length === 0) return {ok: false};
                            const nativeSetter = Object.getOwnPropertyDescriptor(
                                window.HTMLInputElement.prototype, 'value'
                            ).set;
                            for (let i = 0; i < Math.min(code.length, boxes.length); i++) {
                                const box = boxes[i];
                                box.focus();
                                box.click();
                                const tracker = box._valueTracker;
                                if (tracker) tracker.setValue('');
                                nativeSetter.call(box, code[i]);
                                box.dispatchEvent(new Event('input', { bubbles: true }));
                                box.dispatchEvent(new Event('change', { bubbles: true }));
                            }
                            return {ok: true, filled: Math.min(code.length, boxes.length)};
                        }""", code)
                        logger.info(f"BTCTurk: TOTP nativeSetter result: {totp_fill}")
                    elif maxlen and int(maxlen) == 6:
                        await totp_field.click(force=True)
                        await totp_field.fill(code)
                    else:
                        await totp_field.click(force=True)
                        await totp_field.fill(code)

                    await page.wait_for_timeout(1500)
                    await self._debug_screenshot(page, "10_totp_entered")

                    # Click enabled Continue/confirm button (skip disabled ones)
                    totp_clicked = await page.evaluate("""() => {
                        const buttons = document.querySelectorAll('button');
                        for (const b of buttons) {
                            const text = b.textContent.trim().toLowerCase();
                            const isTarget = (
                                text === 'continue' || text === 'devam' || text === 'devam et' ||
                                text === 'onayla' || text === 'doğrula' || text === 'confirm' || text === 'verify'
                            );
                            if (isTarget && !b.disabled) {
                                b.click();
                                return text;
                            }
                        }
                        const submit = document.querySelector('button[type="submit"]:not([disabled])');
                        if (submit) { submit.click(); return 'submit'; }
                        return null;
                    }""")
                    logger.info(f"BTCTurk: clicked TOTP confirm button: {totp_clicked}")
                    await page.wait_for_timeout(3000)
                    await self._debug_screenshot(page, "11_after_totp")

                except Exception as e:
                    logger.warning(f"BTCTurk: TOTP step issue: {e}")
                    await self._debug_screenshot(page, "08c_totp_error")
                    if "/login" not in page.url and "/sign-in" not in page.url and "sso.btcturk" not in page.url and "hesap.btcturk" not in page.url:
                        logger.info("BTCTurk: already past login page — TOTP may not be required")

            # ── Step 6: Handle device confirmation / email verification ──
            await page.wait_for_timeout(2000)
            current_url = page.url
            needs_verification = "deviceconfirmation" in current_url.lower()

            if not needs_verification:
                # Also check page text for verification keywords
                page_text = ""
                try:
                    page_text = await page.evaluate("() => document.body.innerText")
                except Exception:
                    pass
                if any(kw in page_text.lower() for kw in ["e-posta doğrulama", "sms doğrulama", "verification code", "device verification", "new device"]):
                    needs_verification = True

            if needs_verification:
                await self._debug_screenshot(page, "12_verification_needed")
                logger.info("BTCTurk: device/email verification page detected — waiting for user to submit code")
                got_codes = await session.wait_for_verification_codes(timeout=300)
                if not got_codes:
                    # Check if we got logged in anyway
                    token = session.get_auth_token()
                    if token:
                        session.set_logged_in(session.captured_tokens)
                        await browser_manager.save_storage_state(self.exchange_name)
                        return {"success": True, "message": "Login successful"}
                    session.set_error("Verification codes not submitted in time")
                    return {"success": False, "message": "Verification timed out — submit email code from the frontend"}

                email_code = session.verification_codes.get("email_code", "")
                logger.info(f"BTCTurk: received verification code: {email_code[:2]}****")

                # Device confirmation page uses digit boxes (maxlength=1), same as password/TOTP
                digit_boxes = page.locator('input[maxlength="1"]')
                dcount = await digit_boxes.count()

                if dcount >= 6:
                    # Use nativeInputValueSetter with _valueTracker reset
                    vcode_fill = await page.evaluate("""(code) => {
                        const boxes = document.querySelectorAll('input[maxlength="1"]');
                        if (boxes.length === 0) return {ok: false};
                        const nativeSetter = Object.getOwnPropertyDescriptor(
                            window.HTMLInputElement.prototype, 'value'
                        ).set;
                        for (let i = 0; i < Math.min(code.length, boxes.length); i++) {
                            const box = boxes[i];
                            box.focus();
                            box.click();
                            const tracker = box._valueTracker;
                            if (tracker) tracker.setValue('');
                            nativeSetter.call(box, code[i]);
                            box.dispatchEvent(new Event('input', { bubbles: true }));
                            box.dispatchEvent(new Event('change', { bubbles: true }));
                        }
                        return {ok: true, filled: Math.min(code.length, boxes.length)};
                    }""", email_code)
                    logger.info(f"BTCTurk: verification code fill result: {vcode_fill}")
                else:
                    # Fallback to text input
                    try:
                        field = page.locator('input[type="text"], input[type="number"]').first
                        await field.click(force=True)
                        await field.fill(email_code)
                        logger.info("BTCTurk: filled verification code via text input")
                    except Exception as e:
                        logger.warning(f"BTCTurk: verification code fill failed: {e}")

                await page.wait_for_timeout(500)

                # Click Continue (enabled, non-disabled)
                vcode_clicked = await page.evaluate("""() => {
                    const buttons = document.querySelectorAll('button');
                    for (const b of buttons) {
                        const text = b.textContent.trim().toLowerCase();
                        const isTarget = (
                            text === 'continue' || text === 'devam' || text === 'devam et' ||
                            text === 'onayla' || text === 'doğrula' || text === 'confirm'
                        );
                        if (isTarget && !b.disabled) { b.click(); return text; }
                    }
                    const submit = document.querySelector('button[type="submit"]:not([disabled])');
                    if (submit) { submit.click(); return 'submit'; }
                    return null;
                }""")
                logger.info(f"BTCTurk: clicked verification confirm: {vcode_clicked}")

                await page.wait_for_timeout(5000)
                await self._debug_screenshot(page, "13_after_verification")

            # ── Step 7: Wait for redirect ──
            logger.info("BTCTurk: waiting for login redirect...")
            try:
                await page.wait_for_url(
                    lambda url: "/login" not in url and "/sign-in" not in url and "sso.btcturk" not in url and "hesap.btcturk" not in url,
                    timeout=30000,
                )
            except Exception:
                current_url = page.url
                logger.warning(f"BTCTurk: URL after wait: {current_url}")
                await self._debug_screenshot(page, "14_redirect_timeout")
                if "/login" in current_url or "/sign-in" in current_url or "sso.btcturk" in current_url or "hesap.btcturk" in current_url:
                    session.set_error("Login redirect timed out")
                    return {"success": False, "message": session.last_error}

            await page.wait_for_timeout(3000)
            await self._debug_screenshot(page, "14_after_redirect")

            # ── Step 8: Capture auth token ──
            # Navigate to wallet page to trigger API calls with auth token
            token = session.get_auth_token()
            if not token:
                try:
                    await page.goto("https://pro.btcturk.com/en/wallet", wait_until="domcontentloaded", timeout=15000)
                    await page.wait_for_timeout(5000)
                except Exception:
                    pass
                token = session.get_auth_token()

            if token:
                session.set_logged_in(session.captured_tokens)
                await browser_manager.save_storage_state(self.exchange_name)
                logger.info(f"BTCTurk: login successful, auth token captured ({len(token)} chars)")
                await self._debug_screenshot(page, "15_success")
                return {"success": True, "message": "Login successful, token captured"}
            else:
                session.set_logged_in()
                await browser_manager.save_storage_state(self.exchange_name)
                logger.warning("BTCTurk: logged in but no auth token captured yet — will use browser for API calls")
                return {"success": True, "message": "Login successful but no auth token captured yet — withdrawal will use browser cookies"}

        except Exception as e:
            error_msg = f"Login failed: {str(e)}"
            logger.error(f"BTCTurk: {error_msg}")
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
        """Dismiss BTCTurk cookie consent banner."""
        try:
            btn = page.locator('button:has-text("Kabul Et"), button:has-text("Accept"), button:has-text("Tamam")').first
            await btn.wait_for(state="visible", timeout=5000)
            await btn.click(force=True, timeout=3000)
            logger.info("BTCTurk: dismissed cookie consent")
            await page.wait_for_timeout(1000)
        except Exception:
            dismissed = await page.evaluate("""() => {
                const btns = document.querySelectorAll('button');
                for (const b of btns) {
                    if (b.textContent.includes('Kabul Et') || b.textContent.includes('Accept') || b.textContent.includes('Tamam')) {
                        b.click();
                        return true;
                    }
                }
                return false;
            }""")
            if dismissed:
                logger.info("BTCTurk: dismissed cookie consent via JS")
                await page.wait_for_timeout(1000)
            else:
                logger.debug("BTCTurk: no cookie consent found")

    # ── captcha detection ────────────────────────────────────

    async def _check_captcha_visible(self, page: Page) -> bool:
        """Check if a captcha is visible."""
        for text in ["robot", "captcha", "Güvenlik", "Security", "puzzle", "Doğrulama", "Bulmacayı", "kaydırın"]:
            try:
                loc = page.get_by_text(text, exact=False)
                if await loc.first.is_visible():
                    logger.info(f"BTCTurk: captcha detected via text '{text}'")
                    return True
            except Exception:
                pass
        try:
            iframe = page.locator('iframe[src*="captcha"], iframe[src*="recaptcha"], iframe[src*="geetest"]').first
            if await iframe.is_visible():
                logger.info("BTCTurk: captcha detected via iframe")
                return True
        except Exception:
            pass
        return False

    # ── request interceptor ────────────────────────────────────

    def _setup_request_interceptor(self, page: Page, session: ExchangeSession) -> None:
        """Capture auth tokens from BTCTurk API requests."""

        def on_request(request: Request) -> None:
            url = request.url
            if "btcturk.com" not in url:
                return
            headers = request.headers
            auth = headers.get("authorization")
            if auth and auth.startswith("Bearer ") and auth != session.captured_tokens.get("authorization"):
                session.captured_tokens["authorization"] = auth
                logger.info(f"BTCTurk: captured authorization header ({len(auth)} chars)")

        page.on("request", on_request)

    # ── session check ──────────────────────────────────────────

    async def check_session(self, session: ExchangeSession) -> bool:
        """Check if session is still valid using browser fetch with auth token."""
        page = await session.get_page()
        auth_token = session.captured_tokens.get("authorization", "")
        try:
            result = await page.evaluate("""
                async (authToken) => {
                    try {
                        const headers = { 'Accept': 'application/json' };
                        if (authToken) headers['Authorization'] = authToken;
                        const resp = await fetch('https://api.btcturk.com/api/v1/users/balances', {
                            method: 'GET',
                            headers: headers,
                            credentials: 'include',
                        });
                        return { status: resp.status };
                    } catch (e) {
                        return { status: 0, error: e.message };
                    }
                }
            """, auth_token)
            if result.get("status") == 200:
                return True
            return False
        except Exception as e:
            logger.warning(f"BTCTurk session check failed: {e}")
            return False

    # ── keepalive ──────────────────────────────────────────────

    async def keepalive(self, session: ExchangeSession) -> None:
        """Navigate between tabs to keep the SPA alive."""
        try:
            page = await session.get_page()
            current_url = page.url
            if "/login" in current_url or "about:blank" in current_url:
                return

            if "/basic/" in current_url:
                url = "https://kripto.btcturk.com/en/pro/exchange/BTC_TRY"
                label = "Advanced Trade"
            else:
                url = "https://kripto.btcturk.com/en/basic/exchange/BTC_TRY"
                label = "Basic Trade"

            await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            logger.info(f"BTCTurk: keepalive — switched to {label}")
        except Exception as e:
            logger.debug(f"BTCTurk: keepalive error: {e}")

    # ── TRY withdrawal ─────────────────────────────────────────

    async def withdraw_try(
        self,
        session: ExchangeSession,
        amount: float,
        iban: str,
        payment_account_id: str,
    ) -> dict:
        """
        Execute TRY withdrawal via BTCTurk API using browser fetch.
        payment_account_id is used as userBankId for BTCTurk.
        """
        page = await session.get_page()

        if not payment_account_id:
            return {"success": False, "order_id": None, "message": "BTCTurk requires userBankId (payment_account_id)"}

        payload = {
            "amount": str(int(amount)),
            "currencySymbol": "TRY",
            "userBankId": int(payment_account_id),
        }

        logger.info(f"BTCTurk: submitting withdrawal: amount={amount}, userBankId={payment_account_id}")

        try:
            # Get the captured authorization token
            auth_token = session.captured_tokens.get("authorization", "")
            if not auth_token:
                return {"success": False, "order_id": None, "message": "No authorization token captured — please re-login"}

            logger.info(f"BTCTurk: making withdrawal with auth token ({len(auth_token)} chars)")

            # Use page.evaluate with the Bearer token in Authorization header
            result = await page.evaluate("""
                async ([payload, authToken]) => {
                    try {
                        const resp = await fetch('https://api.btcturk.com/api/v2/withdrawals/fiat/bank', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'Accept': 'application/json',
                                'Authorization': authToken,
                            },
                            body: JSON.stringify(payload),
                        });
                        const text = await resp.text();
                        let data;
                        try { data = JSON.parse(text); } catch(e) { data = {raw: text}; }
                        return { status: resp.status, data: data };
                    } catch (e) {
                        return { status: 0, error: e.message, type: e.name };
                    }
                }
            """, [payload, auth_token])

            resp_status = result.get("status", 0)
            data = result.get("data", {})
            fetch_error = result.get("error")
            page_url = result.get("url", "unknown")

            if fetch_error:
                logger.error(f"BTCTurk withdrawal fetch error: {fetch_error} (type={result.get('type')}, page={page_url})")
                return {"success": False, "order_id": None, "message": f"BTCTurk API fetch failed: {fetch_error}"}

            logger.info(f"BTCTurk withdrawal response: status={resp_status}, data={json.dumps(data)}")

            if data.get("success"):
                withdrawal_data = data.get("data", {})
                order_id = str(withdrawal_data.get("id", "N/A"))
                return {
                    "success": True,
                    "order_id": order_id,
                    "message": f"Withdrawal submitted: {withdrawal_data.get('amount')} TRY to {withdrawal_data.get('receiverAddress', 'N/A')}",
                }
            else:
                error_msg = data.get("message", str(data))
                return {"success": False, "order_id": None, "message": f"BTCTurk error: {error_msg}"}

        except Exception as e:
            error_msg = f"Withdrawal request failed: {str(e)}"
            logger.error(f"BTCTurk: {error_msg}")
            return {"success": False, "order_id": None, "message": error_msg}

    # ── crypto withdrawal (API via browser fetch + email confirmation) ──────

    # BTCTurk API asset codes for crypto withdrawal
    BTCTURK_ASSET_CODES = {
        ("USDT", "AVAXC"): "ARC20USDT",
        ("USDT", "AVAX"): "ARC20USDT",
        ("USDT", "TRON"): "TRC20USDT",
        ("USDT", "TRC20"): "TRC20USDT",
        ("USDT", "ERC20"): "ERC20USDT",
        ("USDT", "ETH"): "ERC20USDT",
    }

    # BTCTurk exchange IDs for receiver platforms (Travel Rule)
    # None = exchange not in dropdown, use ReceiverAddressExchangeOtherName instead
    BTCTURK_EXCHANGE_IDS = {
        "okx_tr": 11, "okx tr": 11,
        "binance_tr": 8, "binance tr": 8,
        "paribu": 7,
        "kucoin_tr": 34, "kucoin tr": 34,
        "binance_global": 3, "binance global": 3,
        # Not in BTCTurk dropdown — ExchangeId=None, name in OtherName field
        "cointr": None, "coin tr": None,
        "whitebit_tr": None, "whitebit tr": None,
        "htx": None,
    }

    # Display names for "Diğer" (Other) exchanges in the crypto API
    BTCTURK_EXCHANGE_OTHER_NAMES = {
        "cointr": "cointr",
        "whitebit_tr": "whitebit",
        "htx": "htx",
    }

    async def withdraw_crypto(
        self,
        session: ExchangeSession,
        asset: str,
        network: str,
        amount: float,
        address: str,
        phishing_code: str = "",
        receiver_platform: str = "",
    ) -> dict:
        """
        Execute a crypto withdrawal via BTCTurk API (through browser fetch).

        Uses the same page.evaluate(fetch) pattern as withdraw_try() to call
        POST /api/v2/withdrawals/crypto through the logged-in browser session,
        bypassing geo-blocking.

        Anti-phishing safeguards (email confirmation):
        - Verify the phishing code in the email matches the stored code
        - Verify the withdrawal amount in the email matches the requested amount (±5 USDT)
        - Confirmation link opened in same browser session (cookie validation)
        """
        # Resolve BTCTurk asset code
        asset_key = (asset.upper(), network.upper())
        btcturk_asset = self.BTCTURK_ASSET_CODES.get(asset_key)
        if not btcturk_asset:
            return {
                "success": False,
                "message": f"Unsupported asset/network: {asset}/{network}. "
                           f"Supported: {list(self.BTCTURK_ASSET_CODES.keys())}",
                "tx_id": None,
            }

        if not address:
            return {"success": False, "message": "Withdrawal address is required", "tx_id": None}

        if not phishing_code:
            return {
                "success": False,
                "message": "Phishing code is required for crypto withdrawals (anti-phishing safety)",
                "tx_id": None,
            }

        page = await session.get_page()
        current_url = page.url
        if "/login" in current_url or "about:blank" in current_url:
            return {"success": False, "message": "Browser not logged in", "tx_id": None}

        # Get the captured authorization token
        auth_token = session.captured_tokens.get("authorization", "")
        if not auth_token:
            return {"success": False, "message": "No authorization token captured — please re-login", "tx_id": None}

        logger.info(f"BTCTurk crypto withdraw via API: {amount} {asset} ({btcturk_asset}) "
                     f"via {network} to {address[:16]}...")

        # Load receiver name from DB for Travel Rule
        receiver_first, receiver_last = self._load_receiver_name_from_db()

        # Resolve exchange ID for Travel Rule
        exchange_id = self.BTCTURK_EXCHANGE_IDS.get(receiver_platform, 11)
        other_name = None
        if exchange_id is None:
            # Exchange not in BTCTurk dropdown — use "Other" name field
            other_name = self.BTCTURK_EXCHANGE_OTHER_NAMES.get(receiver_platform, receiver_platform)

        # Build the API payload (matches what the BTCTurk web app sends)
        api_payload = {
            "Asset": btcturk_asset,
            "Amount": str(int(amount) if amount == int(amount) else amount),
            "Address": address,
            "AddressTag": None,
            "ExchangeId": exchange_id,
            "IsUserOwnedAddress": True,
            "Name": None,
            "Reason": "Fiyat farklılıklarından yararlanmak",
            "ReceiverAddressExchangeOtherName": other_name,
            "ReceiverAddressType": "Exchange",
            "ReceiverFirstName": receiver_first or None,
            "ReceiverLastName": receiver_last or None,
        }

        try:
            # Step 1: Call the API via browser fetch (bypasses geo-blocking)
            api_call_time = time.time() - 10  # 10s buffer for clock skew
            logger.info(f"BTCTurk crypto: calling API with auth token ({len(auth_token)} chars)")

            result = await page.evaluate("""
                async ([payload, authToken]) => {
                    try {
                        const resp = await fetch('https://api.btcturk.com/api/v2/withdrawals/crypto', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'Accept': 'application/json',
                                'Authorization': authToken,
                            },
                            body: JSON.stringify(payload),
                        });
                        const text = await resp.text();
                        let data;
                        try { data = JSON.parse(text); } catch(e) { data = {raw: text}; }
                        return { status: resp.status, data: data };
                    } catch (e) {
                        return { status: 0, error: e.message, type: e.name };
                    }
                }
            """, [api_payload, auth_token])

            logger.info(f"BTCTurk crypto API response: status={result.get('status')}, data={result.get('data')}")

            if result.get("status") == 0:
                return {
                    "success": False,
                    "message": f"API fetch failed: {result.get('error', 'unknown')}",
                    "tx_id": None,
                }

            api_data = result.get("data", {})

            if not api_data.get("success"):
                error_msg = api_data.get("message", str(api_data))
                logger.error(f"BTCTurk crypto API error: {error_msg} (code={api_data.get('code')})")
                return {
                    "success": False,
                    "message": f"BTCTurk API error: {error_msg}",
                    "tx_id": None,
                }

            # API call succeeded — extract withdrawal ID and fee
            wd_data = api_data.get("data", {})
            withdrawal_id = str(wd_data.get("id", ""))
            fee = abs(float(wd_data.get("fee", 0)))
            logger.info(f"BTCTurk crypto API success: withdrawal_id={withdrawal_id}, fee={fee}")

            # Step 2: Wait for confirmation email
            logger.info("BTCTurk crypto: waiting for confirmation email...")
            from src.email.monitor import email_monitor
            from src.email.models import EmailWatchRequest

            # Wait for the correct confirmation email with retry loop.
            # Strategy: register a watch, check the latest 2 emails.
            # If they're stale (wrong amount), add their UIDs to exclude list
            # and re-register the watch — the monitor will skip those UIDs
            # and keep polling until a new email arrives.
            MAX_EMAIL_ATTEMPTS = 20
            match = None
            deadline = time.time() + 600  # 10 min overall deadline
            skipped_uids: set = set()

            for attempt in range(1, MAX_EMAIL_ATTEMPTS + 1):
                remaining = deadline - time.time()
                if remaining <= 0:
                    break

                watch_id = f"btcturk_crypto_withdraw_{int(time.time())}_{attempt}"
                watch = EmailWatchRequest(
                    watch_id=watch_id,
                    sender_contains=self.BTCTURK_EMAIL_SENDER,
                    subject_contains="Çekme Onayı",
                    body_link_pattern=self.CONFIRM_LINK_RE,
                    body_code_pattern=r"Phishing Kodu:?\s*(?:</b>\s*</a>\s*</td>\s*<td[^>]*>\s*<a[^>]*>\s*<b[^>]*>\s*|[:\s]+)([^<\s][^<]*)",
                    max_age_seconds=300,
                    timeout_seconds=min(remaining, 60),
                    exclude_uids=set(skipped_uids),
                    min_email_time=api_call_time,
                )
                email_future = email_monitor.watch(watch)

                try:
                    candidate = await asyncio.wait_for(email_future, timeout=min(remaining, 60))
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    email_monitor.cancel_watch(watch_id)
                    if remaining > 60:
                        logger.info(f"BTCTurk crypto: no new email yet (attempt {attempt}), "
                                    f"retrying... ({int(remaining)}s left, {len(skipped_uids)} UIDs excluded)")
                        continue
                    break

                logger.info(f"BTCTurk crypto: email received (attempt {attempt}) — "
                            f"subject='{candidate.subject}', uid={candidate.email_uid}, "
                            f"code='{(candidate.code or '')[:10]}', link_present={bool(candidate.link)}")

                # ANTI-PHISHING — verify phishing code
                email_code = (candidate.code or "").strip()
                expected_code = phishing_code.strip()

                if not email_code:
                    logger.warning(f"BTCTurk crypto: no phishing code in email uid={candidate.email_uid}, skipping")
                    skipped_uids.add(candidate.email_uid)
                    continue

                if email_code != expected_code:
                    logger.error(f"BTCTurk crypto: PHISHING CODE MISMATCH! "
                                 f"Expected '{expected_code}', got '{email_code}'. ABORTING.")
                    return {
                        "success": False,
                        "message": f"SECURITY: Phishing code mismatch! Expected '{expected_code}', "
                                   f"got '{email_code}'. Withdrawal ABORTED — possible phishing attack.",
                        "tx_id": withdrawal_id,
                    }

                logger.info("BTCTurk crypto: phishing code verified ✓")

                # ANTI-PHISHING — verify withdrawal amount from email body
                email_body = candidate.body or ""
                email_amount = None

                # First strip HTML tags to get clean text, avoiding CSS values
                # like "font-weight: 400" being matched as amounts
                import html as _html
                clean_body = re.sub(r'<style[^>]*>.*?</style>', '', email_body, flags=re.DOTALL)
                clean_body = re.sub(r'style="[^"]*"', '', clean_body)
                clean_body = re.sub(r'<[^>]+>', ' ', clean_body)
                clean_body = _html.unescape(clean_body)
                clean_body = re.sub(r'\s+', ' ', clean_body)

                amt_patterns = [
                    r'[Çç]ekme\s+[Aa]dedi\s*[:\s]*([\d]+(?:[.,]\d+)?)',
                    r'[Ww]ithdrawal\s+[Aa]mount\s*[:\s]*([\d]+(?:[.,]\d+)?)',
                    r'[Mm]iktar\s*[:\s]*([\d]+(?:[.,]\d+)?)',
                ]
                for pat in amt_patterns:
                    amt_match = re.search(pat, clean_body)
                    if amt_match:
                        try:
                            email_amount = float(amt_match.group(1).replace(",", "."))
                            break
                        except (ValueError, TypeError):
                            pass

                if email_amount is not None:
                    amount_diff = abs(email_amount - amount)
                    logger.info(f"BTCTurk crypto: email amount={email_amount}, "
                                f"requested amount={amount}, diff={amount_diff}")

                    if amount_diff > 5.0:
                        logger.warning(f"BTCTurk crypto: stale email uid={candidate.email_uid} "
                                       f"(amount={email_amount} vs requested={amount}), skipping")
                        skipped_uids.add(candidate.email_uid)
                        continue

                    logger.info("BTCTurk crypto: amount verified ✓")
                else:
                    logger.warning("BTCTurk crypto: could not extract amount from email body. "
                                   "Proceeding (phishing code was verified).")

                # ANTI-PHISHING — verify destination address from email body
                addr_patterns = [
                    r'[Gg]önderilen\s+[Aa]dres\s+([A-Za-z0-9]{20,})',
                    r'[Dd]estination\s+[Aa]ddress\s+([A-Za-z0-9]{20,})',
                ]
                email_address = None
                for pat in addr_patterns:
                    addr_match = re.search(pat, clean_body)
                    if addr_match:
                        email_address = addr_match.group(1)
                        break

                if email_address:
                    if email_address.lower() != address.lower():
                        logger.error(f"BTCTurk crypto: ADDRESS MISMATCH! "
                                     f"Email shows '{email_address}' but we requested '{address}'. ABORTING.")
                        return {
                            "success": False,
                            "message": f"SECURITY: Address mismatch! Email shows {email_address} "
                                       f"but we requested {address}. Withdrawal ABORTED.",
                            "tx_id": withdrawal_id,
                        }
                    logger.info("BTCTurk crypto: address verified ✓")
                else:
                    logger.warning("BTCTurk crypto: could not extract address from email body. "
                                   "Proceeding (phishing code + amount were verified).")

                match = candidate
                break

            if not match:
                return {
                    "success": False,
                    "message": f"API withdrawal submitted (id={withdrawal_id}) but correct confirmation "
                               "email not found within 10 minutes. Check BTCTurk email and confirm manually.",
                    "tx_id": withdrawal_id,
                }

            # Step 5: Open confirmation link in same browser
            if not match.link:
                return {
                    "success": False,
                    "message": f"SECURITY: No confirmation link found in email body "
                               f"(withdrawal_id={withdrawal_id}). Confirm manually.",
                    "tx_id": withdrawal_id,
                }

            logger.info(f"BTCTurk crypto: opening confirmation link in browser: {match.link[:60]}...")

            await page.goto(match.link, wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_timeout(3000)

            # Dismiss cookie consent banner if present (can block buttons)
            await page.evaluate("""() => {
                const buttons = document.querySelectorAll('button');
                for (const btn of buttons) {
                    const text = (btn.textContent || '').trim().toLowerCase();
                    if (text.includes('tümünü kabul') || text.includes('accept all') ||
                        text.includes('kabul et')) {
                        btn.click();
                        return true;
                    }
                }
                return false;
            }""")
            await page.wait_for_timeout(2000)

            await self._debug_screenshot(page, "crypto_03_after_confirm_link")

            # Step 6: Look for and click the confirmation button on the page
            # BTCTurk shows withdrawal details + a confirm button (Onayla / Confirm)
            click_result = await page.evaluate("""() => {
                const buttons = document.querySelectorAll('button, a.btn, input[type="submit"]');
                for (const btn of buttons) {
                    const text = (btn.textContent || btn.value || '').trim().toLowerCase();
                    if (text.includes('onayla') || text.includes('confirm') ||
                        text.includes('onay') || text.includes('çekmeyi onayla')) {
                        if (!btn.disabled) {
                            btn.click();
                            return {clicked: true, text: text};
                        }
                    }
                }
                return {clicked: false};
            }""")

            if click_result.get("clicked"):
                logger.info(f"BTCTurk crypto: clicked confirmation button: '{click_result.get('text')}'")
                await page.wait_for_timeout(5000)
                await self._debug_screenshot(page, "crypto_04_after_confirm_button")
            else:
                logger.info("BTCTurk crypto: no confirm button found on page (may auto-confirm)")

            # Step 7: Check result page after button click
            page_text = await page.evaluate("document.body?.innerText || ''")
            page_text_lower = page_text.lower()

            if any(kw in page_text_lower for kw in [
                "başarılı", "onaylandı", "confirmed", "success",
                "çekme işleminiz onaylanmıştır", "withdrawal confirmed",
                "işleminiz gerçekleştirilmiştir"
            ]):
                logger.info("BTCTurk crypto: withdrawal confirmed successfully!")
                return {
                    "success": True,
                    "message": f"Crypto withdrawal confirmed: {amount} {asset} via {network} "
                               f"to {address[:16]}... (id={withdrawal_id}, fee={fee})",
                    "tx_id": withdrawal_id,
                }

            if any(kw in page_text_lower for kw in [
                "hata", "error", "başarısız", "failed", "geçersiz", "invalid",
                "süresi dolmuş", "expired"
            ]):
                logger.warning(f"BTCTurk crypto: confirmation page shows error. Text: {page_text[:300]}")
                return {
                    "success": False,
                    "message": f"Confirmation link opened but page indicates error "
                               f"(id={withdrawal_id}). Page: {page_text[:200]}",
                    "tx_id": withdrawal_id,
                }

            # No clear error — assume success (button was clicked)
            logger.info(f"BTCTurk crypto: confirmation page loaded, button {'clicked' if click_result.get('clicked') else 'not found'}. "
                        f"Text: {page_text[:200]}")
            return {
                "success": True,
                "message": f"Confirmation link opened and button clicked. {amount} {asset} via {network} "
                           f"(id={withdrawal_id}). Verify in BTCTurk withdrawal history.",
                "tx_id": withdrawal_id,
            }

        except Exception as e:
            error_msg = f"Crypto withdrawal failed: {str(e)}"
            logger.error(f"BTCTurk: {error_msg}")
            try:
                await self._debug_screenshot(page, "crypto_99_error")
            except Exception:
                pass
            return {"success": False, "message": error_msg, "tx_id": None}

    @staticmethod
    def _load_receiver_name_from_db() -> tuple:
        """Load receiver name from ExchangeWebCredential.extra_data for Travel Rule."""
        try:
            from sqlalchemy import create_engine, text as sa_text
            from src.config import settings
            from src.security.encryption import decrypt_data

            engine = create_engine(settings.DATABASE_URL, pool_size=1, max_overflow=0)
            with engine.connect() as conn:
                row = conn.execute(
                    sa_text(
                        "SELECT extra_data FROM exchange_web_credentials "
                        "WHERE exchange_name = 'btcturk' AND is_active = true "
                        "LIMIT 1"
                    )
                ).fetchone()
            engine.dispose()

            if row and row[0]:
                import json as _json
                decrypted = decrypt_data(row[0])
                extra = _json.loads(decrypted)
                return (
                    extra.get("receiver_first_name", ""),
                    extra.get("receiver_last_name", ""),
                )
        except Exception as e:
            logger.warning(f"Failed to load BTCTurk receiver name: {e}")
        return ("", "")

    # ── travel rule ──────────────────────────────────────────────

    async def get_pending_travel_rules(self, session: ExchangeSession) -> dict:
        """
        Scrape pending travel rule declarations from BTCTurk.
        Uses browser page.evaluate to read the table at
        /para-yatir/beyan-bekleyen-islemler.
        """
        try:
            page = await session.get_page()
            current_url = page.url
            if "/login" in current_url or "about:blank" in current_url:
                return {"success": False, "pending": [], "message": "Not logged in"}

            # Navigate to pending declarations page
            await page.goto(
                self.PENDING_DECLARATIONS_URL,
                wait_until="domcontentloaded",
                timeout=15000,
            )
            await page.wait_for_timeout(3000)

            # Scrape the pending items from the Angular component
            # BTCTurk uses Angular custom elements, not standard HTML tables
            rows = await page.evaluate(r"""() => {
                const results = [];
                // The page uses <user-crypto-deposit-consent-pending> Angular component
                // Content is in div-based rows, not standard table elements
                // Find all elements containing "Onayla" text (the confirm button)
                const allElements = document.querySelectorAll('*');
                for (const el of allElements) {
                    const text = el.textContent.trim();
                    // Look for row-like containers that have Onayla and reasonable data
                    if (text.includes('Onayla') && text.includes('Görüntüle') &&
                        el.children.length >= 3 && text.length < 500 &&
                        !text.includes('Onay Bekleyen İşlemler')) {
                        // Parse the row content — extract currency, network, amount
                        // Pattern: date + currency (name) + network + address + amount + buttons
                        const childTexts = [];
                        for (const child of el.children) {
                            const ct = child.textContent.trim();
                            if (ct) childTexts.push(ct);
                        }

                        // Try to extract structured data from child elements
                        let currency = '', network = '', amount = '', date = '';
                        for (const ct of childTexts) {
                            // Amount is typically a number like "14.00"
                            if (/^\d+[\.,]?\d*$/.test(ct.replace(/\s/g, ''))) {
                                amount = ct.replace(/\s/g, '');
                            }
                            // Date pattern
                            else if (/\d{2}\/\d{2}\/\d{4}/.test(ct)) {
                                date = ct;
                            }
                        }

                        // Fallback: parse from full text content
                        if (!currency || !amount) {
                            // Extract using regex patterns from full text
                            const amtMatch = text.match(/(\d+[\.,]?\d*)\s*(Görüntüle|$)/);
                            if (amtMatch) amount = amtMatch[1].replace(/\s/g, '');

                            // Currency is typically in format "Tether (USDT)" or "Bitcoin (BTC)"
                            const ccyMatch = text.match(/([A-Za-z\s]+)\(([A-Z]+)\)/);
                            if (ccyMatch) currency = ccyMatch[2]; // Use ticker symbol
                        }

                        if (amount) {
                            results.push({ date, currency, network, amount });
                        }
                    }
                }

                // Deduplicate — parent containers may match too
                // Keep only the entries with the smallest container (most specific)
                if (results.length === 0) {
                    // Alternative approach: parse from the container text directly
                    const container = document.querySelector('user-crypto-deposit-consent-pending');
                    if (container) {
                        const bodyText = container.textContent;
                        // Pattern: looks for amount before "Görüntüle"
                        const amtMatch = bodyText.match(/(\d+[\.,]\d+)\s*Görüntüle/g);
                        const ccyMatch = bodyText.match(/\(([A-Z]{2,10})\)/g);
                        if (amtMatch) {
                            for (let i = 0; i < amtMatch.length; i++) {
                                const amt = amtMatch[i].replace(/\s*Görüntüle/, '').trim();
                                const ccy = ccyMatch && ccyMatch[i] ? ccyMatch[i].replace(/[()]/g, '') : '';
                                results.push({ date: '', currency: ccy, network: '', amount: amt });
                            }
                        }
                    }
                }

                return results;
            }""")

            pending = []
            for i, row in enumerate(rows or []):
                # Use index as travel_rule_id since BTCTurk doesn't expose IDs
                amount_str = row.get("amount", "0").replace(",", ".")
                pending.append({
                    "travel_rule_id": str(i),
                    "currency": row.get("currency", ""),
                    "amount": amount_str,
                    "network": row.get("network", ""),
                    "status": "pending",
                })

            logger.info(f"BTCTurk: found {len(pending)} pending travel rule items")
            return {"success": True, "pending": pending}

        except Exception as e:
            logger.error(f"BTCTurk: failed to fetch travel rules: {e}")
            return {"success": False, "pending": [], "message": str(e)}

    async def confirm_travel_rule(
        self,
        session: ExchangeSession,
        travel_rule_id: str,
        source_exchange: str,
    ) -> dict:
        """
        Complete the travel rule (beyan) form for a pending BTCTurk deposit
        via UI automation (Playwright).

        The modal ("İşlem Onayı") has:
        - Checkbox #m-info: "Gönderen kişi benim" (auto-fills name/surname)
        - Name/Surname inputs (filled by checkbox)
        - <select> for "Açıklama Seçiniz" (description)
        - Radio #w-info (Kişisel Cüzdan) / #e-info (Borsa)
        - <select> for "Borsa Adı" (exchange name, appears after Borsa radio)
        - Submit button.btn.btn-blue "Onayla"

        All form interactions are done in a single page.evaluate() call
        to avoid session lock issues between sequential HTTP calls.
        """
        exchange_value = self.TRAVEL_RULE_EXCHANGE_VALUES.get(source_exchange)
        if not exchange_value:
            return {
                "success": False,
                "message": f"Unknown source exchange: {source_exchange}. "
                           f"Supported: {list(self.TRAVEL_RULE_EXCHANGE_VALUES.keys())}",
            }

        try:
            page = await session.get_page()
            current_url = page.url
            if "/login" in current_url or "about:blank" in current_url:
                return {"success": False, "message": "Browser not logged in"}
        except Exception as e:
            return {"success": False, "message": f"Failed to get page: {e}"}

        # Display name for "Diğer" case — used to fill the text input
        exchange_display = self.TRAVEL_RULE_EXCHANGE_DISPLAY.get(source_exchange, "")

        logger.info(f"BTCTurk: starting travel rule confirm (row={travel_rule_id}, "
                     f"source={source_exchange}, value={exchange_value}, display={exchange_display})")

        try:
            # Step 1: Navigate to pending declarations page
            logger.info("BTCTurk travel rule step 1: navigating to pending declarations")
            await page.goto(
                self.PENDING_DECLARATIONS_URL,
                wait_until="domcontentloaded",
                timeout=15000,
            )
            await page.wait_for_timeout(3000)

            # Step 2-6: All form interactions in a single evaluate call
            # This avoids the modal closing between sequential HTTP/lock calls
            logger.info("BTCTurk travel rule step 2: filling form via single JS call")
            row_index = int(travel_rule_id) if travel_rule_id.isdigit() else 0

            form_result = await page.evaluate("""async ([rowIndex, exchangeValue, exchangeDisplay]) => {
                const delay = ms => new Promise(r => setTimeout(r, ms));
                const log = [];

                // Remove cookie banner if present
                const cookies = document.querySelectorAll('[class*="cookie"], .cookie-banner');
                cookies.forEach(el => el.remove());
                log.push('cookies_removed');

                // Step 2: Click ONAYLA button
                const allEls = document.querySelectorAll('a, button, span');
                let onaylaBtn = null;
                let idx = 0;
                for (const el of allEls) {
                    const t = el.textContent.trim();
                    if (t === 'ONAYLA' || t === 'Onayla') {
                        if (idx === rowIndex) { onaylaBtn = el; break; }
                        idx++;
                    }
                }
                if (!onaylaBtn) return JSON.stringify({success: false, message: 'No ONAYLA button found', log});
                onaylaBtn.click();
                log.push('onayla_clicked');
                await delay(2000);

                // Verify modal opened
                const modal = document.querySelector('app-crypto-deposit-decleration-dialog');
                if (!modal) return JSON.stringify({success: false, message: 'Modal did not open', log});
                log.push('modal_opened');

                // Step 3: Check "Gönderen kişi benim" checkbox
                const checkbox = modal.querySelector('#m-info');
                if (checkbox && !checkbox.checked) {
                    const label = modal.querySelector('label[for=m-info]');
                    if (label) label.click();
                    log.push('checkbox_clicked');
                    await delay(1000);
                }

                // Step 4: Select "Borsa" radio
                const borsaLabel = modal.querySelector('label[for=e-info]');
                if (borsaLabel) {
                    borsaLabel.click();
                    log.push('borsa_radio_clicked');
                    await delay(1500);
                }

                // Step 5: Set "Açıklama Seçiniz" <select> to "Fiyat farklılıklarından yararlanmak"
                const selects = modal.querySelectorAll('select');
                let descSelect = null;
                let exchSelect = null;
                for (const s of selects) {
                    if (s.name.includes('description')) descSelect = s;
                    if (s.name.includes('exchangeId')) exchSelect = s;
                }

                if (descSelect) {
                    // Find the option for "Fiyat farklılıklarından yararlanmak"
                    for (const opt of descSelect.options) {
                        if (opt.text.includes('Fiyat farkl')) {
                            descSelect.value = opt.value;
                            descSelect.dispatchEvent(new Event('change', {bubbles: true}));
                            log.push('desc_selected: ' + opt.text);
                            break;
                        }
                    }
                    await delay(500);
                } else {
                    log.push('desc_select_not_found');
                }

                // Step 6: Set "Borsa Adı" <select>
                if (exchSelect) {
                    exchSelect.value = exchangeValue;
                    exchSelect.dispatchEvent(new Event('change', {bubbles: true}));
                    const selectedText = exchSelect.options[exchSelect.selectedIndex]?.text || 'unknown';
                    log.push('exchange_selected: ' + selectedText);
                    await delay(1000);

                    // If "Diğer" was selected, fill the text input that appears
                    if (selectedText.includes('Diğer') && exchangeDisplay) {
                        // Wait for Angular to render the new input
                        await delay(500);
                        // Find the new text input for exchange name
                        const exchInputs = modal.querySelectorAll('input[type="text"]');
                        let filled = false;
                        for (const inp of exchInputs) {
                            const rect = inp.getBoundingClientRect();
                            const ph = inp.placeholder || '';
                            const nm = inp.name || '';
                            // Look for the exchange name input (not firstName/lastName)
                            if (rect.height > 0 && !nm.includes('firstName') && !nm.includes('lastName') &&
                                !ph.includes('Gönderenin')) {
                                const nativeSetter = Object.getOwnPropertyDescriptor(
                                    window.HTMLInputElement.prototype, 'value'
                                ).set;
                                nativeSetter.call(inp, exchangeDisplay);
                                inp.dispatchEvent(new Event('input', {bubbles: true}));
                                inp.dispatchEvent(new Event('change', {bubbles: true}));
                                log.push('diger_input_filled: ' + exchangeDisplay);
                                filled = true;
                                break;
                            }
                        }
                        if (!filled) log.push('diger_input_not_found');
                        await delay(500);
                    }
                } else {
                    log.push('exchange_select_not_found');
                }

                // Step 7: Click submit "Onayla" button
                const submitBtn = modal.querySelector('button.btn.btn-blue');
                if (!submitBtn) return JSON.stringify({success: false, message: 'Submit button not found', log});
                submitBtn.click();
                log.push('submit_clicked');
                await delay(3000);

                // Check result
                const modalStill = document.querySelector('app-crypto-deposit-decleration-dialog');
                if (modalStill) {
                    // Modal still open — might have validation errors
                    const errorTexts = [];
                    const errors = modalStill.querySelectorAll('.text-danger, .error, [class*=error], [class*=invalid]');
                    errors.forEach(e => { if (e.textContent.trim()) errorTexts.push(e.textContent.trim()); });
                    return JSON.stringify({success: false, message: 'Modal still open after submit', log, errors: errorTexts.slice(0, 5)});
                }

                log.push('modal_closed');
                return JSON.stringify({success: true, log});
            }""", [row_index, exchange_value, exchange_display])

            result = json.loads(form_result) if isinstance(form_result, str) else form_result
            logger.info(f"BTCTurk: form result: {result}")

            await self._debug_screenshot(page, "travel_rule_after_submit")

            if result.get("success"):
                return {
                    "success": True,
                    "message": f"Travel rule confirmed: {source_exchange} → BTCTurk",
                    "travel_rule_id": travel_rule_id,
                }
            else:
                return {
                    "success": False,
                    "message": result.get("message", "Form submission failed"),
                }

        except Exception as e:
            error_msg = f"Travel rule UI automation failed: {e}"
            logger.error(f"BTCTurk: {error_msg}")
            try:
                await self._debug_screenshot(page, "travel_rule_error")
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
                target = item
                break

        if not target:
            target = pending["pending"][0]

        return await self.confirm_travel_rule(
            session,
            travel_rule_id=target["travel_rule_id"],
            source_exchange=platform_name,
        )

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
