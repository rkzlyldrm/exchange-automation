"""
CoinTR browser automation — login, token capture, TRY withdrawal.
"""
import asyncio
import json
import os
import logging
from typing import Dict, Any, Optional

import aiohttp
from playwright.async_api import Page, Request, Response

from src.exchanges.base import BaseExchangeAutomation
from src.browser.session import ExchangeSession
from src.browser.manager import browser_manager
from src.security.totp import generate_totp_code

logger = logging.getLogger(__name__)

LOGIN_URL = "https://www.cointr.com/tr/login"
PRECHECK_URL = "https://www.cointr.com/v1/fiat-mix/private/order/withdraw/pre-check"
CONFIRM_URL = "https://www.cointr.com/v1/fiat-mix/private/order/withdraw/confirm"
USER_INFO_URL = "https://www.cointr.com/v1/mix/private/user/base-info"

DEBUG_DIR = "/app/data/debug"

# Turkish bank code → name mapping for CoinTR withdrawal API
BANK_NAMES = {
    "0206": "TÜRKİYE FİNANS KATILIM BANKASI A.Ş.",
    "0010": "TÜRKİYE CUMHURİYETİ ZİRAAT BANKASI A.Ş.",
    "0012": "T. HALK BANKASI A.Ş.",
    "0064": "T. İŞ BANKASI A.Ş.",
    "0046": "AKBANK T.A.Ş.",
    "0062": "T. GARANTİ BANKASI A.Ş.",
    "0067": "YAPI VE KREDİ BANKASI A.Ş.",
    "0015": "T. VAKIFLAR BANKASI T.A.O.",
    "0134": "DENİZBANK A.Ş.",
    "0111": "QNB FİNANSBANK A.Ş.",
    "0203": "ALBARAKA TÜRK KATILIM BANKASI A.Ş.",
    "0205": "KUVEYT TÜRK KATILIM BANKASI A.Ş.",
}


class CoinTRAutomation(BaseExchangeAutomation):
    exchange_name = "cointr"
    confirm_deposit_needs_browser = True

    LOCKED_DEPOSITS_URL = "https://www.cointr.com/v1/spot/capitalOrderListNoPage"

    # ── debug helper ──────────────────────────────────────────

    async def _debug_screenshot(self, page: Page, label: str) -> None:
        """Save a debug screenshot with label."""
        try:
            os.makedirs(DEBUG_DIR, exist_ok=True)
            path = os.path.join(DEBUG_DIR, f"cointr_{label}.png")
            await page.screenshot(path=path, full_page=False)
            logger.info(f"CoinTR: [DEBUG] screenshot saved: {label}.png (url={page.url})")
        except Exception as e:
            logger.warning(f"CoinTR: [DEBUG] screenshot failed for {label}: {e}")

    # ── login ──────────────────────────────────────────────────

    async def login(self, session: ExchangeSession, credentials: Dict[str, str]) -> dict:
        """
        CoinTR login flow:
        1. Navigate to login page, dismiss cookie consent
        2. Click 'E-Posta' tab, fill email + password, click 'Giriş Yap'
        3. Handle captcha if present
        4. Enter TOTP code (Google Authenticator)
        5. Wait for redirect, capture session cookie, save storage state
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
                if token and "/login" not in current_url and "about:blank" not in current_url:
                    logger.info(f"CoinTR: browser already on {current_url} with token — verifying session")
                    if await self.check_session(session):
                        session.set_logged_in(session.captured_tokens)
                        logger.info("CoinTR: already logged in — skipping login flow")
                        return {"success": True, "message": "Already logged in"}
                    else:
                        logger.info("CoinTR: token expired, proceeding with fresh login")
            except Exception:
                pass

            # ── Navigate to login page ──
            logger.info("CoinTR: navigating to login page")
            await page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_timeout(4000)
            await self._debug_screenshot(page, "01_page_loaded")

            # ── Dismiss cookie consent ──
            await self._dismiss_cookie_consent(page)
            await self._debug_screenshot(page, "02_after_cookie")

            # Check if cookies caused auto-redirect
            current_url = page.url
            if "/login" not in current_url and "giris" not in current_url:
                logger.info(f"CoinTR: cookies auto-logged in — redirected to {current_url}")
                await page.wait_for_timeout(3000)
                token = session.get_auth_token()
                if token:
                    session.set_logged_in(session.captured_tokens)
                    await browser_manager.save_storage_state(self.exchange_name)
                    return {"success": True, "message": "Auto-login via saved cookies, token captured"}
                # Try capturing from cookies
                await self._capture_session_cookie(page, session)
                token = session.get_auth_token()
                if token:
                    session.set_logged_in(session.captured_tokens)
                    await browser_manager.save_storage_state(self.exchange_name)
                    return {"success": True, "message": "Auto-login via saved cookies"}
                session.set_logged_in()
                return {"success": True, "message": "Auto-login via cookies but no session token captured yet"}

            # ── Step 1: Click E-Posta tab to show email input ──
            try:
                email_tab = page.locator('text="E-Posta"').first
                await email_tab.wait_for(state="visible", timeout=5000)
                await email_tab.click()
                logger.info("CoinTR: clicked E-Posta tab")
                await page.wait_for_timeout(1000)
            except Exception as e:
                logger.warning(f"CoinTR: E-Posta tab click issue: {e}")
            await self._debug_screenshot(page, "03_email_tab")

            # ── Step 2: Fill email ──
            email = credentials["email"]
            logger.info(f"CoinTR: entering email {email[:3]}***")

            email_input = page.locator('input[placeholder="E-Posta"], input[name="dnPhone"]').first
            await email_input.wait_for(state="visible", timeout=10000)
            await email_input.click(force=True)
            await email_input.fill(email)
            await page.wait_for_timeout(500)
            await self._debug_screenshot(page, "04_email_entered")

            # ── Step 3: Fill password ──
            logger.info("CoinTR: entering password")
            password_input = page.locator('input[type="password"], input[name="dnEmail"]').first
            await password_input.wait_for(state="visible", timeout=5000)
            await password_input.click(force=True)
            await password_input.fill(credentials["password"])
            await page.wait_for_timeout(500)
            await self._debug_screenshot(page, "05_password_entered")

            # ── Step 4: Click submit ──
            submit_btn = page.locator('button:has-text("Giriş Yap")').first
            await submit_btn.click(force=True, timeout=5000)
            logger.info("CoinTR: clicked 'Giriş Yap'")
            await page.wait_for_timeout(4000)
            await self._debug_screenshot(page, "06_after_submit")

            # ── Step 5: Handle captcha (may appear multiple times) ──
            for captcha_round in range(3):
                captcha_detected = await self._check_captcha_visible(page)
                if not captcha_detected:
                    break
                await self._debug_screenshot(page, f"07_captcha_round{captcha_round + 1}")
                logger.info(f"CoinTR: captcha detected (round {captcha_round + 1}) — waiting for human to solve")
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
                await self._debug_screenshot(page, f"07b_after_captcha_round{captcha_round + 1}")

            # ── Step 6: Handle verification page ──
            # Can be GA-only ("Neredeyse bitti") or multi-field (email + SMS + GA)
            # Wait for page to settle after captcha
            totp_secret = credentials.get("totp_secret")
            await page.wait_for_timeout(3000)
            await self._debug_screenshot(page, "08_before_totp")

            # Wait for either "Google Authenticator kodu" label or a TOTP input
            ga_found = False
            for _attempt in range(10):
                try:
                    ga_label = page.get_by_text("Google Authenticator", exact=False)
                    if await ga_label.first.is_visible():
                        ga_found = True
                        break
                except Exception:
                    pass
                # Also check if we already left the login page
                if "/login" not in page.url and "giris" not in page.url:
                    logger.info("CoinTR: already past login page — skipping TOTP")
                    break
                await page.wait_for_timeout(2000)

            if ga_found and totp_secret:
                logger.info("CoinTR: Google Authenticator verification page detected")
                await self._debug_screenshot(page, "09_ga_page")

                # Check if email/SMS fields are also present (multi-field verification)
                has_email_field = False
                has_sms_field = False
                try:
                    email_field = page.locator('input[placeholder*="E-mail" i], input[placeholder*="mail Kod" i], input[placeholder*="posta" i]').first
                    has_email_field = await email_field.is_visible()
                except Exception:
                    pass
                try:
                    phone_field = page.locator('input[placeholder*="Doğrulama kodu al" i], input[placeholder*="Telefon" i], input[placeholder*="SMS" i]').first
                    has_sms_field = await phone_field.is_visible()
                except Exception:
                    pass

                logger.info(f"CoinTR: verification fields — email={has_email_field}, sms={has_sms_field}")

                # If email/SMS fields present, wait for user to submit those codes
                if has_email_field or has_sms_field:
                    logger.info("CoinTR: multi-field verification — waiting for user to submit email/SMS codes")
                    got_codes = await session.wait_for_verification_codes(timeout=300)
                    if not got_codes:
                        session.set_error("Verification codes not submitted in time")
                        return {"success": False, "message": "Verification timed out — submit email + SMS codes from the frontend"}

                    email_code = session.verification_codes.get("email_code", "")
                    sms_code = session.verification_codes.get("sms_code", "")
                    logger.info(f"CoinTR: received verification codes: email={email_code[:2]}**** sms={sms_code[:2]}****")

                    if has_email_field:
                        try:
                            await email_field.click(force=True)
                            await email_field.fill("")
                            await email_field.fill(email_code)
                            logger.info("CoinTR: filled email verification code")
                        except Exception as e:
                            logger.warning(f"CoinTR: email code fill failed: {e}")
                        await page.wait_for_timeout(300)

                    if has_sms_field:
                        try:
                            await phone_field.click(force=True)
                            await phone_field.fill("")
                            await phone_field.fill(sms_code)
                            logger.info("CoinTR: filled phone verification code")
                        except Exception as e:
                            logger.warning(f"CoinTR: phone code fill failed: {e}")
                        await page.wait_for_timeout(300)

                # Fill Google Authenticator code
                try:
                    ga_field = page.locator(
                        'input[placeholder*="GA Kodunu" i], '
                        'input[placeholder*="GA" i], '
                        'input[placeholder*="Google" i], '
                        'input[placeholder*="Authenticator" i]'
                    ).first
                    await ga_field.wait_for(state="visible", timeout=5000)
                    code = generate_totp_code(totp_secret)
                    logger.info(f"CoinTR: entering GA code {code[:2]}****")
                    await ga_field.click(force=True)
                    await ga_field.fill("")
                    await ga_field.fill(code)
                    logger.info(f"CoinTR: filled GA code {code[:2]}****")
                except Exception as e:
                    logger.warning(f"CoinTR: GA code fill failed: {e}")

                await page.wait_for_timeout(500)
                await self._debug_screenshot(page, "11_codes_entered")

                # Click Onayla (Confirm)
                try:
                    confirm_btn = page.locator('button:has-text("Onayla")').first
                    await confirm_btn.click(force=True, timeout=5000)
                    logger.info("CoinTR: clicked Onayla on verification page")
                except Exception as e:
                    logger.warning(f"CoinTR: Onayla click failed: {e}")

                await page.wait_for_timeout(5000)
                await self._debug_screenshot(page, "12_after_verify")

            # ── Step 7: Wait for redirect ──
            logger.info("CoinTR: waiting for login redirect...")
            try:
                await page.wait_for_url(
                    lambda url: "/login" not in url and "giris" not in url,
                    timeout=30000,
                )
            except Exception:
                current_url = page.url
                logger.warning(f"CoinTR: URL after wait: {current_url}")
                await self._debug_screenshot(page, "13_redirect_timeout")
                if "/login" in current_url or "giris" in current_url:
                    session.set_error("Login redirect timed out")
                    return {"success": False, "message": session.last_error}

            await page.wait_for_timeout(3000)
            await self._debug_screenshot(page, "13_after_redirect")

            # ── Step 8: Capture session cookie ──
            await self._capture_session_cookie(page, session)

            token = session.get_auth_token()
            if token:
                session.set_logged_in(session.captured_tokens)
                await browser_manager.save_storage_state(self.exchange_name)
                logger.info(f"CoinTR: login successful, session token captured ({len(token)} chars)")
                await self._debug_screenshot(page, "14_success")
                return {"success": True, "message": "Login successful, token captured"}
            else:
                # Try navigating to trigger API calls
                try:
                    await page.goto("https://www.cointr.com/tr/assets/spot", wait_until="domcontentloaded", timeout=15000)
                    await page.wait_for_timeout(3000)
                except Exception:
                    pass

                await self._capture_session_cookie(page, session)
                await self._debug_screenshot(page, "15_assets_page")
                token = session.get_auth_token()
                if token:
                    session.set_logged_in(session.captured_tokens)
                    await browser_manager.save_storage_state(self.exchange_name)
                    logger.info(f"CoinTR: token captured after assets page ({len(token)} chars)")
                    return {"success": True, "message": "Login successful, token captured"}
                else:
                    session.set_logged_in()
                    await browser_manager.save_storage_state(self.exchange_name)
                    logger.warning("CoinTR: logged in but no session token captured yet")
                    return {"success": True, "message": "Login successful but no session token captured yet"}

        except Exception as e:
            error_msg = f"Login failed: {str(e)}"
            logger.error(f"CoinTR: {error_msg}")
            await self._debug_screenshot(page, "99_error")
            # Close the stuck page so next get_page() creates a fresh one
            try:
                await page.close()
            except Exception:
                pass
            session._page = None
            session.set_error(error_msg)
            return {"success": False, "message": error_msg}

    # ── cookie consent ────────────────────────────────────────

    async def _dismiss_cookie_consent(self, page: Page) -> None:
        """Dismiss CoinTR cookie consent banner."""
        try:
            btn = page.locator('button:has-text("Kabul Et")').first
            await btn.wait_for(state="visible", timeout=5000)
            await btn.click(force=True, timeout=3000)
            logger.info("CoinTR: dismissed cookie consent")
            await page.wait_for_timeout(1000)
        except Exception:
            # Try JS fallback
            dismissed = await page.evaluate("""() => {
                const btns = document.querySelectorAll('button');
                for (const b of btns) {
                    if (b.textContent.includes('Kabul Et') || b.textContent.includes('Accept')) {
                        b.click();
                        return true;
                    }
                }
                return false;
            }""")
            if dismissed:
                logger.info("CoinTR: dismissed cookie consent via JS")
                await page.wait_for_timeout(1000)
            else:
                logger.debug("CoinTR: no cookie consent found")

    # ── captcha detection ────────────────────────────────────

    async def _check_captcha_visible(self, page: Page) -> bool:
        """Check if a captcha is visible (including slider captcha).
        Excludes the 2FA/TOTP verification page which also contains 'Doğrulama'."""
        # First check if we're on the TOTP/verification page — NOT a captcha
        for totp_text in ["Google Authenticator", "Neredeyse bitti", "GA Kodunu"]:
            try:
                loc = page.get_by_text(totp_text, exact=False)
                if await loc.first.is_visible():
                    logger.debug(f"CoinTR: '{totp_text}' visible — this is TOTP page, not captcha")
                    return False
            except Exception:
                pass

        for text in ["robot", "captcha", "Güvenlik", "Security", "puzzle", "Doğrulama", "Bulmacayı", "kaydırın"]:
            try:
                loc = page.get_by_text(text, exact=False)
                if await loc.first.is_visible():
                    logger.info(f"CoinTR: captcha detected via text '{text}'")
                    return True
            except Exception:
                pass
        try:
            iframe = page.locator('iframe[src*="captcha"], iframe[src*="recaptcha"], iframe[src*="geetest"]').first
            if await iframe.is_visible():
                logger.info("CoinTR: captcha detected via iframe")
                return True
        except Exception:
            pass
        return False

    # ── session cookie capture ────────────────────────────────

    async def _capture_session_cookie(self, page: Page, session: ExchangeSession) -> None:
        """Extract bt_newsessionid cookie from the browser context."""
        try:
            ctx = page.context
            cookies = await ctx.cookies(["https://www.cointr.com"])
            for cookie in cookies:
                if cookie["name"] == "bt_newsessionid":
                    value = cookie["value"]
                    if value and value != session.captured_tokens.get("bt_newsessionid"):
                        session.captured_tokens["bt_newsessionid"] = value
                        logger.info(f"CoinTR: captured bt_newsessionid cookie ({len(value)} chars)")
                    return
        except Exception as e:
            logger.warning(f"CoinTR: cookie capture failed: {e}")

    # ── request interceptor ────────────────────────────────────

    def _setup_request_interceptor(self, page: Page, session: ExchangeSession) -> None:
        """Capture auth tokens from CoinTR API requests."""

        def on_request(request: Request) -> None:
            if "cointr.com" not in request.url:
                return
            headers = request.headers
            # CoinTR uses cookies, but also check for auth headers
            auth = headers.get("authorization")
            if auth and auth != session.captured_tokens.get("authorization"):
                session.captured_tokens["authorization"] = auth
                logger.info(f"CoinTR: captured auth header ({len(auth)} chars)")

        page.on("request", on_request)

    # ── session check ──────────────────────────────────────────

    async def check_session(self, session: ExchangeSession) -> bool:
        """Check if session is still valid."""
        token = session.get_auth_token()
        if not token:
            return False

        try:
            cookies = {"bt_newsessionid": token}
            async with aiohttp.ClientSession() as http:
                async with http.get(
                    USER_INFO_URL,
                    cookies=cookies,
                    headers={"Accept": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("code") == "00000":
                            return True
                    return False
        except Exception as e:
            logger.warning(f"CoinTR session check failed: {e}")
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
                url = "https://www.cointr.com/en/fiat/cash-conversion"
                label = "Easy Buy/Sell"
            else:
                url = "https://www.cointr.com/en/markets"
                label = "Markets"

            await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            logger.info(f"CoinTR: keepalive — switched to {label}")
        except Exception as e:
            logger.debug(f"CoinTR: keepalive error: {e}")

    # ── TRY withdrawal ─────────────────────────────────────────

    async def withdraw_try(
        self,
        session: ExchangeSession,
        amount: float,
        iban: str,
        payment_account_id: str,
    ) -> dict:
        """
        Execute TRY withdrawal via CoinTR API (pre-check + confirm).
        payment_account_id is used as bank_card_id for CoinTR.
        """
        token = session.get_auth_token()
        if not token:
            return {"success": False, "order_id": None, "message": "No session token available"}

        cookies = {"bt_newsessionid": token}
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        # Extract bank code from IBAN — Turkish IBANs have 5-digit bank code at positions 4-8
        # e.g. TR030001500... → "00015" → strip leading zero → "0015" (Vakıfbank)
        if len(iban) >= 9:
            raw_code = iban[4:9]                       # 5-digit: "00015"
            bank_code = raw_code.lstrip("0").zfill(4)  # 4-digit: "0015"
        else:
            bank_code = "0206"
        bank_name = BANK_NAMES.get(bank_code, "")

        # Pre-check
        payload_precheck = {
            "channelCode": "BIRAPI",
            "currency": "TRY",
            "paymentMethod": "BANK_TRANSFER",
            "withdrawAmount": str(int(amount)),
            "bankCardId": payment_account_id,
            "bankCode": bank_code,
            "languageType": 0,
        }

        try:
            async with aiohttp.ClientSession() as http:
                # Step 1: Pre-check
                async with http.post(
                    PRECHECK_URL,
                    json=payload_precheck,
                    headers=headers,
                    cookies=cookies,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    try:
                        data = await resp.json()
                    except Exception:
                        text = await resp.text()
                        return {"success": False, "order_id": None, "message": f"Pre-check parse error: {text[:200]}"}

                    logger.info(f"CoinTR pre-check response: {json.dumps(data)}")
                    if data.get("code") != "00000":
                        return {"success": False, "order_id": None, "message": f"Pre-check failed: {data.get('msg', str(data))}"}

                await asyncio.sleep(0.5)

                # Step 2: Confirm
                payload_confirm = {
                    "accountNumber": iban,
                    "bankCardId": payment_account_id,
                    "bankCode": bank_code,
                    "bankName": bank_name,
                    "channelCode": "BIRAPI",
                    "currency": "TRY",
                    "languageType": 0,
                    "paymentMethod": "BANK_TRANSFER",
                    "transactionAmount": str(int(amount)),
                }

                async with http.post(
                    CONFIRM_URL,
                    json=payload_confirm,
                    headers=headers,
                    cookies=cookies,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    try:
                        data = await resp.json()
                    except Exception:
                        text = await resp.text()
                        return {"success": False, "order_id": None, "message": f"Confirm parse error: {text[:200]}"}

                    logger.info(f"CoinTR confirm response: {json.dumps(data)}")

                    if data.get("code") == "00000":
                        order_id = data.get("data", {}).get("orderId", "N/A")
                        return {
                            "success": True,
                            "order_id": order_id,
                            "message": "Withdrawal submitted",
                        }
                    else:
                        return {
                            "success": False,
                            "order_id": None,
                            "message": f"CoinTR error: {data.get('msg', str(data))}",
                        }

        except Exception as e:
            error_msg = f"Withdrawal request failed: {str(e)}"
            logger.error(f"CoinTR: {error_msg}")
            return {"success": False, "order_id": None, "message": error_msg}

    # ── travel rule (locked deposits) ─────────────────────────

    async def get_pending_travel_rules(self, session: ExchangeSession) -> dict:
        """
        Fetch locked deposits that need travel rule verification from CoinTR API.
        POST /v1/spot/capitalOrderListNoPage with bizType=1, status=27
        returns deposits with status "Locked" / "Kilitli" or "Processing" / "İşleniyor".
        We only return items that are still locked.
        """
        token = session.get_auth_token()
        if not token:
            return {"success": False, "pending": [], "message": "No auth token"}

        try:
            cookies = {"bt_newsessionid": token}
            payload = {"bizType": 1, "status": 27, "languageType": 8}
            async with aiohttp.ClientSession() as http:
                async with http.post(
                    self.LOCKED_DEPOSITS_URL,
                    json=payload,
                    cookies=cookies,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    data = await resp.json()

            code = str(data.get("code", ""))
            if code not in ("00000", "200"):
                msg = data.get("msg", str(data))
                return {"success": False, "pending": [], "message": f"API error: {msg}"}

            # Data is nested under data.capitalOrderInfoResults
            inner = data.get("data", {})
            if isinstance(inner, dict):
                items = inner.get("capitalOrderInfoResults", []) or []
            else:
                items = inner if isinstance(inner, list) else []

            pending = []
            for item in items:
                # statusDesc contains the status label (English: "Locked", "Processing";
                # Turkish with languageType=8: "Kilitli", "İşleniyor")
                status_str = item.get("statusDesc", item.get("statusStr", ""))
                # Only include items that are still locked, not processing
                status_lower = status_str.lower()
                if "processing" in status_lower or "işleniyor" in status_lower or "isleniyor" in status_lower:
                    continue

                order_id = str(item.get("orderId", item.get("id", "")))
                pending.append({
                    "travel_rule_id": order_id,
                    "currency": item.get("coinName", item.get("coin", item.get("currency", ""))),
                    "amount": str(item.get("amount", item.get("totalAmount", ""))),
                    "status": status_str,
                })

            logger.info(f"CoinTR: found {len(pending)} pending travel rule items (locked deposits)")
            return {"success": True, "pending": pending}

        except Exception as e:
            logger.error(f"CoinTR: failed to fetch locked deposits: {e}")
            return {"success": False, "pending": [], "message": str(e)}

    async def confirm_travel_rule(
        self,
        session: ExchangeSession,
        travel_rule_id: str,
        source_exchange: str,
    ) -> dict:
        """
        Complete the travel rule unlock form for a locked CoinTR deposit
        via browser UI automation.

        Steps:
        1. Navigate to https://www.cointr.com/tr/asset/locked
        2. Click "Kilidi Aç" (Unlock)
        3. Select "Diğer" (Other) from the fund source dropdown
        4. Fill the textarea with a reason (min 20 chars)
        5. Click "Gönder" (Submit)
        """
        try:
            page = await session.get_page()
            current_url = page.url
            if "/login" in current_url or "about:blank" in current_url:
                return {"success": False, "message": "Browser not logged in (on login page)"}
        except Exception as e:
            return {"success": False, "message": f"Failed to get page: {e}"}

        logger.info(f"CoinTR: starting UI-based travel rule confirm for {travel_rule_id}")

        try:
            # Step 1: Navigate to locked assets page
            logger.info("CoinTR travel rule step 1: navigating to locked assets")
            await page.goto(
                "https://www.cointr.com/tr/asset/locked",
                wait_until="domcontentloaded",
                timeout=15000,
            )
            await page.wait_for_timeout(2000)
            await self._debug_screenshot(page, "tr_01_locked_page")

            # Step 2: Click "Kilidi Aç" (Unlock) — click the first one
            logger.info("CoinTR travel rule step 2: clicking Kilidi Aç")
            unlock_link = page.get_by_text("Kilidi Aç", exact=False).first
            await unlock_link.click(timeout=5000)
            await page.wait_for_timeout(1000)
            await self._debug_screenshot(page, "tr_02_modal_open")

            # Step 3: Click the fund source dropdown
            logger.info("CoinTR travel rule step 3: opening fund source dropdown")
            await page.click("input[placeholder='Bir seçim yapın']", timeout=5000)
            await page.wait_for_timeout(500)

            # Step 4: Select "Diğer" (Other)
            logger.info("CoinTR travel rule step 4: selecting Diğer")
            await page.get_by_text("Diğer", exact=True).first.click(timeout=5000)
            await page.wait_for_timeout(500)
            await self._debug_screenshot(page, "tr_03_diger_selected")

            # Step 5: Fill the textarea with a reason (min 20 chars)
            logger.info("CoinTR travel rule step 5: filling reason textarea")
            await page.fill(
                "textarea.el-textarea__inner",
                "baska fiyattan islem yapmak",
                timeout=5000,
            )
            await page.wait_for_timeout(500)
            await self._debug_screenshot(page, "tr_04_reason_filled")

            # Step 6: Click submit ("Gönder")
            logger.info("CoinTR travel rule step 6: clicking submit")
            await page.click("button.foot-btn.submit", timeout=5000)
            await page.wait_for_timeout(3000)
            await self._debug_screenshot(page, "tr_05_after_submit")

            # Check result: if "Kilidi Aç" is gone or status changed to "İşleniyor"
            try:
                still_locked = await page.get_by_text("Kilidi Aç", exact=False).first.is_visible()
            except Exception:
                still_locked = False

            processing_visible = False
            try:
                processing_visible = await page.get_by_text("İşleniyor", exact=False).first.is_visible()
            except Exception:
                pass

            if not still_locked or processing_visible:
                logger.info(f"CoinTR: travel rule COMPLETED for {travel_rule_id}")
                return {
                    "success": True,
                    "message": "Travel rule unlock submitted — status changing to İşleniyor",
                    "travel_rule_id": travel_rule_id,
                }
            else:
                logger.warning("CoinTR: travel rule may have failed — Kilidi Aç still visible")
                return {
                    "success": False,
                    "message": "Travel rule form submitted but Kilidi Aç still visible",
                }

        except Exception as e:
            error_msg = f"Travel rule UI automation failed: {e}"
            logger.error(f"CoinTR: {error_msg}")
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
        """Confirm deposit via travel rule unlock. platform_name is ignored for CoinTR
        (the form doesn't ask which exchange sent the funds)."""
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
        page = await session.get_page()
        try:
            return await page.screenshot(full_page=False, timeout=10000)
        except Exception as e:
            logger.error(f"Screenshot failed: {e}")
            # Page is likely stuck — close it so next call gets a fresh one
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
