"""
WhiteBIT TR browser automation — login, token capture, TRY withdrawal.

Login flow:
  1. Navigate to login page
  2. Fill email + password, submit
  3. Handle 2FA code (TOTP — Google Authenticator)
  4. Wait for redirect, capture JWT token
  5. Save storage state

Token capture:
  JWT token is obtained from GET https://account.whitebit-tr.com/auth/cookie/jwt
  after the browser is authenticated (cookie-based auth → JWT).

Withdrawal:
  POST https://internal.whitebit-tr.com/v2/withdraw
  Body: {amount, ticker, address, withFee}
  Auth: Bearer token in Authorization header
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

LOGIN_URL = "https://whitebit-tr.com/auth/login"
JWT_URL = "https://account.whitebit-tr.com/auth/cookie/jwt"
WITHDRAW_URL = "https://internal.whitebit-tr.com/v2/withdraw"
VERIFIED_ADDRESSES_URL = "https://internal.whitebit-tr.com/v2/verified-addresses"
DEPOSITS_URL = "https://whitebit-tr.com/history/main/crypto-transfer"
DEPOSIT_HISTORY_API_URL = "https://internal.whitebit-tr.com/v2/history/deposits"
SANCTUM_CSRF_URL = "https://internal.whitebit-tr.com/sanctum/csrf-cookie"

# Exchange name mapping for the SumSub KVHS dropdown.
# Names may need adjustment after verifying the actual dropdown options.
TRAVEL_RULE_EXCHANGE_NAMES = {
    "binance_tr": "Binance TR",
    "paribu": "Paribu",
    "btcturk": "BTCTurk",
    "cointr": "CoinTR",
    "okx_tr": "OKX",
    "whitebit_tr": "WhiteBIT",
    "kucoin_tr": "KuCoin",
    "htx": "HTX",
}

COMPANY_NAME = "Pairextr Teknoloji ve Yazilim AS"

DEBUG_DIR = "/app/data/debug"


class WhiteBitTRAutomation(BaseExchangeAutomation):
    exchange_name = "whitebit_tr"
    confirm_deposit_needs_browser = True

    # ── debug helper ──────────────────────────────────────────

    async def _debug_screenshot(self, page: Page, label: str) -> None:
        try:
            os.makedirs(DEBUG_DIR, exist_ok=True)
            path = os.path.join(DEBUG_DIR, f"whitebit_tr_{label}.png")
            await page.screenshot(path=path, full_page=False)
            logger.info(f"WhiteBIT TR: [DEBUG] screenshot saved: {label}.png (url={page.url})")
        except Exception as e:
            logger.warning(f"WhiteBIT TR: [DEBUG] screenshot failed for {label}: {e}")

    # ── login ──────────────────────────────────────────────────

    async def login(self, session: ExchangeSession, credentials: Dict[str, str]) -> dict:
        """
        WhiteBIT TR login flow:
        1. Navigate to login page
        2. Fill email + password, submit
        3. Handle 2FA (TOTP)
        4. Wait for redirect, capture JWT, save storage
        """
        session.status = "logging_in"
        page = await session.get_page()

        try:
            # Set up token interceptor before navigation
            self._setup_request_interceptor(page, session)

            # Check if already logged in
            try:
                current_url = page.url
                token = session.get_auth_token()
                if token and "/auth/" not in current_url and "about:blank" not in current_url:
                    logger.info(f"WhiteBIT TR: browser already on {current_url} with token — verifying")
                    if await self.check_session(session):
                        session.set_logged_in(session.captured_tokens)
                        logger.info("WhiteBIT TR: already logged in — skipping login flow")
                        return {"success": True, "message": "Already logged in"}
                    else:
                        logger.info("WhiteBIT TR: token expired, proceeding with fresh login")
            except Exception:
                pass

            # ── Navigate to login page ──
            logger.info("WhiteBIT TR: navigating to login page")
            await page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_timeout(3000)
            await self._debug_screenshot(page, "01_page_loaded")

            # ── Wait for Cloudflare/security check to pass ──
            # WhiteBIT shows "Security check" interstitial that auto-resolves
            for attempt in range(30):  # up to ~60 seconds
                # If page URL changed away from login, security check is done
                current_url = page.url
                if "/auth/" not in current_url and "login" not in current_url and "about:blank" not in current_url:
                    logger.info(f"WhiteBIT TR: page navigated to {current_url} — security check passed")
                    await self._debug_screenshot(page, "01b_after_security_check")
                    break
                try:
                    body_text = await page.locator("body").inner_text(timeout=5000)
                except Exception:
                    body_text = ""
                if "security check" in body_text.lower() or "insan olduğunuz doğrulanıyor" in body_text.lower():
                    if attempt == 0:
                        logger.info("WhiteBIT TR: security check detected — waiting for it to pass")
                        session.status = "waiting_for_captcha"
                    await page.wait_for_timeout(2000)
                else:
                    if attempt > 0:
                        logger.info(f"WhiteBIT TR: security check passed after {attempt * 2}s")
                        await self._debug_screenshot(page, "01b_after_security_check")
                    break
            else:
                logger.warning("WhiteBIT TR: security check did not pass after 60s")
                await self._debug_screenshot(page, "01c_security_check_stuck")
                session.set_error("Security check stuck — may need human intervention")
                return {"success": False, "message": "Security check did not pass after 60s"}

            session.status = "logging_in"

            # ── Dismiss cookie consent banner ──
            try:
                cookie_btn = page.locator('button:has-text("tümünü kabul et"), button:has-text("Tümünü Kabul Et"), button:has-text("Tümünü kabul et")')
                if await cookie_btn.count() > 0:
                    await cookie_btn.first.click(force=True)
                    logger.info("WhiteBIT TR: dismissed cookie banner")
                    await page.wait_for_timeout(1000)
            except Exception:
                pass  # no cookie banner or already dismissed

            # Check if cookies caused auto-redirect (already logged in)
            current_url = page.url
            if "/auth/" not in current_url:
                logger.info(f"WhiteBIT TR: cookies auto-logged in — redirected to {current_url}")
                await page.wait_for_timeout(3000)
                jwt = await self._fetch_jwt(session)
                if jwt:
                    session.set_logged_in(session.captured_tokens)
                    await browser_manager.save_storage_state(self.exchange_name)
                    return {"success": True, "message": "Auto-login via saved cookies, token captured"}
                else:
                    session.set_logged_in()
                    await browser_manager.save_storage_state(self.exchange_name)
                    return {"success": True, "message": "Auto-login via cookies but no JWT captured yet"}

            # ── Step 1: Fill email ──
            email_addr = credentials["email"]
            logger.info(f"WhiteBIT TR: entering email ***{email_addr[-10:]}")

            email_input = page.locator('input[type="email"], input[name="email"], input[autocomplete="email"], input[placeholder*="mail"], input[placeholder*="Mail"]').first
            await email_input.wait_for(state="visible", timeout=10000)
            await email_input.click(force=True)
            await email_input.fill(email_addr)
            await page.wait_for_timeout(500)
            await self._debug_screenshot(page, "02_email_entered")

            # ── Step 2: Fill password ──
            logger.info("WhiteBIT TR: entering password")
            password_input = page.locator('input[type="password"]').first
            await password_input.wait_for(state="visible", timeout=5000)
            await password_input.click(force=True)
            await password_input.fill(credentials["password"])
            await page.wait_for_timeout(500)
            await self._debug_screenshot(page, "03_password_entered")

            # ── Step 3: Intercept login API to handle reCAPTCHA low_score ──
            # The SPA's reCAPTCHA Enterprise often fails with low_score on first try.
            # We intercept the /v2/login response: if 422 low_score, we make our own
            # direct API call (which retries and succeeds), then fulfill the SPA's
            # request with the successful response. The SPA then shows the 2FA modal.
            login_intercepted = asyncio.Event()
            login_response_data = {}

            async def _intercept_login(route):
                """Intercept /v2/login — if low_score, retry via our own API call."""
                try:
                    response = await route.fetch()
                    status = response.status
                    body_text = await response.text()
                    logger.info(f"WhiteBIT TR: intercepted login response: {status} {body_text[:200]}")

                    if status == 200:
                        # SPA's own call succeeded — pass through
                        login_response_data["body"] = body_text
                        login_response_data["status"] = 200
                        login_intercepted.set()
                        await route.fulfill(response=response)
                        return

                    body = json.loads(body_text) if body_text else {}
                    if status == 422 and body.get("errors", {}).get("low_score"):
                        logger.info("WhiteBIT TR: SPA got low_score — retrying via direct API")
                        # Make our own direct API call with a fresh reCAPTCHA token
                        for attempt in range(3):
                            await asyncio.sleep(2)
                            result = await page.evaluate(
                                """async (creds) => {
                                    try {
                                        await new Promise(r => grecaptcha.enterprise.ready(r));
                                        const token = await grecaptcha.enterprise.execute(0);
                                        const xsrf = document.cookie.match(/XSRF-TOKEN=([^;]+)/);
                                        const csrf = xsrf ? decodeURIComponent(xsrf[1]) : '';
                                        const resp = await fetch('https://internal.whitebit-tr.com/v2/login', {
                                            method: 'POST',
                                            headers: {
                                                'Content-Type': 'application/json',
                                                'X-XSRF-TOKEN': csrf,
                                                'Accept': 'application/json',
                                            },
                                            credentials: 'include',
                                            body: JSON.stringify({
                                                email: creds.email,
                                                password: creds.password,
                                                'g-recaptcha-response': token
                                            })
                                        });
                                        return {status: resp.status, body: await resp.text()};
                                    } catch(e) {
                                        return {error: e.message};
                                    }
                                }""",
                                {"email": credentials["email"], "password": credentials["password"]},
                            )
                            logger.info(f"WhiteBIT TR: direct API attempt {attempt+1}: {result.get('status')} {str(result.get('body',''))[:150]}")
                            if result.get("status") == 200:
                                # Feed the successful response back to the SPA
                                login_response_data["body"] = result["body"]
                                login_response_data["status"] = 200
                                login_intercepted.set()
                                await route.fulfill(
                                    status=200,
                                    content_type="application/json",
                                    body=result["body"],
                                )
                                return
                            r_body = json.loads(result.get("body", "{}")) if result.get("body") else {}
                            if not r_body.get("errors", {}).get("low_score"):
                                break  # non-retryable error

                        # All retries failed — pass through original error
                        login_response_data["status"] = status
                        login_intercepted.set()
                        await route.fulfill(response=response)
                    else:
                        # Other error — pass through
                        login_response_data["body"] = body_text
                        login_response_data["status"] = status
                        login_intercepted.set()
                        await route.fulfill(response=response)
                except Exception as e:
                    logger.warning(f"WhiteBIT TR: intercept error: {e}")
                    login_intercepted.set()
                    try:
                        await route.continue_()
                    except Exception:
                        pass

            await page.route("**/v2/login", _intercept_login)

            # ── Step 4: Click submit — SPA handles reCAPTCHA, we intercept response ──
            try:
                submit_btn = page.locator('button[type="submit"]:visible').first
                await submit_btn.click(timeout=5000)
                logger.info("WhiteBIT TR: clicked submit (Devam et)")
            except Exception:
                await page.evaluate("""() => {
                    const btn = document.querySelector('button[type="submit"]');
                    if (btn) btn.click();
                }""")

            # Wait for either the 2FA modal or redirect (up to 120s)
            logger.info("WhiteBIT TR: waiting for login + 2FA modal...")
            totp_secret = credentials.get("totp_secret")
            twofa_modal = False
            redirected = False

            for i in range(120):
                await page.wait_for_timeout(1000)

                # Check for 2FA modal — broader detection
                has_modal = await page.evaluate("""() => {
                    // Check for input with placeholder 000000
                    if (document.querySelector('input[placeholder="000000"]')) return true;
                    // Check for Confirmation text in any modal/overlay
                    const text = document.body.innerText;
                    if (text.includes('Confirmation') && text.includes('2FA')) return true;
                    if (text.includes('Authenticator')) return true;
                    // Check for new input elements beyond email/password
                    const inputs = document.querySelectorAll('input:not([type="email"]):not([type="password"]):not([type="hidden"])');
                    for (const inp of inputs) {
                        if (inp.offsetParent !== null) return true;  // visible non-email/password input
                    }
                    return false;
                }""")
                if has_modal:
                    logger.info(f"WhiteBIT TR: 2FA modal detected after {i+1}s")
                    twofa_modal = True
                    break

                if "/auth/" not in page.url:
                    logger.info(f"WhiteBIT TR: redirected to {page.url}")
                    redirected = True
                    break

                if i % 15 == 14:
                    await self._debug_screenshot(page, f"04_waiting_{i+1}s")
                    logger.info(f"WhiteBIT TR: still waiting after {i+1}s...")

            # Remove the route interceptor
            try:
                await page.unroute("**/v2/login")
            except Exception:
                pass

            if not twofa_modal and not redirected:
                await self._debug_screenshot(page, "04_timeout")
                session.set_error("Login timed out after 120s")
                return {"success": False, "message": session.last_error}

            await self._debug_screenshot(page, "04_login_done")

            # ── Step 5: Handle 2FA modal ──
            if twofa_modal:
                if not totp_secret:
                    session.set_error("2FA required but no TOTP secret configured")
                    return {"success": False, "message": session.last_error}

                code = generate_totp_code(totp_secret)
                logger.info(f"WhiteBIT TR: TOTP code {code[:2]}****")
                await self._debug_screenshot(page, "05_2fa_modal")

                # Fill 2FA code — try multiple selectors
                filled = False
                for selector in ['input[placeholder="000000"]', 'input:not([type="email"]):not([type="password"]):not([type="hidden"]):visible']:
                    try:
                        inp = page.locator(selector).first
                        await inp.wait_for(state="visible", timeout=3000)
                        await inp.click(force=True)
                        await inp.fill("")
                        await inp.fill(code)
                        logger.info(f"WhiteBIT TR: filled 2FA code via {selector}")
                        filled = True
                        break
                    except Exception:
                        continue

                if not filled:
                    await page.keyboard.type(code, delay=80)
                    logger.warning("WhiteBIT TR: typed 2FA via keyboard")

                await page.wait_for_timeout(500)
                await self._debug_screenshot(page, "06_2fa_entered")

                # Click "Onayla" (Confirm)
                try:
                    confirm_btn = page.locator(
                        'button:has-text("Onayla"):visible, '
                        'button:has-text("Confirm"):visible'
                    ).first
                    await confirm_btn.click(force=True, timeout=5000)
                    logger.info("WhiteBIT TR: clicked Onayla")
                except Exception:
                    await page.keyboard.press("Enter")
                    logger.warning("WhiteBIT TR: pressed Enter as fallback")

                # Wait for redirect after 2FA
                for i in range(30):
                    await page.wait_for_timeout(1000)
                    if "/auth/" not in page.url:
                        logger.info(f"WhiteBIT TR: redirected after 2FA in {i+1}s")
                        break
                await page.wait_for_timeout(2000)
                await self._debug_screenshot(page, "07_after_2fa")

            # ── Step 6: Wait for redirect / session to be established ──
            logger.info("WhiteBIT TR: waiting for post-login state...")
            # Reload the page — cookies should now be set from the API call
            await page.goto("https://whitebit-tr.com/", wait_until="domcontentloaded", timeout=15000)
            await page.wait_for_timeout(3000)
            await self._debug_screenshot(page, "09_after_redirect")

            # ── Step 6: Capture JWT token ──
            jwt = await self._fetch_jwt(session)
            if jwt:
                session.set_logged_in(session.captured_tokens)
                await browser_manager.save_storage_state(self.exchange_name)
                logger.info(f"WhiteBIT TR: login successful, JWT captured ({len(jwt)} chars)")
                return {"success": True, "message": "Login successful, token captured"}
            else:
                # Try navigating to a page that triggers API calls
                logger.info("WhiteBIT TR: no JWT yet, navigating to main page to trigger API calls")
                try:
                    await page.goto("https://whitebit-tr.com/balances/spot", wait_until="domcontentloaded", timeout=15000)
                    await page.wait_for_timeout(3000)
                except Exception:
                    pass

                jwt = await self._fetch_jwt(session)
                if jwt:
                    session.set_logged_in(session.captured_tokens)
                    await browser_manager.save_storage_state(self.exchange_name)
                    logger.info(f"WhiteBIT TR: JWT captured after navigation ({len(jwt)} chars)")
                    return {"success": True, "message": "Login successful, token captured"}
                else:
                    # Check if any token was captured via interceptor
                    token = session.get_auth_token()
                    if token:
                        session.set_logged_in(session.captured_tokens)
                        await browser_manager.save_storage_state(self.exchange_name)
                        return {"success": True, "message": "Login successful, token captured via interceptor"}

                    session.set_logged_in()
                    await browser_manager.save_storage_state(self.exchange_name)
                    logger.warning("WhiteBIT TR: logged in but no JWT captured yet")
                    return {"success": True, "message": "Login successful but no API token captured yet"}

        except Exception as e:
            error_msg = f"Login failed: {str(e)}"
            logger.error(f"WhiteBIT TR: {error_msg}")
            await self._debug_screenshot(page, "99_error")
            try:
                await page.close()
            except Exception:
                pass
            session._page = None
            session.set_error(error_msg)
            return {"success": False, "message": error_msg}

    # ── JWT fetcher ──────────────────────────────────────────

    async def _fetch_jwt(self, session: ExchangeSession) -> Optional[str]:
        """
        Fetch JWT from WhiteBIT's cookie-to-JWT endpoint.
        The browser is already authenticated via cookies, so this endpoint
        returns a JWT when called with those cookies.
        """
        page = await session.get_page()
        try:
            # Use the browser's cookie context to call the JWT endpoint
            response = await page.evaluate("""async () => {
                try {
                    const resp = await fetch('https://account.whitebit-tr.com/auth/cookie/jwt', {
                        credentials: 'include',
                    });
                    if (!resp.ok) return null;
                    const data = await resp.json();
                    return data.data ? data.data.token : null;
                } catch(e) {
                    return null;
                }
            }""")

            if response:
                session.captured_tokens["authorization"] = f"Bearer {response}"
                logger.info(f"WhiteBIT TR: captured JWT token ({len(response)} chars)")
                return response
            return None
        except Exception as e:
            logger.warning(f"WhiteBIT TR: JWT fetch failed: {e}")
            return None

    # ── request interceptor ────────────────────────────────────

    def _setup_request_interceptor(self, page: Page, session: ExchangeSession) -> None:
        """Capture authorization headers from WhiteBIT API requests."""

        def on_request(request: Request) -> None:
            url = request.url
            if "whitebit" not in url:
                return

            headers = request.headers
            auth = headers.get("authorization")
            if auth and auth != session.captured_tokens.get("authorization"):
                session.captured_tokens["authorization"] = auth
                logger.info(f"WhiteBIT TR: captured auth header from request ({len(auth)} chars)")

        page.on("request", on_request)

    # ── session check ──────────────────────────────────────────

    async def check_session(self, session: ExchangeSession) -> bool:
        """Check if session is still valid by fetching a fresh JWT."""
        try:
            jwt = await self._fetch_jwt(session)
            return jwt is not None
        except Exception as e:
            logger.warning(f"WhiteBIT TR session check failed: {e}")
            return False

    # ── keepalive ──────────────────────────────────────────────

    async def keepalive(self, session: ExchangeSession) -> None:
        """Navigate between tabs to keep the SPA alive."""
        try:
            page = await session.get_page()
            current_url = page.url
            if "/login" in current_url or "about:blank" in current_url:
                return

            if "/balance" in current_url:
                url = "https://whitebit-tr.com/analytics/account"
                label = "Analytics"
            else:
                url = "https://whitebit-tr.com/balance/total"
                label = "Cüzdan"

            await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            logger.info(f"WhiteBIT TR: keepalive — switched to {label}")
        except Exception as e:
            logger.debug(f"WhiteBIT TR: keepalive error: {e}")

    # ── TRY withdrawal ─────────────────────────────────────────

    async def withdraw_try(
        self,
        session: ExchangeSession,
        amount: float,
        iban: str,
        payment_account_id: str,
    ) -> dict:
        """
        Execute TRY withdrawal via the WhiteBIT TR API.

        Uses:
          POST https://internal.whitebit-tr.com/v2/withdraw
          Body: {amount, ticker, address, withFee}

        The ticker for TRY fiat withdrawal is "TRY_BIR_TURKEY_FINANCE".
        The address is the IBAN.
        """
        # Refresh JWT before withdrawal
        jwt = await self._fetch_jwt(session)
        if not jwt:
            token = session.get_auth_token()
            if not token:
                return {"success": False, "order_id": None, "message": "No auth token available"}
        else:
            token = f"Bearer {jwt}"

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": token,
        }

        payload = {
            "amount": str(int(amount)),
            "ticker": "TRY_BIR_TURKEY_FINANCE",
            "address": iban,
            "withFee": False,
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
                        logger.error(f"WhiteBIT TR withdraw response parse error: {text[:500]}")
                        return {"success": False, "order_id": None, "message": f"Response parse error: {text[:200]}"}

                    logger.info(f"WhiteBIT TR withdraw response (amount={amount}): status={resp.status} body={json.dumps(data)}")

                    if resp.status == 200:
                        order_id = data.get("data", {}).get("id") if isinstance(data.get("data"), dict) else None
                        return {
                            "success": True,
                            "order_id": str(order_id) if order_id else None,
                            "message": "Withdrawal submitted",
                        }
                    else:
                        error_msg = data.get("message", str(data))
                        if isinstance(error_msg, dict):
                            error_msg = error_msg.get("message", str(error_msg))
                        return {
                            "success": False,
                            "order_id": None,
                            "message": f"WhiteBIT TR error ({resp.status}): {error_msg}",
                        }

        except Exception as e:
            error_msg = f"Withdrawal request failed: {str(e)}"
            logger.error(f"WhiteBIT TR: {error_msg}")
            return {"success": False, "order_id": None, "message": error_msg}

    # ── helper: fetch verified addresses ────────────────────────

    async def get_verified_addresses(self, session: ExchangeSession) -> list:
        """Fetch the list of verified IBAN addresses for TRY withdrawal."""
        jwt = await self._fetch_jwt(session)
        if not jwt:
            token = session.get_auth_token()
            if not token:
                return []
        else:
            token = f"Bearer {jwt}"

        try:
            async with aiohttp.ClientSession() as http:
                async with http.get(
                    VERIFIED_ADDRESSES_URL,
                    headers={"Authorization": token},
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("data", [])
                    return []
        except Exception as e:
            logger.warning(f"WhiteBIT TR: failed to fetch verified addresses: {e}")
            return []

    # ── travel rule / deposit confirmation ─────────────────────

    async def get_pending_travel_rules(self, session: ExchangeSession) -> dict:
        """
        Fetch pending deposits needing travel rule verification from WhiteBIT TR.

        Uses the internal API: GET /v2/history/deposits?status=travel_rule_frozen
        This avoids browser navigation which triggers Cloudflare.
        """
        try:
            page = await session.get_page()
            current_url = page.url
            if "/auth/" in current_url or "about:blank" in current_url:
                return {"success": False, "pending": [], "message": "Not logged in"}
        except Exception as e:
            return {"success": False, "pending": [], "message": f"Failed to get page: {e}"}

        try:
            logger.info("WhiteBIT TR: fetching pending travel rules via API")

            # Use the browser's JS context to call the internal API
            # (leverages existing session cookies, avoids Cloudflare)
            deposits = await page.evaluate("""async () => {
                try {
                    const r = await fetch(
                        'https://internal.whitebit-tr.com/v2/history/deposits?status=travel_rule_frozen',
                        {
                            method: 'GET',
                            headers: {'Accept': 'application/json'},
                            credentials: 'include'
                        }
                    );
                    if (!r.ok) return {error: 'HTTP ' + r.status};
                    const d = await r.json();
                    return d;
                } catch(e) {
                    return {error: e.message};
                }
            }""")

            if not deposits or deposits.get("error"):
                error_msg = deposits.get("error", "Unknown error") if deposits else "No response"
                logger.warning(f"WhiteBIT TR: API call failed: {error_msg}")
                return {"success": False, "pending": [], "message": error_msg}

            items = deposits.get("data", [])
            pending = []
            for item in items:
                pending.append({
                    "travel_rule_id": item.get("id", ""),
                    "currency": item.get("ticker", ""),
                    "amount": item.get("amount", "0"),
                    "network": item.get("network", ""),
                    "status": "travel_rule_frozen",
                    "hash": item.get("hash", ""),
                    "created_at": item.get("createdAt", ""),
                })

            logger.info(f"WhiteBIT TR: found {len(pending)} pending travel rule items")
            return {"success": True, "pending": pending}

        except Exception as e:
            logger.error(f"WhiteBIT TR: failed to fetch pending travel rules: {e}")
            return {"success": False, "pending": [], "message": str(e)}

    async def _ensure_page_ready(self, page: Page) -> bool:
        """Wait for the page to be past Cloudflare security check.

        Returns True if the page is ready (not stuck on security check),
        False if it's still blocked after waiting.
        """
        for attempt in range(15):
            body_text = await page.evaluate(
                "() => (document.body ? document.body.innerText : '').substring(0, 200)"
            )
            if "Security check" not in body_text and "Bir dakika" not in body_text:
                return True
            logger.info(
                f"WhiteBIT TR: page stuck on Cloudflare security check, "
                f"waiting... (attempt {attempt + 1}/15)"
            )
            await asyncio.sleep(2)
        return False

    async def _navigate_spa(self, page: Page, target_path: str) -> bool:
        """Navigate within the WhiteBIT SPA without full page.goto.

        Uses Vue Router push if available, falls back to history.pushState
        + dispatchEvent. Returns True if navigation succeeded.
        """
        current_url = page.url
        # If already on the target path, no navigation needed
        if target_path in current_url:
            return True

        navigated = await page.evaluate("""async (path) => {
            // Try Vue Router first
            const app = document.querySelector('#app');
            if (app) {
                const vueApp = app.__vue_app__;
                if (vueApp) {
                    const router = vueApp.config?.globalProperties?.$router;
                    if (router) {
                        try {
                            await router.push(path);
                            return true;
                        } catch(e) { /* fall through */ }
                    }
                }
            }
            // Fallback: use window.location (triggers SPA router if configured)
            try {
                window.location.href = path;
                return true;
            } catch(e) {
                return false;
            }
        }""", target_path)

        if navigated:
            await asyncio.sleep(2)
        return bool(navigated)

    async def confirm_travel_rule(
        self,
        session: ExchangeSession,
        travel_rule_id: str,
        source_exchange: str,
    ) -> dict:
        """
        Complete the travel rule verification for a pending WhiteBIT TR deposit.

        Flow:
        1. Navigate to crypto-transfer history (SPA navigation to avoid Cloudflare)
        2. Find row with "Doğrulama bekleniyor" and click it
        3. Click "Doğrula" button → SumSub form opens in a new tab
        4. Complete the SumSub multi-step form
        5. Close SumSub tab, return to main page
        """
        try:
            page = await session.get_page()
            current_url = page.url
            if "/auth/" in current_url or "about:blank" in current_url:
                return {"success": False, "message": "Browser not logged in (on login page)"}
        except Exception as e:
            return {"success": False, "message": f"Failed to get page: {e}"}

        logger.info(
            f"WhiteBIT TR: starting travel rule confirm for id={travel_rule_id} "
            f"(source={source_exchange})"
        )

        sumsub_page = None

        try:
            # Step 1: Ensure page is not stuck on Cloudflare
            logger.info("WhiteBIT TR travel rule step 1: checking page state")
            page_ready = await self._ensure_page_ready(page)
            if not page_ready:
                await self._debug_screenshot(page, "tr_01_cloudflare_stuck")
                return {
                    "success": False,
                    "message": "Page stuck on Cloudflare security check. "
                    "Please manually navigate the browser past the security check first.",
                }

            # Step 2: Navigate to crypto-transfer history via SPA
            logger.info("WhiteBIT TR travel rule step 2: navigating to crypto-transfer history")
            await self._navigate_spa(page, "/history/main/crypto-transfer")
            await asyncio.sleep(3)
            await self._debug_screenshot(page, "tr_02_crypto_transfer_page")

            # Step 3: Find and click the row with "Doğrulama bekleniyor"
            logger.info("WhiteBIT TR travel rule step 3: finding pending verification row")
            verification_rows = page.get_by_text("Doğrulama bekleniyor", exact=False)
            count = await verification_rows.count()
            logger.info(f"WhiteBIT TR: found {count} rows with 'Doğrulama bekleniyor'")

            if count == 0:
                await self._debug_screenshot(page, "tr_03_no_pending_rows")
                return {"success": False, "message": "No rows with 'Doğrulama bekleniyor' found on crypto-transfer page"}

            # Match by travel_rule_id (row index) if it's a number, otherwise take first
            target_idx = 0
            try:
                target_idx = int(travel_rule_id)
            except (ValueError, TypeError):
                pass
            target_idx = min(target_idx, count - 1)

            await verification_rows.nth(target_idx).click(timeout=5000)
            await asyncio.sleep(2)
            await self._debug_screenshot(page, "tr_04_row_clicked")

            # Step 4: Click "Doğrula" (Verify) button
            logger.info("WhiteBIT TR travel rule step 4: clicking Doğrula button")
            verify_btn = page.get_by_text("Doğrula", exact=False).first
            await verify_btn.wait_for(state="visible", timeout=5000)

            # Set up listener for new tab BEFORE clicking the button
            context = page.context
            async with context.expect_page(timeout=15000) as new_page_info:
                await verify_btn.click(timeout=5000)

            sumsub_page = await new_page_info.value
            await sumsub_page.wait_for_load_state("domcontentloaded", timeout=15000)
            await asyncio.sleep(3)
            await self._debug_screenshot(sumsub_page, "tr_05_sumsub_opened")
            logger.info(f"WhiteBIT TR: SumSub tab opened: {sumsub_page.url}")

            # Step 5: Click "Devam Et" (Continue) in SumSub
            logger.info("WhiteBIT TR travel rule step 5: clicking Devam Et")
            await asyncio.sleep(2)
            devam_btn = sumsub_page.get_by_text("Devam Et", exact=False).first
            await devam_btn.click(timeout=10000)
            await asyncio.sleep(2)
            await self._debug_screenshot(sumsub_page, "tr_06_after_devam")

            # Step 6: "Bu sizin kendi cüzdanınız mı?" → Click "Evet" (Yes)
            logger.info("WhiteBIT TR travel rule step 6: clicking Evet (own wallet)")
            evet_btn = sumsub_page.get_by_text("Evet", exact=True).first
            await evet_btn.click(timeout=10000)
            await asyncio.sleep(2)
            await self._debug_screenshot(sumsub_page, "tr_07_after_evet")

            # Step 7: Tick checkbox for "Mevzuat gereksinimleriyle uyumluluk için"
            logger.info("WhiteBIT TR travel rule step 7: ticking compliance checkbox")
            try:
                checkbox = sumsub_page.locator(
                    'input[type="checkbox"], '
                    '[role="checkbox"], '
                    'label:has-text("Mevzuat")'
                ).first
                await checkbox.click(timeout=10000)
            except Exception:
                mevzuat = sumsub_page.get_by_text("Mevzuat gereksinimleriyle", exact=False).first
                await mevzuat.click(timeout=5000)
            await asyncio.sleep(1)
            await self._debug_screenshot(sumsub_page, "tr_08_checkbox_ticked")

            # Step 8: Click "Bu cihazdan devam et"
            logger.info("WhiteBIT TR travel rule step 8: clicking Bu cihazdan devam et")
            cihaz_btn = sumsub_page.get_by_text("Bu cihazdan devam et", exact=False).first
            await cihaz_btn.click(timeout=10000)
            await asyncio.sleep(2)
            await self._debug_screenshot(sumsub_page, "tr_09_after_cihaz")

            # Step 9: Select "Şirket" from "Bireysel veya Şirket" dropdown
            logger.info("WhiteBIT TR travel rule step 9: selecting Şirket")
            try:
                dropdown = sumsub_page.locator(
                    'select:near(:text("Bireysel")), '
                    '[class*="select"]:near(:text("Bireysel")):visible'
                ).first
                await dropdown.click(timeout=5000)
                await asyncio.sleep(500)
                sirket_option = sumsub_page.get_by_text("Şirket", exact=True).first
                await sirket_option.click(timeout=5000)
            except Exception:
                try:
                    bireysel_el = sumsub_page.get_by_text("Bireysel", exact=False).first
                    await bireysel_el.click(timeout=5000)
                    await asyncio.sleep(500)
                    sirket_option = sumsub_page.get_by_text("Şirket", exact=True).first
                    await sirket_option.click(timeout=5000)
                except Exception:
                    logger.warning("WhiteBIT TR: could not select Şirket from dropdown — trying select element")
                    await sumsub_page.select_option('select', label="Şirket", timeout=5000)
            await asyncio.sleep(1)
            await self._debug_screenshot(sumsub_page, "tr_10_sirket_selected")

            # Step 10: Leave "Merkezi" as default (don't touch)
            logger.info("WhiteBIT TR travel rule step 10: leaving Merkezi as default (no action)")

            # Step 11: Select source exchange from "KVHS seçin" dropdown
            exchange_name = TRAVEL_RULE_EXCHANGE_NAMES.get(source_exchange, source_exchange)
            logger.info(f"WhiteBIT TR travel rule step 11: selecting KVHS = {exchange_name}")
            try:
                kvhs_dropdown = sumsub_page.locator(
                    'select:near(:text("KVHS")), '
                    '[class*="select"]:near(:text("KVHS")):visible'
                ).first
                await kvhs_dropdown.click(timeout=5000)
                await asyncio.sleep(500)
                exchange_option = sumsub_page.get_by_text(exchange_name, exact=False).first
                await exchange_option.click(timeout=5000)
            except Exception:
                try:
                    kvhs_el = sumsub_page.get_by_text("KVHS seçin", exact=False).first
                    await kvhs_el.click(timeout=5000)
                    await asyncio.sleep(500)
                    exchange_option = sumsub_page.get_by_text(exchange_name, exact=False).first
                    await exchange_option.click(timeout=5000)
                except Exception:
                    logger.warning(
                        f"WhiteBIT TR: could not select KVHS via click — trying select_option"
                    )
                    try:
                        await sumsub_page.select_option(
                            'select:near(:text("KVHS"))',
                            label=exchange_name,
                            timeout=5000,
                        )
                    except Exception:
                        selects = sumsub_page.locator("select")
                        sel_count = await selects.count()
                        for i in range(sel_count):
                            try:
                                options_text = await selects.nth(i).inner_text()
                                if exchange_name.lower() in options_text.lower() or "kvhs" in options_text.lower():
                                    await selects.nth(i).select_option(label=exchange_name)
                                    break
                            except Exception:
                                continue
            await asyncio.sleep(1)
            await self._debug_screenshot(sumsub_page, "tr_11_kvhs_selected")

            # Step 12: Fill "Şirket adı" with company name
            logger.info(f"WhiteBIT TR travel rule step 12: filling Şirket adı = {COMPANY_NAME}")
            try:
                company_input = sumsub_page.locator(
                    'input[placeholder*="irket"], '
                    'input:near(:text("Şirket adı")):visible'
                ).first
                await company_input.click(timeout=5000)
                await company_input.fill(COMPANY_NAME)
            except Exception:
                try:
                    inputs = sumsub_page.locator("input[type='text'], input:not([type])")
                    inp_count = await inputs.count()
                    for i in range(inp_count):
                        try:
                            placeholder = await inputs.nth(i).get_attribute("placeholder") or ""
                            label_text = await inputs.nth(i).evaluate(
                                """el => {
                                    const label = el.closest('label') || el.parentElement;
                                    return label ? label.textContent : '';
                                }"""
                            )
                            if "irket" in placeholder.lower() or "irket" in label_text.lower():
                                await inputs.nth(i).click()
                                await inputs.nth(i).fill(COMPANY_NAME)
                                break
                        except Exception:
                            continue
                except Exception as fill_err:
                    logger.warning(f"WhiteBIT TR: could not fill company name: {fill_err}")
            await asyncio.sleep(1)
            await self._debug_screenshot(sumsub_page, "tr_12_company_filled")

            # Step 13: Submit / click next button
            logger.info("WhiteBIT TR travel rule step 13: submitting form")
            try:
                submit_btn = sumsub_page.locator(
                    'button[type="submit"], '
                    'button:has-text("Devam"), '
                    'button:has-text("Gönder"), '
                    'button:has-text("İleri"), '
                    'button:has-text("Onayla")'
                ).first
                await submit_btn.click(timeout=10000)
            except Exception:
                try:
                    cta = sumsub_page.locator(
                        'button[class*="primary"], '
                        'button[class*="submit"], '
                        'button[class*="cta"]'
                    ).first
                    await cta.click(timeout=5000)
                except Exception as sub_err:
                    logger.warning(f"WhiteBIT TR: could not find submit button: {sub_err}")
            await asyncio.sleep(3)
            await self._debug_screenshot(sumsub_page, "tr_13_after_submit")

            logger.info("WhiteBIT TR: SumSub form completed, closing tab")

            # Close the SumSub tab
            try:
                await sumsub_page.close()
            except Exception:
                pass
            sumsub_page = None

            # Verify via API that status changed
            await asyncio.sleep(2)
            verify_result = await page.evaluate("""async () => {
                try {
                    const r = await fetch(
                        'https://internal.whitebit-tr.com/v2/history/deposits?status=travel_rule_frozen',
                        {method: 'GET', headers: {'Accept': 'application/json'}, credentials: 'include'}
                    );
                    const d = await r.json();
                    return {count: (d.data || []).length};
                } catch(e) { return {error: e.message}; }
            }""")
            remaining = verify_result.get("count", -1) if verify_result else -1

            logger.info(
                f"WhiteBIT TR: travel rule confirm completed for id={travel_rule_id}, "
                f"remaining frozen: {remaining}"
            )
            return {
                "success": True,
                "message": "Travel rule verification submitted via SumSub form",
                "travel_rule_id": travel_rule_id,
                "remaining_frozen": remaining,
            }

        except Exception as e:
            error_msg = f"Travel rule UI automation failed: {e}"
            logger.error(f"WhiteBIT TR: {error_msg}")
            try:
                if sumsub_page and not sumsub_page.is_closed():
                    await self._debug_screenshot(sumsub_page, "tr_99_sumsub_error")
                    await sumsub_page.close()
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
        """Confirm deposit via travel rule verification.
        Finds a pending travel rule item, optionally matching by amount (2% tolerance),
        then completes the SumSub travel rule form."""
        # Get pending travel rules
        pending = await self.get_pending_travel_rules(session)
        if not pending["success"] or not pending["pending"]:
            return {
                "success": False,
                "message": pending.get("message", "No pending travel rules found"),
            }

        # Match by amount if provided (2% tolerance)
        target = None
        for item in pending["pending"]:
            if amount:
                try:
                    item_amount = float(item.get("amount", 0))
                    if abs(item_amount - amount) / max(amount, 1) < 0.02:
                        target = item
                        break
                except (ValueError, TypeError):
                    pass
            else:
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
