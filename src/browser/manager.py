"""
Browser Manager — single Chromium instance with per-exchange BrowserContexts.
Handles lifecycle, health monitoring, and restarts.
"""
import asyncio
import json
import os
import time
import logging
from typing import Dict, Optional

from playwright.async_api import async_playwright, Browser, BrowserContext, Playwright

from src.config import settings
from src.security.encryption import encrypt_file_content, decrypt_file_content

STORAGE_DIR = "/app/data"

logger = logging.getLogger(__name__)


class BrowserManager:
    """Manages a single Chromium browser and per-exchange BrowserContexts."""

    def __init__(self):
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._contexts: Dict[str, BrowserContext] = {}
        self._started_at: float = 0
        self._health_task: Optional[asyncio.Task] = None

    # ── lifecycle ──────────────────────────────────────────────

    async def start(self) -> None:
        """Launch Chromium with stealth-friendly flags."""
        logger.info("Launching Chromium browser...")
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=False,
            args=[
                "--disable-dev-shm-usage",
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-blink-features=AutomationControlled",
                "--disable-infobars",
                "--mute-audio",
                "--no-first-run",
                "--window-size=1280,800",
                "--disable-quic",
                "--disable-gpu",
                "--disable-software-rasterizer",
            ],
        )
        self._started_at = time.time()
        self._health_task = asyncio.create_task(self._health_loop())
        logger.info("Chromium browser launched successfully")

    async def stop(self) -> None:
        """Gracefully shut down everything."""
        if self._health_task:
            self._health_task.cancel()
            try:
                await self._health_task
            except asyncio.CancelledError:
                pass

        for name, ctx in list(self._contexts.items()):
            try:
                await ctx.close()
            except Exception:
                pass
        self._contexts.clear()

        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                pass
            self._browser = None

        if self._playwright:
            try:
                await self._playwright.stop()
            except Exception:
                pass
            self._playwright = None

        logger.info("Browser manager stopped")

    # ── context management ─────────────────────────────────────

    def _storage_path(self, exchange_name: str) -> str:
        """Return path to the storage state file for an exchange."""
        return os.path.join(STORAGE_DIR, f"{exchange_name}_storage.json")

    async def save_storage_state(self, exchange_name: str) -> None:
        """Save cookies and localStorage for an exchange context to disk (encrypted)."""
        ctx = self._contexts.get(exchange_name)
        if not ctx:
            return
        try:
            path = self._storage_path(exchange_name)
            state = await ctx.storage_state()
            encrypted = encrypt_file_content(json.dumps(state))
            with open(path, "wb") as f:
                f.write(encrypted)
            logger.info(f"Saved encrypted storage state for {exchange_name} to {path}")
        except Exception as e:
            logger.warning(f"Failed to save storage state for {exchange_name}: {e}")

    def _load_storage_state(self, exchange_name: str) -> Optional[dict]:
        """Load and decrypt storage state from disk, with backward compat for plain JSON."""
        path = self._storage_path(exchange_name)
        if not os.path.exists(path):
            return None

        raw = open(path, "rb").read()
        if not raw:
            return None

        # Try encrypted format first (Fernet tokens start with 'gAAAAA')
        try:
            decrypted = decrypt_file_content(raw)
            logger.info(f"Loaded encrypted storage state for {exchange_name}")
            return json.loads(decrypted)
        except Exception:
            pass

        # Fall back to legacy plain JSON
        try:
            state = json.loads(raw)
            logger.warning(f"Loaded plain-text storage state for {exchange_name} (legacy) — will re-encrypt on next save")
            return state
        except Exception as e:
            logger.error(f"Failed to load storage state for {exchange_name}: {e}")
            return None

    async def get_context(self, exchange_name: str) -> BrowserContext:
        """Get or create an isolated BrowserContext for an exchange."""
        if exchange_name in self._contexts:
            return self._contexts[exchange_name]

        if not self._browser:
            raise RuntimeError("Browser not started")

        # Load saved storage state (cookies/localStorage) if available
        storage_state = self._load_storage_state(exchange_name)
        if storage_state:
            logger.info(f"Applying saved storage state for {exchange_name}")

        ctx = await self._browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            ),
            locale="tr-TR",
            timezone_id="Europe/Istanbul",
            storage_state=storage_state,
        )
        # Stealth: hide automation signals from bot detection (GeeTest, reCAPTCHA, etc.)
        await ctx.add_init_script("""
            // Remove webdriver flag
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            delete navigator.__proto__.webdriver;

            // Fake plugins (must look like real PluginArray)
            const fakePlugins = {
                0: { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
                1: { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
                2: { name: 'Native Client', filename: 'internal-nacl-plugin', description: '' },
                length: 3,
                item: function(i) { return this[i] || null; },
                namedItem: function(n) { for (let i=0; i<this.length; i++) if (this[i].name===n) return this[i]; return null; },
                refresh: function() {},
            };
            Object.setPrototypeOf(fakePlugins, PluginArray.prototype);
            Object.defineProperty(navigator, 'plugins', { get: () => fakePlugins });

            // Fake mimeTypes
            const fakeMimeTypes = {
                0: { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format', enabledPlugin: fakePlugins[0] },
                length: 1,
                item: function(i) { return this[i] || null; },
                namedItem: function(n) { for (let i=0; i<this.length; i++) if (this[i].type===n) return this[i]; return null; },
            };
            Object.setPrototypeOf(fakeMimeTypes, MimeTypeArray.prototype);
            Object.defineProperty(navigator, 'mimeTypes', { get: () => fakeMimeTypes });

            // Fake languages
            Object.defineProperty(navigator, 'languages', {
                get: () => ['tr-TR', 'tr', 'en-US', 'en'],
            });

            // Spoof userAgentData to hide HeadlessChrome
            if (navigator.userAgentData) {
                const origBrands = navigator.userAgentData.brands;
                const cleanBrands = [
                    { brand: 'Google Chrome', version: '131' },
                    { brand: 'Chromium', version: '131' },
                    { brand: 'Not_A Brand', version: '24' },
                ];
                Object.defineProperty(navigator, 'userAgentData', {
                    get: () => ({
                        brands: cleanBrands,
                        mobile: false,
                        platform: 'Windows',
                        getHighEntropyValues: (hints) => Promise.resolve({
                            brands: cleanBrands,
                            mobile: false,
                            platform: 'Windows',
                            platformVersion: '10.0',
                            architecture: 'x64',
                            bitness: '64',
                            model: '',
                            uaFullVersion: '131.0.6778.33',
                            fullVersionList: cleanBrands.map(b => ({...b})),
                        }),
                    }),
                });
            }

            // Chrome object (must look complete)
            window.chrome = {
                app: { isInstalled: false, InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' }, RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' } },
                runtime: { OnInstalledReason: { CHROME_UPDATE: 'chrome_update', INSTALL: 'install', SHARED_MODULE_UPDATE: 'shared_module_update', UPDATE: 'update' }, OnRestartRequiredReason: { APP_UPDATE: 'app_update', OS_UPDATE: 'os_update', PERIODIC: 'periodic' }, PlatformArch: { ARM: 'arm', ARM64: 'arm64', MIPS: 'mips', MIPS64: 'mips64', X86_32: 'x86-32', X86_64: 'x86-64' }, PlatformNaclArch: { ARM: 'arm', MIPS: 'mips', MIPS64: 'mips64', X86_32: 'x86-32', X86_64: 'x86-64' }, PlatformOs: { ANDROID: 'android', CROS: 'cros', FUCHSIA: 'fuchsia', LINUX: 'linux', MAC: 'mac', OPENBSD: 'openbsd', WIN: 'win' }, RequestUpdateCheckStatus: { NO_UPDATE: 'no_update', THROTTLED: 'throttled', UPDATE_AVAILABLE: 'update_available' }, connect: function() {}, sendMessage: function() {} },
                csi: function() { return { startE: Date.now(), onloadT: Date.now(), pageT: Math.random() * 1000, tran: 15 }; },
                loadTimes: function() { return { csi_finished: true, firstPaintAfterLoadTime: 0, firstPaintTime: Math.random() * 50, navigationType: 'Other', requestTime: Date.now() / 1000, startLoadTime: Date.now() / 1000, commitLoadTime: Date.now() / 1000, finishDocumentLoadTime: Date.now() / 1000, finishLoadTime: Date.now() / 1000, wasAlternateProtocolAvailable: false, wasFetchedViaSpdy: false, wasNpnNegotiated: false, npnNegotiatedProtocol: 'unknown', wasAlternateProtocolAvailable: false }; },
            };

            // Override permissions query
            const originalQuery = window.navigator.permissions.query;
            window.navigator.permissions.query = (parameters) =>
                parameters.name === 'notifications'
                    ? Promise.resolve({ state: Notification.permission })
                    : originalQuery(parameters);

            // Hardware concurrency (real browsers have >1)
            Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 4 });

            // Device memory
            Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });

            // Connection info
            if (navigator.connection) {
                Object.defineProperty(navigator.connection, 'rtt', { get: () => 50 });
            }

            // WebGL vendor/renderer (avoid "Google SwiftShader" which screams headless)
            const getParameter = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(param) {
                if (param === 37445) return 'Google Inc. (NVIDIA)';
                if (param === 37446) return 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1050 Direct3D11 vs_5_0 ps_5_0, D3D11)';
                return getParameter.apply(this, arguments);
            };
            const getParameter2 = WebGL2RenderingContext.prototype.getParameter;
            WebGL2RenderingContext.prototype.getParameter = function(param) {
                if (param === 37445) return 'Google Inc. (NVIDIA)';
                if (param === 37446) return 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1050 Direct3D11 vs_5_0 ps_5_0, D3D11)';
                return getParameter2.apply(this, arguments);
            };

            // Hide CDP (Chrome DevTools Protocol) artifacts
            // GeeTest checks for these
            const origCall = Function.prototype.call;
            const origToString = Function.prototype.toString;
            Function.prototype.toString = function() {
                if (this === Function.prototype.toString) return 'function toString() { [native code] }';
                return origToString.call(this);
            };

            // Mask Notification.permission if not available
            if (typeof Notification === 'undefined') {
                window.Notification = { permission: 'default' };
            }

            // Screen dimensions (avoid 0x0 which headless might report)
            if (screen.width === 0 || screen.height === 0) {
                Object.defineProperty(screen, 'width', { get: () => 1920 });
                Object.defineProperty(screen, 'height', { get: () => 1080 });
                Object.defineProperty(screen, 'availWidth', { get: () => 1920 });
                Object.defineProperty(screen, 'availHeight', { get: () => 1040 });
                Object.defineProperty(screen, 'colorDepth', { get: () => 24 });
                Object.defineProperty(screen, 'pixelDepth', { get: () => 24 });
            }

            // Prevent iframe-based detection of automation
            Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', {
                get: function() {
                    return new Proxy(this.contentWindow || window, {
                        get: function(target, prop) {
                            if (prop === 'chrome') return window.chrome;
                            return Reflect.get(target, prop);
                        }
                    });
                }
            });
        """)
        # Block heavy resources to save memory (keep images for captcha)
        await ctx.route(
            "**/*.{woff,woff2,ttf,eot,mp4,webm}",
            lambda route: route.abort(),
        )
        self._contexts[exchange_name] = ctx
        logger.info(f"Created browser context for {exchange_name}")
        return ctx

    async def close_context(self, exchange_name: str) -> None:
        """Close and remove a specific exchange context."""
        ctx = self._contexts.pop(exchange_name, None)
        if ctx:
            try:
                await ctx.close()
            except Exception:
                pass
            logger.info(f"Closed browser context for {exchange_name}")

    async def restart_context(self, exchange_name: str) -> BrowserContext:
        """Hard restart: close and recreate context (loses session)."""
        await self.close_context(exchange_name)
        return await self.get_context(exchange_name)

    # ── health monitoring ──────────────────────────────────────

    async def _health_loop(self) -> None:
        """Periodically check browser health."""
        interval = settings.SESSION_HEARTBEAT_INTERVAL_SEC
        while True:
            await asyncio.sleep(interval)
            try:
                uptime_h = (time.time() - self._started_at) / 3600
                if uptime_h > settings.BROWSER_MAX_UPTIME_HOURS:
                    logger.warning(
                        f"Browser uptime {uptime_h:.1f}h exceeds limit "
                        f"({settings.BROWSER_MAX_UPTIME_HOURS}h). Scheduling restart."
                    )
                    # Full restart handled externally via the /hard-restart endpoint
            except Exception as e:
                logger.error(f"Health check error: {e}")

    def get_health(self) -> dict:
        """Return browser health info."""
        uptime = time.time() - self._started_at if self._started_at else 0
        return {
            "browser_running": self._browser is not None and self._browser.is_connected(),
            "uptime_seconds": round(uptime),
            "contexts": list(self._contexts.keys()),
            "context_count": len(self._contexts),
        }

    @property
    def is_running(self) -> bool:
        return self._browser is not None and self._browser.is_connected()


# Module-level singleton
browser_manager = BrowserManager()
