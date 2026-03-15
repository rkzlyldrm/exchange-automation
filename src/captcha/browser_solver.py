"""
Browser-level Geetest captcha solver.

Strategies (in order):
  1. Network interception — capture Geetest bg/piece image URLs from API responses
  2. Canvas extraction — access Geetest iframe canvas elements via toDataURL()
  3. Playwright frame access — access Geetest iframe and extract canvas within its context
  4. Screenshot fallback — take cropped screenshot and detect gap via edge analysis

Falls back gracefully, ultimately to human solving if all strategies fail.
"""
import asyncio
import base64
import logging
import math
import os
import random
from typing import Optional, Dict, List

import aiohttp
from playwright.async_api import Page, Response

from src.captcha.geetest_solver import find_slide_offset, find_gap_in_screenshot

logger = logging.getLogger(__name__)

DEBUG_DIR = "/app/data/debug"

# Collected Geetest image URLs from network interception
_intercepted_images: Dict[str, List[str]] = {}  # page_id -> [url, ...]


async def setup_geetest_interception(page: Page) -> None:
    """Register a response listener to capture Geetest image URLs.
    Call this BEFORE triggering the captcha (e.g., before clicking submit)."""
    page_id = str(id(page))
    _intercepted_images[page_id] = []

    async def on_response(response: Response):
        url = response.url
        # Geetest loads puzzle images from static.geetest.com or similar CDN
        if any(domain in url for domain in ["static.geetest.com", "geetest.com/pictures", "gcaptcha4.geetest.com"]):
            content_type = response.headers.get("content-type", "")
            if "image" in content_type or url.endswith((".png", ".jpg", ".webp")):
                _intercepted_images.setdefault(page_id, []).append(url)
                logger.info(f"geetest_auto: intercepted image URL: {url[:100]}...")

    page.on("response", on_response)
    logger.debug("geetest_auto: network interception registered")


async def auto_solve_geetest(page: Page, max_attempts: int = 3) -> bool:
    """Attempt to automatically solve a Geetest slide captcha.

    Returns True if the captcha appears to be solved, False otherwise.
    The caller should fall back to human solving on failure.
    """
    for attempt in range(1, max_attempts + 1):
        logger.info(f"geetest_auto: attempt {attempt}/{max_attempts}")

        # Give Geetest a moment to fully render
        await page.wait_for_timeout(1500)

        # Strategy 1: Network-intercepted images
        offset = await _try_intercepted_images(page)

        # Strategy 2: Canvas extraction from main document
        if offset is None:
            offset = await _try_canvas_extraction(page)

        # Strategy 3: Access Geetest iframe directly via Playwright frames
        if offset is None:
            offset = await _try_iframe_frame_access(page)

        # Strategy 4: Screenshot-based gap detection
        if offset is None:
            offset = await _try_screenshot_detection(page)

        if offset is None:
            logger.warning(f"geetest_auto: attempt {attempt} — could not determine slide offset")
            if attempt < max_attempts:
                await _click_refresh(page)
                await page.wait_for_timeout(2500)
            continue

        # Get slider geometry
        slider_info = await _get_slider_geometry(page)
        if slider_info is None:
            logger.warning(f"geetest_auto: attempt {attempt} — could not find slider geometry")
            if attempt < max_attempts:
                await _click_refresh(page)
                await page.wait_for_timeout(2500)
            continue

        # Calculate drag distance
        drag_distance = _calculate_drag_distance(
            gap_x_pixels=offset,
            image_width=slider_info["image_width"],
            track_width=slider_info["track_width"],
        )

        logger.info(
            f"geetest_auto: offset={offset}px, image_w={slider_info['image_width']}, "
            f"track_w={slider_info['track_width']}, drag_dist={drag_distance:.1f}px"
        )

        # Perform the humanized drag
        start_x = slider_info["handle_x"]
        start_y = slider_info["handle_y"]
        end_x = start_x + drag_distance

        await _humanized_drag(page, start_x, start_y, end_x, start_y)

        # Wait for Geetest to validate
        await page.wait_for_timeout(3000)

        # Check if captcha is gone
        still_visible = await _is_captcha_still_visible(page)
        if not still_visible:
            logger.info(f"geetest_auto: SOLVED on attempt {attempt}")
            return True

        logger.info(f"geetest_auto: attempt {attempt} failed, captcha still visible")
        await page.wait_for_timeout(2000)

    logger.warning(f"geetest_auto: all {max_attempts} attempts failed")
    return False


# ---------------------------------------------------------------------------
# Strategy 1: Network-intercepted images
# ---------------------------------------------------------------------------

async def _try_intercepted_images(page: Page) -> Optional[int]:
    """Use images captured via network interception."""
    page_id = str(id(page))
    urls = _intercepted_images.get(page_id, [])
    if not urls:
        logger.debug("geetest_auto: no intercepted image URLs")
        return None

    try:
        images_data = []
        async with aiohttp.ClientSession() as session:
            for url in urls[-4:]:  # last 4 images (most recent captcha)
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        if resp.status == 200:
                            data = await resp.read()
                            images_data.append(data)
                            logger.debug(f"geetest_auto: downloaded intercepted image ({len(data)} bytes)")
                except Exception as e:
                    logger.debug(f"geetest_auto: failed to download {url[:80]}: {e}")

        if len(images_data) >= 2:
            # Typically: bg image is larger, piece is smaller
            images_data.sort(key=len, reverse=True)
            bg_bytes = images_data[0]
            piece_bytes = images_data[1]
            offset = find_slide_offset(bg_bytes, piece_bytes)
            if offset is not None:
                logger.info(f"geetest_auto: intercepted images SUCCESS — offset={offset}px")
                _save_debug_image(bg_bytes, "geetest_intercepted_bg.png")
                _save_debug_image(piece_bytes, "geetest_intercepted_piece.png")
                return offset

        if len(images_data) >= 1:
            # Single image — try gap detection
            offset = find_gap_in_screenshot(images_data[0])
            if offset is not None:
                logger.info(f"geetest_auto: intercepted bg-only gap detection — offset={offset}px")
                return offset

    except Exception as e:
        logger.debug(f"geetest_auto: intercepted images error: {e}")

    return None


# ---------------------------------------------------------------------------
# Strategy 2: Canvas extraction from main document
# ---------------------------------------------------------------------------

async def _try_canvas_extraction(page: Page) -> Optional[int]:
    """Try to extract bg + piece images from Geetest canvas elements."""
    try:
        images = await page.evaluate("""() => {
            const result = {};

            function findCanvases(doc) {
                // Geetest v3 class names
                const bgCanvas = doc.querySelector('.geetest_canvas_bg canvas, canvas.geetest_canvas_bg');
                const sliceCanvas = doc.querySelector('.geetest_canvas_slice canvas, canvas.geetest_canvas_slice');
                const allCanvases = doc.querySelectorAll('canvas');

                if (bgCanvas) {
                    try { result.bg = bgCanvas.toDataURL('image/png'); } catch(e) {}
                }
                if (sliceCanvas) {
                    try { result.piece = sliceCanvas.toDataURL('image/png'); } catch(e) {}
                }
                if (!result.bg && allCanvases.length >= 2) {
                    try { result.bg = allCanvases[0].toDataURL('image/png'); } catch(e) {}
                    try { result.piece = allCanvases[1].toDataURL('image/png'); } catch(e) {}
                }
                if (!result.bg && allCanvases.length === 1) {
                    try { result.bg = allCanvases[0].toDataURL('image/png'); } catch(e) {}
                }
            }

            // Search main document
            findCanvases(document);

            // Try accessing iframes from parent context
            if (!result.bg) {
                const iframes = document.querySelectorAll('iframe');
                for (const iframe of iframes) {
                    try {
                        const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
                        if (iframeDoc) {
                            findCanvases(iframeDoc);
                            if (result.bg) break;
                        }
                    } catch(e) { /* cross-origin */ }
                }
            }

            // Try img tags with Geetest URLs
            if (!result.bg) {
                const imgs = document.querySelectorAll('img[src*="geetest"], img[src*="static.geetest"]');
                for (const img of imgs) {
                    if (img.naturalWidth > 100) {
                        try {
                            const c = document.createElement('canvas');
                            c.width = img.naturalWidth;
                            c.height = img.naturalHeight;
                            c.getContext('2d').drawImage(img, 0, 0);
                            if (!result.bg) result.bg = c.toDataURL('image/png');
                            else if (!result.piece) result.piece = c.toDataURL('image/png');
                        } catch(e) { /* tainted canvas */ }
                    }
                }
            }

            return result;
        }""")

        if not images or not images.get("bg"):
            logger.debug("geetest_auto: canvas extraction — no images found")
            return None

        bg_b64 = images["bg"].split(",", 1)[-1] if "," in images["bg"] else images["bg"]
        bg_bytes = base64.b64decode(bg_b64)
        _save_debug_image(bg_bytes, "geetest_canvas_bg.png")

        if images.get("piece"):
            piece_b64 = images["piece"].split(",", 1)[-1] if "," in images["piece"] else images["piece"]
            piece_bytes = base64.b64decode(piece_b64)
            _save_debug_image(piece_bytes, "geetest_canvas_piece.png")
            offset = find_slide_offset(bg_bytes, piece_bytes)
            if offset is not None:
                logger.info(f"geetest_auto: canvas extraction SUCCESS — offset={offset}px")
                return offset

        offset = find_gap_in_screenshot(bg_bytes)
        if offset is not None:
            logger.info(f"geetest_auto: canvas bg-only gap — offset={offset}px")
        return offset

    except Exception as e:
        logger.debug(f"geetest_auto: canvas extraction error: {e}")
        return None


# ---------------------------------------------------------------------------
# Strategy 3: Playwright frame access (bypasses cross-origin restrictions)
# ---------------------------------------------------------------------------

async def _try_iframe_frame_access(page: Page) -> Optional[int]:
    """Access Geetest iframe via Playwright's frame API (not JS cross-origin).
    Playwright can access cross-origin iframes natively."""
    try:
        # Find all frames, look for Geetest ones
        for frame in page.frames:
            if "geetest" in (frame.url or "").lower():
                logger.info(f"geetest_auto: found Geetest frame: {frame.url[:80]}")

                images = await frame.evaluate("""() => {
                    const result = {};
                    const canvases = document.querySelectorAll('canvas');

                    // Try Geetest-specific selectors
                    const bgCanvas = document.querySelector('.geetest_canvas_bg canvas, canvas.geetest_canvas_bg');
                    const sliceCanvas = document.querySelector('.geetest_canvas_slice canvas, canvas.geetest_canvas_slice');

                    if (bgCanvas) {
                        try { result.bg = bgCanvas.toDataURL('image/png'); } catch(e) {}
                    }
                    if (sliceCanvas) {
                        try { result.piece = sliceCanvas.toDataURL('image/png'); } catch(e) {}
                    }

                    // Fallback to all canvases
                    if (!result.bg && canvases.length >= 2) {
                        try { result.bg = canvases[0].toDataURL('image/png'); } catch(e) {}
                        try { result.piece = canvases[1].toDataURL('image/png'); } catch(e) {}
                    }
                    if (!result.bg && canvases.length === 1) {
                        try { result.bg = canvases[0].toDataURL('image/png'); } catch(e) {}
                    }

                    // Also try img elements within the frame
                    if (!result.bg) {
                        const imgs = document.querySelectorAll('img');
                        for (const img of imgs) {
                            if (img.naturalWidth > 100) {
                                try {
                                    const c = document.createElement('canvas');
                                    c.width = img.naturalWidth;
                                    c.height = img.naturalHeight;
                                    c.getContext('2d').drawImage(img, 0, 0);
                                    if (!result.bg) result.bg = c.toDataURL('image/png');
                                    else if (!result.piece) result.piece = c.toDataURL('image/png');
                                } catch(e) {}
                            }
                        }
                    }

                    result.canvasCount = canvases.length;
                    result.imgCount = document.querySelectorAll('img').length;
                    return result;
                }""")

                logger.info(
                    f"geetest_auto: iframe has {images.get('canvasCount', 0)} canvases, "
                    f"{images.get('imgCount', 0)} images, bg={'yes' if images.get('bg') else 'no'}, "
                    f"piece={'yes' if images.get('piece') else 'no'}"
                )

                if images and images.get("bg"):
                    bg_b64 = images["bg"].split(",", 1)[-1]
                    bg_bytes = base64.b64decode(bg_b64)
                    _save_debug_image(bg_bytes, "geetest_iframe_bg.png")

                    if images.get("piece"):
                        piece_b64 = images["piece"].split(",", 1)[-1]
                        piece_bytes = base64.b64decode(piece_b64)
                        _save_debug_image(piece_bytes, "geetest_iframe_piece.png")
                        offset = find_slide_offset(bg_bytes, piece_bytes)
                        if offset is not None:
                            logger.info(f"geetest_auto: iframe extraction SUCCESS — offset={offset}px")
                            return offset

                    offset = find_gap_in_screenshot(bg_bytes)
                    if offset is not None:
                        logger.info(f"geetest_auto: iframe bg-only gap — offset={offset}px")
                    return offset

    except Exception as e:
        logger.debug(f"geetest_auto: iframe frame access error: {e}")

    return None


# ---------------------------------------------------------------------------
# Strategy 4: Screenshot-based detection
# ---------------------------------------------------------------------------

async def _try_screenshot_detection(page: Page) -> Optional[int]:
    """Take a screenshot of just the puzzle image and detect the gap."""
    try:
        # Find the puzzle image area within the Geetest widget
        crop_box = await page.evaluate("""() => {
            // Look for the puzzle image container specifically
            const selectors = [
                '.geetest_panel_box',
                '.geetest_widget',
                '.geetest_holder',
                'div[class*="geetest"]',
            ];

            let widget = null;
            for (const sel of selectors) {
                const el = document.querySelector(sel);
                if (el) {
                    const r = el.getBoundingClientRect();
                    if (r.width > 100 && r.height > 100) {
                        widget = r;
                        break;
                    }
                }
            }

            // Fallback: find by text
            if (!widget) {
                const texts = ['Yapbozu tamamlamak', 'kaydırın', 'Bulmacayı', 'puzzle'];
                const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
                while (walker.nextNode()) {
                    const text = walker.currentNode.textContent.trim();
                    if (texts.some(t => text.includes(t))) {
                        let node = walker.currentNode.parentElement;
                        for (let i = 0; i < 20; i++) {
                            if (!node) break;
                            const r = node.getBoundingClientRect();
                            if (r.width > 200 && r.height > 200) {
                                widget = r;
                                break;
                            }
                            node = node.parentElement;
                        }
                        if (widget) break;
                    }
                }
            }

            if (!widget) return null;

            // Return just the top portion (puzzle image area, not the slider)
            // The puzzle image typically occupies the top ~60% of the widget
            return {
                x: widget.x,
                y: widget.y,
                width: widget.width,
                height: widget.height * 0.60,
            };
        }""")

        if not crop_box:
            logger.debug("geetest_auto: screenshot detection — could not find widget")
            return None

        # Clamp to viewport
        crop_box["x"] = max(0, crop_box["x"])
        crop_box["y"] = max(0, crop_box["y"])
        crop_box["width"] = min(crop_box["width"], 1280 - crop_box["x"])
        crop_box["height"] = min(crop_box["height"], 800 - crop_box["y"])

        screenshot = await page.screenshot(clip=crop_box)
        _save_debug_image(screenshot, "geetest_screenshot_crop.png")

        offset = find_gap_in_screenshot(screenshot)
        if offset is not None:
            logger.info(f"geetest_auto: screenshot detection SUCCESS — offset={offset}px")
        return offset

    except Exception as e:
        logger.debug(f"geetest_auto: screenshot detection error: {e}")
        return None


# ---------------------------------------------------------------------------
# Slider geometry detection
# ---------------------------------------------------------------------------

async def _get_slider_geometry(page: Page) -> Optional[Dict[str, float]]:
    """Get the slider handle position and track dimensions."""
    try:
        info = await page.evaluate("""() => {
            // === Find slider handle ===
            const handleSelectors = [
                '.geetest_btn',
                '.geetest_slider_button',
                'div[class*="geetest"] div[class*="btn"]',
                'div[class*="slider"] button',
                'div[class*="slider"] div[class*="btn"]',
                'div[class*="slider"] div[class*="handle"]',
            ];

            let handle = null;
            for (const sel of handleSelectors) {
                const el = document.querySelector(sel);
                if (el) {
                    const r = el.getBoundingClientRect();
                    if (r.width > 10 && r.width < 100 && r.height > 10) {
                        handle = r;
                        break;
                    }
                }
            }

            // Broader search: small roughly-square element in the captcha area
            if (!handle) {
                const allElements = document.querySelectorAll('div, span, button');
                for (const el of allElements) {
                    const r = el.getBoundingClientRect();
                    // Handle is ~30-60px square, positioned in lower part of page
                    if (r.width >= 25 && r.width <= 70 && r.height >= 25 && r.height <= 70
                        && Math.abs(r.width - r.height) < 15 && r.y > 350) {
                        // Check if it's within a captcha-like container
                        const parent = el.closest('[class*="geetest"], [class*="captcha"], [class*="slider"]');
                        if (parent) {
                            handle = r;
                            break;
                        }
                    }
                }
            }

            // === Find slider track ===
            const trackSelectors = [
                '.geetest_slider',
                '.geetest_panel_next',
                'div[class*="geetest"][class*="slider"]',
                'div[class*="slider"][class*="track"]',
                'div[class*="slider"][class*="bar"]',
            ];

            let track = null;
            for (const sel of trackSelectors) {
                const el = document.querySelector(sel);
                if (el) {
                    const r = el.getBoundingClientRect();
                    if (r.width > 150 && r.height < 80) {
                        track = r;
                        break;
                    }
                }
            }

            // === Find puzzle image width ===
            let imageWidth = 0;
            const imgSelectors = [
                '.geetest_canvas_img',
                '.geetest_widget canvas',
                'div[class*="geetest"] canvas',
                'div[class*="geetest"] img',
            ];

            for (const sel of imgSelectors) {
                const el = document.querySelector(sel);
                if (el) {
                    const r = el.getBoundingClientRect();
                    if (r.width > 100) {
                        imageWidth = r.width;
                        break;
                    }
                }
            }

            // Estimate from widget width if needed
            if (!imageWidth) {
                const widgets = document.querySelectorAll('div[class*="geetest"]');
                for (const w of widgets) {
                    const r = w.getBoundingClientRect();
                    if (r.width > 200 && r.width < 500 && r.height > 100) {
                        imageWidth = r.width;
                        break;
                    }
                }
            }

            if (!handle && !track) return null;

            // Defaults / fallbacks
            const trackWidth = track ? track.width : (imageWidth || 230);
            const handleX = handle ? (handle.x + handle.width / 2) : (track ? track.x + 25 : null);
            const handleY = handle ? (handle.y + handle.height / 2) : (track ? track.y + track.height / 2 : null);

            if (handleX === null) return null;

            return {
                handle_x: handleX,
                handle_y: handleY,
                track_width: trackWidth,
                track_x: track ? track.x : handleX - 25,
                image_width: imageWidth || trackWidth,
            };
        }""")

        if info and info.get("handle_x"):
            logger.info(
                f"geetest_auto: slider geometry — handle=({info['handle_x']:.0f},{info['handle_y']:.0f}), "
                f"track_w={info['track_width']:.0f}, image_w={info['image_width']:.0f}"
            )
            return info

        logger.debug("geetest_auto: slider geometry not found")
        return None

    except Exception as e:
        logger.debug(f"geetest_auto: slider geometry error: {e}")
        return None


# ---------------------------------------------------------------------------
# Coordinate calculation
# ---------------------------------------------------------------------------

def _calculate_drag_distance(
    gap_x_pixels: int,
    image_width: float,
    track_width: float,
) -> float:
    """Map the gap x-position (in image pixels) to a viewport drag distance."""
    if image_width <= 0:
        image_width = 260

    ratio = gap_x_pixels / image_width
    drag = ratio * track_width

    # Small random jitter to avoid being too precise
    drag += random.uniform(-2, 2)

    return max(10, drag)


# ---------------------------------------------------------------------------
# Humanized drag
# ---------------------------------------------------------------------------

async def _humanized_drag(
    page: Page,
    start_x: float, start_y: float,
    end_x: float, end_y: float,
    steps: int = 30,
) -> None:
    """Perform a human-like drag from start to end coordinates."""
    # 1. Approach with slight offset
    await page.mouse.move(
        start_x - random.uniform(5, 15),
        start_y + random.uniform(-5, 5),
    )
    await page.wait_for_timeout(random.randint(100, 250))
    await page.mouse.move(start_x, start_y)
    await page.wait_for_timeout(random.randint(150, 350))

    # 2. Press down
    await page.mouse.down()
    await page.wait_for_timeout(random.randint(80, 200))

    # 3. Drag with easing + wobble
    for i in range(1, steps + 1):
        t = i / steps
        # Ease-out cubic
        eased_t = 1 - (1 - t) ** 3

        # Vertical wobble (sinusoidal, stronger in middle)
        wobble_amp = 2.5 * math.sin(t * math.pi)
        wobble_y = random.uniform(-wobble_amp, wobble_amp)

        ix = start_x + (end_x - start_x) * eased_t
        iy = start_y + (end_y - start_y) * eased_t + wobble_y
        await page.mouse.move(ix, iy)

        # Variable timing
        if t < 0.15 or t > 0.85:
            delay = random.randint(18, 45)
        else:
            delay = random.randint(6, 18)
        await page.wait_for_timeout(delay)

    # 4. Slight overshoot then correct (very human)
    overshoot = random.uniform(2, 6)
    await page.mouse.move(end_x + overshoot, end_y + random.uniform(-1, 1))
    await page.wait_for_timeout(random.randint(30, 80))
    await page.mouse.move(end_x, end_y)
    await page.wait_for_timeout(random.randint(80, 200))

    # 5. Release
    await page.mouse.up()
    logger.info(f"geetest_auto: drag complete ({start_x:.0f},{start_y:.0f}) -> ({end_x:.0f},{end_y:.0f})")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _is_captcha_still_visible(page: Page) -> bool:
    """Check if the Geetest captcha widget is still visible."""
    try:
        visible = await page.evaluate("""() => {
            // Check text indicators
            const texts = ['Yapbozu tamamlamak', 'kaydırın', 'Bulmacayı', 'puzzle', 'slide'];
            const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
            while (walker.nextNode()) {
                const text = walker.currentNode.textContent.trim();
                if (texts.some(t => text.includes(t))) {
                    const el = walker.currentNode.parentElement;
                    if (el && el.offsetParent !== null) {
                        const r = el.getBoundingClientRect();
                        if (r.width > 0 && r.height > 0) return true;
                    }
                }
            }
            // Check Geetest DOM elements
            const gtElements = document.querySelectorAll('[class*="geetest"]');
            for (const el of gtElements) {
                const r = el.getBoundingClientRect();
                if (r.width > 100 && r.height > 100 && el.offsetParent !== null) {
                    return true;
                }
            }
            return false;
        }""")
        return visible
    except Exception:
        return False


async def _click_refresh(page: Page) -> None:
    """Click the Geetest refresh button to get a new puzzle."""
    try:
        clicked = await page.evaluate("""() => {
            const refreshSelectors = [
                '.geetest_refresh',
                '.geetest_refresh_1',
                'a[class*="refresh"]',
                'div[class*="refresh"]',
            ];
            for (const sel of refreshSelectors) {
                const el = document.querySelector(sel);
                if (el) { el.click(); return 'selector'; }
            }
            // Fallback: ↻ icon button in the captcha area
            const svgs = document.querySelectorAll('svg, path');
            for (const svg of svgs) {
                const parent = svg.closest('a, button, div[role="button"]');
                if (parent) {
                    const r = parent.getBoundingClientRect();
                    if (r.width > 10 && r.width < 50 && r.height > 10 && r.height < 50 && r.y > 350) {
                        parent.click();
                        return 'icon';
                    }
                }
            }
            return false;
        }""")
        if clicked:
            logger.info(f"geetest_auto: clicked refresh ({clicked})")
        else:
            logger.debug("geetest_auto: no refresh button found")
    except Exception as e:
        logger.debug(f"geetest_auto: refresh click failed: {e}")


def _save_debug_image(data: bytes, filename: str) -> None:
    """Save an image to the debug directory for inspection."""
    try:
        os.makedirs(DEBUG_DIR, exist_ok=True)
        path = os.path.join(DEBUG_DIR, filename)
        with open(path, "wb") as f:
            f.write(data)
        logger.debug(f"geetest_auto: saved debug image {filename} ({len(data)} bytes)")
    except Exception:
        pass
