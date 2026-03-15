"""
Geetest v4 slide-puzzle captcha solver.

Uses OpenCV edge detection + template matching to find the gap position
in the background image, then returns the pixel offset for the slider drag.

Two extraction strategies:
  1. Canvas extraction — access Geetest iframe's canvas elements via toDataURL()
  2. Screenshot-based  — take a clipped screenshot and detect gap via edge analysis

Falls back gracefully: canvas → screenshot → give up (let human solve).
"""
import io
import logging
import math
import random
import tempfile
from typing import Optional, Tuple

import cv2
import numpy as np

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Core solver: given background + puzzle piece images, find the X offset
# ---------------------------------------------------------------------------

def find_slide_offset(bg_bytes: bytes, piece_bytes: bytes) -> Optional[int]:
    """Find the horizontal pixel offset where the puzzle piece fits into the
    background image.  Returns the x-coordinate (in background-image pixels)
    or None if detection fails."""
    bg_img = _bytes_to_cv2(bg_bytes)
    piece_img = _bytes_to_cv2(piece_bytes)
    if bg_img is None or piece_img is None:
        logger.warning("geetest_solver: failed to decode one of the images")
        return None

    # Crop whitespace/transparency from the puzzle piece
    piece_cropped = _crop_non_transparent(piece_img)
    if piece_cropped is None:
        piece_cropped = piece_img

    # Apply edge detection to both
    bg_edges = _edge_detect(bg_img)
    piece_edges = _edge_detect(piece_cropped)

    if piece_edges.shape[0] > bg_edges.shape[0] or piece_edges.shape[1] > bg_edges.shape[1]:
        logger.warning("geetest_solver: piece larger than background after crop")
        return None

    # Template matching
    result = cv2.matchTemplate(bg_edges, piece_edges, cv2.TM_CCOEFF_NORMED)
    _, max_val, _, max_loc = cv2.minMaxLoc(result)
    logger.info(f"geetest_solver: template match confidence={max_val:.3f}, position=({max_loc[0]}, {max_loc[1]})")

    if max_val < 0.15:
        logger.warning(f"geetest_solver: low confidence ({max_val:.3f}), result may be unreliable")

    return max_loc[0]  # x-coordinate of the top-left corner of the match


def find_gap_in_screenshot(screenshot_bytes: bytes) -> Optional[int]:
    """Detect the gap (dark shadow outline) in a single captcha screenshot.
    Used as fallback when we can't extract separate bg/piece images.
    Returns the x-coordinate of the gap center relative to the image."""
    img = _bytes_to_cv2(screenshot_bytes)
    if img is None:
        return None

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    h, w = gray.shape

    # The puzzle area is typically the top ~70% of the captcha widget
    # (bottom has the slider bar)
    puzzle_h = int(h * 0.65)
    puzzle_region = gray[:puzzle_h, :]

    # Apply Gaussian blur then Canny edge detection
    blurred = cv2.GaussianBlur(puzzle_region, (5, 5), 0)
    edges = cv2.Canny(blurred, 50, 150)

    # Look for vertical edge clusters — the gap has strong vertical edges
    # Sum edges along each column
    col_sums = np.sum(edges, axis=0).astype(float)

    # Smooth the column sums
    kernel_size = 5
    kernel = np.ones(kernel_size) / kernel_size
    smoothed = np.convolve(col_sums, kernel, mode='same')

    # The gap typically has two vertical edge peaks (left and right sides)
    # Skip the first 15% (slider starting area) and look for strong edge regions
    start_x = int(w * 0.15)
    search_region = smoothed[start_x:]

    if len(search_region) == 0:
        return None

    # Find the peak — this is likely the left edge of the gap
    peak_idx = int(np.argmax(search_region)) + start_x

    # The gap is typically ~40-60px wide, return center
    gap_center = peak_idx + 25

    logger.info(f"geetest_solver: gap detected at x={gap_center} (peak edge at {peak_idx})")
    return gap_center


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bytes_to_cv2(data: bytes):
    """Convert raw image bytes to an OpenCV BGR image."""
    arr = np.frombuffer(data, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_UNCHANGED)
    return img


def _crop_non_transparent(img):
    """Crop image to the bounding box of non-transparent / non-white pixels."""
    if img is None:
        return None

    if img.shape[2] == 4:
        # RGBA — use alpha channel
        alpha = img[:, :, 3]
        mask = alpha > 10
    else:
        # RGB — use brightness
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        mask = gray > 10

    coords = np.column_stack(np.where(mask))
    if coords.size == 0:
        return None

    y_min, x_min = coords.min(axis=0)
    y_max, x_max = coords.max(axis=0)

    cropped = img[y_min:y_max + 1, x_min:x_max + 1]
    # Convert to BGR if RGBA
    if cropped.shape[2] == 4:
        cropped = cv2.cvtColor(cropped, cv2.COLOR_BGRA2BGR)
    return cropped


def _edge_detect(img):
    """Apply Sobel edge detection (works better than Canny for template matching)."""
    if len(img.shape) == 3:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    else:
        gray = img

    blurred = cv2.GaussianBlur(gray, (3, 3), 0)

    grad_x = cv2.Sobel(blurred, cv2.CV_16S, 1, 0, ksize=3)
    grad_y = cv2.Sobel(blurred, cv2.CV_16S, 0, 1, ksize=3)
    abs_x = cv2.convertScaleAbs(grad_x)
    abs_y = cv2.convertScaleAbs(grad_y)
    edges = cv2.addWeighted(abs_x, 0.5, abs_y, 0.5, 0)

    return edges
