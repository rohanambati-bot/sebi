"""
Synthetic Media Scanner (images) — hackathon MVP
--------------------------------------------------
True deepfake video/voice detection needs pretrained CNN/RNN models
(e.g. Xception-based frame classifiers, wav2vec spoof detectors) that
require GPU inference and large weight downloads — out of scope for a
Round-1, offline-buildable MVP.

What IS genuinely implemented and running here:
  - Error Level Analysis (ELA) on images: re-compresses the image at a
    known JPEG quality and diffs it against the original. Regions that
    were spliced/AI-generated/edited compress differently from the rest
    of a genuine photograph, showing up as bright patches in the ELA map.
    This is a real, widely-used forensic technique (not a mock).
  - EXIF / metadata forensics: absence of camera EXIF data, or presence
    of editing-software tags (Photoshop, GIMP, known AI-art tool markers)
    is scored as a risk signal.

Roadmap (documented, not faked): swap `image_score()` for a trained
CNN (e.g. fine-tuned EfficientNet on FaceForensics++) behind the same
API contract, and add an audio spoof-detection microservice (wav2vec2
+ ASVspoof) for the voice-call vector — both are drop-in replacements
because the API returns the same {score, verdict, evidence} shape.
"""

import io
from PIL import Image, ImageChops, ExifTags
import numpy as np


def _ela_image(pil_img: Image.Image, quality: int = 90):
    buffer = io.BytesIO()
    pil_img.convert("RGB").save(buffer, "JPEG", quality=quality)
    buffer.seek(0)
    resaved = Image.open(buffer)
    diff = ImageChops.difference(pil_img.convert("RGB"), resaved)
    diff_arr = np.array(diff).astype(np.float32)
    return diff_arr


def _exif_signals(pil_img: Image.Image):
    signals = []
    exif = pil_img.getexif()
    if not exif or len(exif) == 0:
        signals.append("No EXIF/camera metadata found (common in AI-generated or "
                        "screenshot-recompressed images; genuine phone photos usually carry EXIF)")
        return signals, 15
    tags = {ExifTags.TAGS.get(k, k): v for k, v in exif.items()}
    software = str(tags.get("Software", "")).lower()
    risky_tools = ["photoshop", "gimp", "midjourney", "stable diffusion", "dall", "ai"]
    if any(tool in software for tool in risky_tools):
        signals.append(f"EXIF 'Software' tag indicates editing/generation tool: {tags.get('Software')}")
        return signals, 25
    return signals, 0


def analyze_image(file_bytes: bytes):
    pil_img = Image.open(io.BytesIO(file_bytes))
    diff_arr = _ela_image(pil_img)

    mean_diff = float(diff_arr.mean())
    max_diff = float(diff_arr.max())
    # High-variance patches (bright spots) relative to a mostly-uniform
    # compression signature suggest localized tampering / synthetic regions.
    std_diff = float(diff_arr.std())

    score = 0
    evidence = []

    # Heuristic thresholds tuned on a small internal sample set (see docs/EVALUATION.md)
    if std_diff > 14:
        score += 35
        evidence.append(f"High variance in compression-error map (std={std_diff:.1f}) — "
                         f"suggests non-uniform editing/splicing across the image")
    elif std_diff > 8:
        score += 15
        evidence.append(f"Moderate compression-error variance (std={std_diff:.1f})")

    if max_diff > 180:
        score += 20
        evidence.append(f"Localized high-error region detected (max ELA intensity={max_diff:.0f}/255)")

    exif_signals, exif_score = _exif_signals(pil_img)
    evidence.extend(exif_signals)
    score += exif_score

    score = max(0, min(100, score))
    if score >= 55:
        verdict = "LIKELY_MANIPULATED"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY_AUTHENTIC"

    # small preview stats for the UI
    ela_preview = Image.fromarray(np.clip(diff_arr * 8, 0, 255).astype("uint8"))
    preview_buffer = io.BytesIO()
    ela_preview.save(preview_buffer, format="PNG")

    return {
        "risk_score": score,
        "verdict": verdict,
        "evidence": evidence,
        "metrics": {"mean_ela": mean_diff, "std_ela": std_diff, "max_ela": max_diff},
    }, preview_buffer.getvalue()
