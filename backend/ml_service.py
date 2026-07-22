#!/usr/bin/env python3
"""
SentinelSEBI Python ML Microservice
Called from Node.js via child_process.execFile('python', ['ml_service.py', <mode>, <filepath>])

Modes:
  audio <filepath>   — librosa FFT spectral analysis, MFCC, ZCR, Resemblyzer embedding
  image <filepath>   — OpenCV + MediaPipe Face Mesh, exifread EXIF forensics
  video <filepath>   — OpenCV frame extraction + MediaPipe temporal face mesh analysis

All output is JSON to stdout. Errors to stderr.
"""

import sys
import json
import os
import tempfile
import struct
import math

# ──────────────────────────────────────────────────────────────
# Graceful import handling — report which libraries are available
# ──────────────────────────────────────────────────────────────
AVAILABLE = {}

try:
    import numpy as np
    AVAILABLE['numpy'] = True
except ImportError:
    AVAILABLE['numpy'] = False

try:
    import librosa
    AVAILABLE['librosa'] = True
except ImportError:
    AVAILABLE['librosa'] = False

try:
    import ffmpeg
    AVAILABLE['ffmpeg'] = True
except ImportError:
    AVAILABLE['ffmpeg'] = False

try:
    import cv2
    AVAILABLE['opencv'] = True
except ImportError:
    AVAILABLE['opencv'] = False

try:
    import mediapipe as mp
    AVAILABLE['mediapipe'] = True
except ImportError:
    AVAILABLE['mediapipe'] = False

try:
    import exifread
    AVAILABLE['exifread'] = True
except ImportError:
    AVAILABLE['exifread'] = False

try:
    from resemblyzer import VoiceEncoder, preprocess_wav
    AVAILABLE['resemblyzer'] = True
except ImportError:
    AVAILABLE['resemblyzer'] = False


def error_result(msg):
    return {"success": False, "error": msg, "available_libraries": AVAILABLE}


# ═══════════════════════════════════════════════════════════════
# AUDIO ANALYSIS MODULE
# ═══════════════════════════════════════════════════════════════
def analyze_audio(filepath):
    """Real audio forensics using librosa + optional resemblyzer."""
    if not os.path.exists(filepath):
        return error_result(f"File not found: {filepath}")

    result = {
        "success": True,
        "engine": "python_ml_audio",
        "libraries_used": [],
        "risk_score": 0,
        "verdict": "AUTHENTIC",
        "evidence": [],
    }

    wav_path = filepath

    # 1. Transcode to WAV using ffmpeg-python if needed
    ext = os.path.splitext(filepath)[1].lower()
    if ext not in ['.wav', '.pcm'] and AVAILABLE.get('ffmpeg'):
        try:
            wav_path = tempfile.mktemp(suffix='.wav')
            (
                ffmpeg
                .input(filepath)
                .output(wav_path, ar=16000, ac=1, f='wav')
                .overwrite_output()
                .run(quiet=True)
            )
            result['libraries_used'].append('ffmpeg-python (transcoded to WAV)')
        except Exception as e:
            result['evidence'].append(f"ffmpeg transcode failed: {str(e)}, attempting direct load")
            wav_path = filepath

    # 2. Librosa spectral analysis
    if AVAILABLE.get('librosa') and AVAILABLE.get('numpy'):
        try:
            y, sr = librosa.load(wav_path, sr=None)
            result['libraries_used'].append('librosa')

            # Real FFT spectral flatness (Wiener entropy)
            spectral_flatness = librosa.feature.spectral_flatness(y=y)
            mean_flatness = float(np.mean(spectral_flatness))
            result['spectral_flatness'] = round(mean_flatness, 6)

            # Synthetic speech tends to have higher spectral flatness (more uniform spectrum)
            if mean_flatness > 0.15:
                result['risk_score'] += 30
                result['evidence'].append(
                    f"High spectral flatness ({mean_flatness:.4f}): Uniform frequency distribution suggests synthetic generation."
                )

            # MFCC extraction (voice characteristics)
            mfccs = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=13)
            mfcc_variance = float(np.var(mfccs))
            result['mfcc_variance'] = round(mfcc_variance, 4)

            # Very low MFCC variance = potentially synthetic
            if mfcc_variance < 50:
                result['risk_score'] += 25
                result['evidence'].append(
                    f"Low MFCC variance ({mfcc_variance:.2f}): Limited vocal characteristic variation, consistent with voice cloning."
                )

            # Zero-crossing rate
            zcr = librosa.feature.zero_crossing_rate(y)
            mean_zcr = float(np.mean(zcr))
            zcr_std = float(np.std(zcr))
            result['zero_crossing_rate'] = round(mean_zcr, 6)
            result['zcr_std'] = round(zcr_std, 6)

            # Very low ZCR std = synthetic monotonicity
            if zcr_std < 0.01:
                result['risk_score'] += 15
                result['evidence'].append(
                    f"Very low ZCR standard deviation ({zcr_std:.4f}): Unnaturally consistent speech cadence."
                )

            # RMS energy analysis
            rms = librosa.feature.rms(y=y)
            rms_std = float(np.std(rms))
            result['rms_energy_std'] = round(rms_std, 6)

            # Spectral centroid
            centroid = librosa.feature.spectral_centroid(y=y, sr=sr)
            result['spectral_centroid_mean'] = round(float(np.mean(centroid)), 2)

            # Duration
            result['duration_seconds'] = round(len(y) / sr, 2)
            result['sample_rate'] = sr

        except Exception as e:
            result['evidence'].append(f"librosa analysis error: {str(e)}")

    elif AVAILABLE.get('numpy'):
        # Numpy-only fallback: read raw PCM/WAV and do real FFT
        try:
            with open(wav_path, 'rb') as f:
                data = f.read()

            # Skip WAV header if present
            if data[:4] == b'RIFF':
                data = data[44:]

            samples = np.frombuffer(data[:8192], dtype=np.int16).astype(np.float64)
            samples = samples / 32768.0

            # Real FFT
            fft_result = np.fft.rfft(samples)
            magnitudes = np.abs(fft_result)
            geo_mean = np.exp(np.mean(np.log(magnitudes + 1e-10)))
            arith_mean = np.mean(magnitudes)
            flatness = float(geo_mean / (arith_mean + 1e-10))
            result['spectral_flatness_numpy'] = round(flatness, 6)
            result['libraries_used'].append('numpy (FFT fallback)')

            if flatness > 0.2:
                result['risk_score'] += 20
                result['evidence'].append(f"High spectral flatness (numpy FFT): {flatness:.4f}")

        except Exception as e:
            result['evidence'].append(f"numpy FFT fallback error: {str(e)}")

    else:
        result['evidence'].append("WARNING: Neither librosa nor numpy available. Install with: pip install librosa numpy")

    # 3. Resemblyzer speaker embedding (if available)
    if AVAILABLE.get('resemblyzer'):
        try:
            encoder = VoiceEncoder()
            processed = preprocess_wav(wav_path)
            embedding = encoder.embed_utterance(processed)
            result['speaker_embedding_dims'] = len(embedding)
            result['libraries_used'].append('resemblyzer (speaker embedding)')
            result['evidence'].append(
                f"Speaker embedding extracted ({len(embedding)}-dim vector). Ready for voiceprint comparison."
            )
        except Exception as e:
            result['evidence'].append(f"resemblyzer embedding error: {str(e)}")

    # Cleanup temp file
    if wav_path != filepath and os.path.exists(wav_path):
        try:
            os.unlink(wav_path)
        except:
            pass

    # Final verdict
    if result['risk_score'] >= 50:
        result['verdict'] = 'LIKELY_SYNTHETIC'
    elif result['risk_score'] >= 25:
        result['verdict'] = 'SUSPICIOUS'

    return result


# ═══════════════════════════════════════════════════════════════
# IMAGE ANALYSIS MODULE
# ═══════════════════════════════════════════════════════════════
def analyze_image(filepath):
    """Real image forensics using OpenCV, MediaPipe Face Mesh, and exifread."""
    if not os.path.exists(filepath):
        return error_result(f"File not found: {filepath}")

    result = {
        "success": True,
        "engine": "python_ml_image",
        "libraries_used": [],
        "risk_score": 0,
        "verdict": "AUTHENTIC",
        "evidence": [],
    }

    # 1. EXIF forensics via exifread
    if AVAILABLE.get('exifread'):
        try:
            with open(filepath, 'rb') as f:
                tags = exifread.process_file(f, details=False)

            result['libraries_used'].append('exifread')
            exif_data = {}

            # Check for manipulation-tool signatures
            suspicious_software = ['photoshop', 'gimp', 'affinity', 'pixlr', 'faceapp', 'deepfake', 'faceswap', 'reface']
            for key, val in tags.items():
                val_str = str(val)
                exif_data[str(key)] = val_str

                if 'software' in key.lower():
                    if any(s in val_str.lower() for s in suspicious_software):
                        result['risk_score'] += 40
                        result['evidence'].append(
                            f"Suspicious editing software detected in EXIF: {key}={val_str}"
                        )
                    else:
                        result['evidence'].append(f"EXIF Software: {val_str}")

            # Check for stripped EXIF (common in deepfakes)
            if len(tags) < 3:
                result['risk_score'] += 15
                result['evidence'].append(
                    f"Minimal EXIF metadata ({len(tags)} tags): May indicate stripped/regenerated image."
                )

            result['exif_tag_count'] = len(tags)
            if 'Image Make' in tags:
                result['camera_make'] = str(tags['Image Make'])
            if 'Image Model' in tags:
                result['camera_model'] = str(tags['Image Model'])

        except Exception as e:
            result['evidence'].append(f"exifread error: {str(e)}")
    else:
        result['evidence'].append("exifread not available — install with: pip install exifread")

    # 2. OpenCV + MediaPipe Face Mesh analysis
    if AVAILABLE.get('opencv') and AVAILABLE.get('mediapipe'):
        try:
            img = cv2.imread(filepath)
            if img is not None:
                result['libraries_used'].extend(['opencv', 'mediapipe'])
                rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
                h, w = img.shape[:2]
                result['dimensions'] = f"{w}x{h}"

                face_mesh = mp.solutions.face_mesh.FaceMesh(
                    static_image_mode=True,
                    max_num_faces=5,
                    refine_landmarks=True,
                    min_detection_confidence=0.5
                )
                mesh_results = face_mesh.process(rgb)

                if mesh_results.multi_face_landmarks:
                    result['faces_detected'] = len(mesh_results.multi_face_landmarks)

                    for idx, face_landmarks in enumerate(mesh_results.multi_face_landmarks):
                        landmarks = face_landmarks.landmark
                        # Extract key facial landmarks for symmetry analysis
                        # Left eye: 33, Right eye: 263, Nose tip: 1, Chin: 152
                        left_eye = landmarks[33]
                        right_eye = landmarks[263]
                        nose = landmarks[1]

                        # Face symmetry score (asymmetry in deepfakes)
                        eye_dist = math.sqrt(
                            (left_eye.x - right_eye.x) ** 2 +
                            (left_eye.y - right_eye.y) ** 2
                        )
                        nose_center_x = (left_eye.x + right_eye.x) / 2
                        nose_offset = abs(nose.x - nose_center_x) / (eye_dist + 1e-6)
                        result[f'face_{idx}_symmetry_offset'] = round(nose_offset, 4)

                        if nose_offset > 0.15:
                            result['risk_score'] += 20
                            result['evidence'].append(
                                f"Face {idx}: Unusual facial asymmetry (offset={nose_offset:.4f}). "
                                f"May indicate face-swap artifact."
                            )

                        # Check landmark depth consistency (z-values)
                        z_values = [lm.z for lm in landmarks]
                        z_std = float(np.std(z_values)) if AVAILABLE.get('numpy') else 0
                        result[f'face_{idx}_depth_std'] = round(z_std, 6)

                        if z_std < 0.005:
                            result['risk_score'] += 15
                            result['evidence'].append(
                                f"Face {idx}: Abnormally flat facial depth map (z_std={z_std:.6f}). "
                                f"2D face pasted onto scene."
                            )
                else:
                    result['faces_detected'] = 0
                    result['evidence'].append("No faces detected by MediaPipe Face Mesh.")

                face_mesh.close()

                # Error Level Analysis using OpenCV
                # Re-save at quality 95 and compare — real ELA
                temp_resaved = tempfile.mktemp(suffix='.jpg')
                cv2.imwrite(temp_resaved, img, [cv2.IMWRITE_JPEG_QUALITY, 95])
                resaved = cv2.imread(temp_resaved)
                if resaved is not None and AVAILABLE.get('numpy'):
                    diff = cv2.absdiff(img, resaved)
                    ela_mean = float(np.mean(diff))
                    ela_std = float(np.std(diff))
                    result['ela_mean'] = round(ela_mean, 4)
                    result['ela_std'] = round(ela_std, 4)

                    if ela_std > 20:
                        result['risk_score'] += 20
                        result['evidence'].append(
                            f"High ELA variance (std={ela_std:.2f}): Inconsistent compression "
                            f"suggests post-processing or splicing."
                        )
                try:
                    os.unlink(temp_resaved)
                except:
                    pass

            else:
                result['evidence'].append("OpenCV could not decode image file.")

        except Exception as e:
            result['evidence'].append(f"OpenCV/MediaPipe analysis error: {str(e)}")

    elif AVAILABLE.get('opencv'):
        try:
            img = cv2.imread(filepath)
            if img is not None:
                result['libraries_used'].append('opencv')
                h, w = img.shape[:2]
                result['dimensions'] = f"{w}x{h}"
                result['evidence'].append("MediaPipe not available — using OpenCV only. Install with: pip install mediapipe")
        except Exception as e:
            result['evidence'].append(f"OpenCV error: {str(e)}")
    else:
        result['evidence'].append("OpenCV not available — install with: pip install opencv-python-headless")

    # Final verdict
    if result['risk_score'] >= 50:
        result['verdict'] = 'LIKELY_MANIPULATED'
    elif result['risk_score'] >= 25:
        result['verdict'] = 'SUSPICIOUS'

    return result


# ═══════════════════════════════════════════════════════════════
# VIDEO ANALYSIS MODULE
# ═══════════════════════════════════════════════════════════════
def analyze_video(filepath):
    """Real video forensics using OpenCV frame extraction + MediaPipe temporal face mesh."""
    if not os.path.exists(filepath):
        return error_result(f"File not found: {filepath}")

    result = {
        "success": True,
        "engine": "python_ml_video",
        "libraries_used": [],
        "risk_score": 0,
        "verdict": "AUTHENTIC",
        "evidence": [],
    }

    if not AVAILABLE.get('opencv'):
        result['evidence'].append("OpenCV not available. Install with: pip install opencv-python-headless")
        return result

    result['libraries_used'].append('opencv')

    try:
        cap = cv2.VideoCapture(filepath)
        if not cap.isOpened():
            return error_result("OpenCV could not open video file.")

        fps = cap.get(cv2.CAP_PROP_FPS)
        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        duration = frame_count / fps if fps > 0 else 0

        result['fps'] = round(fps, 2)
        result['frame_count'] = frame_count
        result['dimensions'] = f"{width}x{height}"
        result['duration_seconds'] = round(duration, 2)

        # Sample frames for temporal analysis
        sample_interval = max(1, frame_count // 30)  # Analyze ~30 frames
        face_mesh = None
        if AVAILABLE.get('mediapipe'):
            face_mesh = mp.solutions.face_mesh.FaceMesh(
                static_image_mode=False,
                max_num_faces=2,
                refine_landmarks=True,
                min_detection_confidence=0.5,
                min_tracking_confidence=0.5
            )
            result['libraries_used'].append('mediapipe')

        prev_landmarks = None
        landmark_deltas = []
        frame_luminances = []
        face_presence = []
        frame_idx = 0

        while True:
            ret, frame = cap.read()
            if not ret:
                break

            if frame_idx % sample_interval == 0:
                # Track luminance
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                mean_lum = float(gray.mean())
                frame_luminances.append(mean_lum)

                # MediaPipe face tracking
                if face_mesh is not None:
                    rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    mesh_results = face_mesh.process(rgb)

                    if mesh_results.multi_face_landmarks:
                        face_presence.append(True)
                        current_landmarks = [
                            (lm.x, lm.y, lm.z)
                            for lm in mesh_results.multi_face_landmarks[0].landmark
                        ]

                        if prev_landmarks is not None and AVAILABLE.get('numpy'):
                            # Calculate temporal landmark stability
                            curr_arr = np.array(current_landmarks[:68])  # Key points
                            prev_arr = np.array(prev_landmarks[:68])
                            delta = float(np.mean(np.linalg.norm(curr_arr - prev_arr, axis=1)))
                            landmark_deltas.append(delta)

                        prev_landmarks = current_landmarks
                    else:
                        face_presence.append(False)

            frame_idx += 1

        cap.release()
        if face_mesh:
            face_mesh.close()

        # Temporal analysis
        if AVAILABLE.get('numpy') and len(frame_luminances) > 2:
            lum_std = float(np.std(frame_luminances))
            result['luminance_std'] = round(lum_std, 4)

            if lum_std > 30:
                result['risk_score'] += 15
                result['evidence'].append(
                    f"High luminance variance (std={lum_std:.2f}): Inconsistent lighting across frames."
                )

        # Face presence flicker detection
        if len(face_presence) > 5:
            face_ratio = sum(face_presence) / len(face_presence)
            result['face_detection_ratio'] = round(face_ratio, 4)

            # Face flickering (appears and disappears) is a deepfake artifact
            transitions = sum(1 for i in range(1, len(face_presence)) if face_presence[i] != face_presence[i-1])
            result['face_flicker_count'] = transitions

            if transitions > len(face_presence) * 0.3:
                result['risk_score'] += 30
                result['evidence'].append(
                    f"Face detection flickering ({transitions} transitions in {len(face_presence)} samples): "
                    f"Temporal face instability characteristic of deepfake generation."
                )

        # Landmark temporal stability
        if AVAILABLE.get('numpy') and len(landmark_deltas) > 2:
            delta_std = float(np.std(landmark_deltas))
            delta_mean = float(np.mean(landmark_deltas))
            result['landmark_delta_mean'] = round(delta_mean, 6)
            result['landmark_delta_std'] = round(delta_std, 6)

            # Very low variance = unnaturally smooth (GAN-generated)
            if delta_std < 0.001 and delta_mean > 0:
                result['risk_score'] += 25
                result['evidence'].append(
                    f"Abnormally smooth facial motion (delta_std={delta_std:.6f}): "
                    f"Unnaturally consistent landmark movement suggests GAN generation."
                )

    except Exception as e:
        result['evidence'].append(f"Video analysis error: {str(e)}")

    # Final verdict
    if result['risk_score'] >= 50:
        result['verdict'] = 'LIKELY_DEEPFAKE'
    elif result['risk_score'] >= 25:
        result['verdict'] = 'SUSPICIOUS'

    return result


# ═══════════════════════════════════════════════════════════════
# STATUS CHECK
# ═══════════════════════════════════════════════════════════════
def check_status():
    """Return available libraries and readiness status."""
    return {
        "success": True,
        "engine": "python_ml_service",
        "available_libraries": AVAILABLE,
        "ready_modules": {
            "audio": AVAILABLE.get('librosa', False) or AVAILABLE.get('numpy', False),
            "image": AVAILABLE.get('opencv', False),
            "video": AVAILABLE.get('opencv', False),
            "exif": AVAILABLE.get('exifread', False),
            "speaker_embedding": AVAILABLE.get('resemblyzer', False),
        }
    }


# ═══════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(json.dumps(error_result("Usage: ml_service.py <mode> [filepath]")))
        sys.exit(1)

    mode = sys.argv[1].lower()

    if mode == 'status':
        print(json.dumps(check_status(), indent=2))
    elif mode == 'audio' and len(sys.argv) >= 3:
        print(json.dumps(analyze_audio(sys.argv[2])))
    elif mode == 'image' and len(sys.argv) >= 3:
        print(json.dumps(analyze_image(sys.argv[2])))
    elif mode == 'video' and len(sys.argv) >= 3:
        print(json.dumps(analyze_video(sys.argv[2])))
    else:
        print(json.dumps(error_result(f"Unknown mode: {mode}. Use: status, audio, image, video")))
        sys.exit(1)
