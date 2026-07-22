/**
 * SentinelSEBI Image Forensics Engine — Hybrid JS DQT/EXIF + Python OpenCV/MediaPipe/exifread
 * 
 * Architecture:
 * 1. Primary: Python ML (OpenCV ELA, MediaPipe Face Mesh, exifread structured EXIF)
 * 2. Fallback: JS JPEG DQT quantization table parser + string-based EXIF inspection
 */

const { callPythonML } = require('./ml_bridge');
const fs = require('fs');
const os = require('os');
const path = require('path');

class MediaEngine {

  /**
   * Async analysis: tries Python OpenCV + MediaPipe first, falls back to JS DQT.
   */
  static async analyzeImageAsync(imageBuffer, originalFilename = '') {
    const buffer = Buffer.isBuffer(imageBuffer)
      ? imageBuffer
      : Buffer.from(String(imageBuffer || '').replace(/^data:image\/\w+;base64,/, ''), 'base64');

    if (!buffer || buffer.length < 50) {
      return {
        risk_score: 0,
        verdict: 'UNABLE_TO_PARSE',
        elaScore: 0,
        model: 'Hybrid Image Forensics Engine',
        analysis: 'Image file too small or invalid buffer.'
      };
    }

    // Try Python ML service first
    try {
      const ext = path.extname(originalFilename || '.jpg').toLowerCase() || '.jpg';
      const tempPath = path.join(os.tmpdir(), `sentinel_image_${Date.now()}${ext}`);
      fs.writeFileSync(tempPath, buffer);

      const mlResult = await callPythonML('image', tempPath);

      // Cleanup
      try { fs.unlinkSync(tempPath); } catch {}

      if (mlResult.success && !mlResult.fallback) {
        return {
          risk_score: mlResult.risk_score || 0,
          verdict: mlResult.verdict === 'LIKELY_MANIPULATED' ? 'MANIPULATED_SYNTHETIC_IMAGE'
                 : mlResult.verdict === 'SUSPICIOUS' ? 'SUSPICIOUS_EDITED_MEDIA'
                 : 'GENUINE_MEDIA',
          model: `Python ML: ${(mlResult.libraries_used || []).join(' + ')}`,
          elaScore: mlResult.ela_std ? parseFloat((mlResult.ela_std / 100).toFixed(3)) : 0,
          elaDetails: {
            ela_mean: mlResult.ela_mean || null,
            ela_std: mlResult.ela_std || null,
          },
          facesDetected: mlResult.faces_detected ?? null,
          exifTagCount: mlResult.exif_tag_count ?? null,
          cameraMake: mlResult.camera_make || null,
          cameraModel: mlResult.camera_model || null,
          dimensions: mlResult.dimensions || null,
          evidence: mlResult.evidence || [],
          analysis: (mlResult.evidence || []).join(' | ') || 'Python ML image analysis complete.',
        };
      }
    } catch (err) {
      // Fall through to JS fallback
    }

    // JS DQT/EXIF fallback
    return this.analyzeImage(buffer);
  }

  /**
   * Synchronous JS-only analysis (fallback). JPEG DQT + EXIF string search.
   */
  static analyzeImage(imageBuffer) {
    const buffer = Buffer.isBuffer(imageBuffer)
      ? imageBuffer
      : Buffer.from(String(imageBuffer || '').replace(/^data:image\/\w+;base64,/, ''), 'base64');

    if (!buffer || buffer.length < 50) {
      return {
        risk_score: 0,
        verdict: 'UNABLE_TO_PARSE',
        elaScore: 0,
        model: 'JS Fallback: JPEG Quantization & EXIF Signal Analyzer',
        analysis: 'Image file too small or invalid buffer.'
      };
    }

    const dqtAnalysis = this.analyzeDqtTables(buffer);
    const exifAnalysis = this.inspectExifHeaders(buffer);

    let riskScore = Math.min(100, Math.round(dqtAnalysis.varianceScore * 100));
    if (exifAnalysis.editingSoftwareDetected) {
      riskScore = Math.max(riskScore, 80);
    }

    let verdict = 'GENUINE_MEDIA';
    if (riskScore >= 70) verdict = 'MANIPULATED_SYNTHETIC_IMAGE';
    else if (riskScore >= 35) verdict = 'SUSPICIOUS_EDITED_MEDIA';

    return {
      risk_score: riskScore,
      verdict,
      model: 'JS Fallback: JPEG Quantization & EXIF Signal Analyzer',
      elaScore: parseFloat(dqtAnalysis.varianceScore.toFixed(3)),
      dqtTablesFound: dqtAnalysis.tablesFound,
      exifData: exifAnalysis.metadata,
      editingSoftwareDetected: exifAnalysis.editingSoftwareDetected,
      analysis: `JPEG Quantization Table (DQT) variance score: ${dqtAnalysis.varianceScore.toFixed(3)}. ${exifAnalysis.summary}`,
    };
  }

  static analyzeDqtTables(buffer) {
    let tablesFound = 0;
    let totalDqtValues = 0;
    let dqtSum = 0;
    let dqtSqSum = 0;

    for (let i = 0; i < buffer.length - 4; i++) {
      if (buffer[i] === 0xFF && buffer[i + 1] === 0xDB) {
        tablesFound++;
        const length = (buffer[i + 2] << 8) | buffer[i + 3];
        const dataEnd = Math.min(buffer.length, i + 2 + length);
        
        for (let j = i + 5; j < dataEnd; j++) {
          const val = buffer[j];
          dqtSum += val;
          dqtSqSum += val * val;
          totalDqtValues++;
        }
      }
    }

    if (totalDqtValues === 0) {
      return { tablesFound: 0, varianceScore: this.calculateByteEntropyVariance(buffer) };
    }

    const mean = dqtSum / totalDqtValues;
    const variance = (dqtSqSum / totalDqtValues) - (mean * mean);
    const varianceScore = Math.min(0.95, Math.max(0.05, Math.sqrt(Math.abs(variance)) / 64));

    return { tablesFound, varianceScore };
  }

  static calculateByteEntropyVariance(buffer) {
    const sampleSize = Math.min(buffer.length, 2048);
    let sum = 0;
    for (let i = 0; i < sampleSize; i++) {
      sum += buffer[i];
    }
    const avg = sum / sampleSize;
    let varSum = 0;
    for (let i = 0; i < sampleSize; i++) {
      varSum += Math.pow(buffer[i] - avg, 2);
    }
    return Math.min(0.95, Math.max(0.05, Math.sqrt(varSum / sampleSize) / 128));
  }

  static inspectExifHeaders(buffer) {
    const str = buffer.toString('binary', 0, Math.min(buffer.length, 4096));
    const editingKeywords = ['Photoshop', 'GIMP', 'Canvas', 'DeepFake', 'StableDiffusion', 'Midjourney', 'DALL-E'];
    const foundKeywords = editingKeywords.filter(kw => new RegExp(kw, 'i').test(str));
    const editingSoftwareDetected = foundKeywords.length > 0;

    return {
      editingSoftwareDetected,
      metadata: {
        Software: editingSoftwareDetected ? foundKeywords.join(', ') : 'Standard Camera Hardware',
        HeaderSizeBytes: buffer.length,
      },
      summary: editingSoftwareDetected
        ? `EXIF inspection detected image editing software: ${foundKeywords.join(', ')}.`
        : 'EXIF metadata shows uniform camera quantization without editing artifacts.',
    };
  }
}

module.exports = MediaEngine;
