const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class MlAudioClassifier {
  constructor() {
    this.model = null;
    this.status = 'NOT_LOADED';
    this.sha256Verified = false;
    this.loadModel();
  }

  loadModel() {
    try {
      const modelPath = path.join(__dirname, '..', 'models', 'audio_ml_model.json');
      const manifestPath = path.join(__dirname, '..', 'models', 'model_manifest.json');

      if (!fs.existsSync(modelPath) || !fs.existsSync(manifestPath)) {
        this.status = 'FALLBACK';
        return;
      }

      const fileBuffer = fs.readFileSync(modelPath);
      const actualHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
      const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

      const expectedHash = manifest.models && manifest.models['audio_ml_model.json'] ? manifest.models['audio_ml_model.json'].sha256 : null;

      if (expectedHash && actualHash === expectedHash) {
        this.sha256Verified = true;
      }

      this.model = JSON.parse(fileBuffer.toString('utf8'));
      this.status = 'READY';
    } catch (e) {
      console.warn('[MlAudioClassifier] Failed to load audio model, fallback enabled:', e.message);
      this.status = 'FALLBACK';
    }
  }

  predict(features) {
    if (this.status !== 'READY' || !this.model || !features) {
      return {
        model_status: 'FALLBACK',
        model_version: null,
        synthetic_speech_probability: null,
        sha256_verified: false
      };
    }

    // Feature vector: [zcr, centroid, bandwidth, rolloff, energy_var, ...mfccs]
    const vec = [
      features.zcr || 0,
      features.spectral_centroid || 0,
      features.spectral_bandwidth || 0,
      features.spectral_rolloff || 0,
      features.energy_variance || 0,
      ...(features.mfccs || new Array(13).fill(0))
    ];

    const { synth_stats, human_stats, priors } = this.model;

    function gaussianLogPdf(val, mean, variance) {
      return -0.5 * Math.log(2 * Math.PI * variance) - (Math.pow(val - mean, 2) / (2 * variance));
    }

    let logSynth = Math.log(priors.synthetic_speech);
    let logHuman = Math.log(priors.natural_human);

    for (let i = 0; i < vec.length; i++) {
      if (synth_stats.means[i] !== undefined && synth_stats.vars[i] !== undefined) {
        logSynth += gaussianLogPdf(vec[i], synth_stats.means[i], synth_stats.vars[i]);
        logHuman += gaussianLogPdf(vec[i], human_stats.means[i], human_stats.vars[i]);
      }
    }

    const maxLog = Math.max(logSynth, logHuman);
    const expSynth = Math.exp(logSynth - maxLog);
    const expHuman = Math.exp(logHuman - maxLog);
    const probability = expSynth / (expSynth + expHuman);

    return {
      model_status: 'READY',
      model_version: this.model.model_version || '1.0.0',
      model_type: this.model.model_type,
      synthetic_speech_probability: Number(probability.toFixed(3)),
      sha256_verified: this.sha256Verified,
      metrics: this.model.metrics
    };
  }
}

module.exports = new MlAudioClassifier();
