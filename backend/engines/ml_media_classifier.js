const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class MlMediaClassifier {
  constructor() {
    this.model = null;
    this.status = 'NOT_LOADED';
    this.sha256Verified = false;
    this.loadModel();
  }

  loadModel() {
    try {
      const modelPath = path.join(__dirname, '..', 'models', 'media_ml_model.json');
      const manifestPath = path.join(__dirname, '..', 'models', 'model_manifest.json');

      if (!fs.existsSync(modelPath) || !fs.existsSync(manifestPath)) {
        this.status = 'FALLBACK';
        return;
      }

      const fileBuffer = fs.readFileSync(modelPath);
      const actualHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
      const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

      const expectedHash = manifest.models && manifest.models['media_ml_model.json'] ? manifest.models['media_ml_model.json'].sha256 : null;

      if (expectedHash && actualHash === expectedHash) {
        this.sha256Verified = true;
      }

      this.model = JSON.parse(fileBuffer.toString('utf8'));
      this.status = 'READY';
    } catch (e) {
      console.warn('[MlMediaClassifier] Failed to load media model, fallback enabled:', e.message);
      this.status = 'FALLBACK';
    }
  }

  predict(features) {
    if (this.status !== 'READY' || !this.model || !features) {
      return {
        model_status: 'FALLBACK',
        model_version: null,
        manipulation_probability: null,
        sha256_verified: false
      };
    }

    const { weights, bias, feature_mean, feature_std } = this.model;

    const rawVec = [
      features.ela_variance || 0,
      features.dqt_quant_error || 0,
      features.metadata_anomaly_score || 0
    ];

    // Feature normalization: (x - mean) / std
    const normVec = rawVec.map((val, i) => (val - (feature_mean[i] || 0)) / (feature_std[i] || 1));

    // Logistic dot product
    let z = bias;
    for (let i = 0; i < normVec.length; i++) {
      z += normVec[i] * weights[i];
    }

    const probability = 1 / (1 + Math.exp(-z));

    return {
      model_status: 'READY',
      model_version: this.model.model_version || '1.0.0',
      model_type: this.model.model_type,
      manipulation_probability: Number(probability.toFixed(3)),
      sha256_verified: this.sha256Verified,
      metrics: this.model.metrics
    };
  }
}

module.exports = new MlMediaClassifier();
