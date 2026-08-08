const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class MlPhishingClassifier {
  constructor() {
    this.model = null;
    this.status = 'NOT_LOADED';
    this.sha256Verified = false;
    this.loadModel();
  }

  loadModel() {
    try {
      const modelPath = path.join(__dirname, '..', 'models', 'phishing_ml_model.json');
      const manifestPath = path.join(__dirname, '..', 'models', 'model_manifest.json');

      if (!fs.existsSync(modelPath) || !fs.existsSync(manifestPath)) {
        this.status = 'FALLBACK';
        return;
      }

      const fileBuffer = fs.readFileSync(modelPath);
      const actualHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
      const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

      const expectedHash = manifest.models && manifest.models['phishing_ml_model.json'] ? manifest.models['phishing_ml_model.json'].sha256 : null;

      if (!expectedHash || actualHash !== expectedHash) {
        console.warn('[MlPhishingClassifier] SHA-256 integrity hash mismatch! Forcing FALLBACK.');
        this.status = 'FALLBACK';
        this.sha256Verified = false;
        this.model = null;
        return;
      }

      this.sha256Verified = true;
      this.model = JSON.parse(fileBuffer.toString('utf8'));
      this.status = 'READY';
    } catch (e) {
      console.warn('[MlPhishingClassifier] Failed to load model, fallback enabled:', e.message);
      this.status = 'FALLBACK';
    }
  }

  tokenize(text) {
    const clean = text.toLowerCase().replace(/[^a-z0-9\s]/g, ' ');
    const words = clean.split(/\s+/).filter(w => w.length > 1);
    const ngrams = [...words];

    for (let i = 0; i < words.length - 1; i++) {
      ngrams.push(`${words[i]}_${words[i+1]}`);
      if (i < words.length - 2) {
        ngrams.push(`${words[i]}_${words[i+1]}_${words[i+2]}`);
      }
    }

    for (let i = 0; i < clean.length - 2; i++) {
      ngrams.push(`char_${clean.substring(i, i + 3)}`);
    }

    return ngrams;
  }

  predict(text) {
    if (this.status !== 'READY' || !this.model) {
      return {
        model_status: 'FALLBACK',
        model_version: null,
        ml_probability: null,
        sha256_verified: false,
        top_features: []
      };
    }

    const tokens = this.tokenize(text);
    const { log_priors, log_likelihoods } = this.model;

    let scorePhishing = log_priors.phishing;
    let scoreLegit = log_priors.legitimate;
    const matchedFeatures = [];

    tokens.forEach(token => {
      if (log_likelihoods.phishing[token] !== undefined) {
        scorePhishing += log_likelihoods.phishing[token];
        scoreLegit += log_likelihoods.legitimate[token];
        const diff = log_likelihoods.phishing[token] - log_likelihoods.legitimate[token];
        if (diff > 0.5) matchedFeatures.push({ token, weight: Number(diff.toFixed(3)) });
      }
    });

    // Log-Sum-Exp normalization to compute genuine probability
    const maxScore = Math.max(scorePhishing, scoreLegit);
    const expPhish = Math.exp(scorePhishing - maxScore);
    const expLegit = Math.exp(scoreLegit - maxScore);
    const probability = expPhish / (expPhish + expLegit);

    matchedFeatures.sort((a, b) => b.weight - a.weight);

    return {
      model_status: 'READY',
      model_version: this.model.model_version || '1.0.0',
      model_type: this.model.model_type,
      ml_probability: Number(probability.toFixed(3)),
      sha256_verified: this.sha256Verified,
      metrics: this.model.metrics,
      top_features: matchedFeatures.slice(0, 5)
    };
  }
}

module.exports = new MlPhishingClassifier();
