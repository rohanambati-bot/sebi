const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function computeSha256(filePath) {
  const fileBuffer = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(fileBuffer).digest('hex');
}

function tokenize(text) {
  const clean = text.toLowerCase().replace(/[^a-z0-9\s]/g, ' ');
  const words = clean.split(/\s+/).filter(w => w.length > 1);
  const ngrams = [...words];

  // Word 2-grams & 3-grams
  for (let i = 0; i < words.length - 1; i++) {
    ngrams.push(`${words[i]}_${words[i+1]}`);
    if (i < words.length - 2) {
      ngrams.push(`${words[i]}_${words[i+1]}_${words[i+2]}`);
    }
  }

  // Character 3-grams
  for (let i = 0; i < clean.length - 2; i++) {
    ngrams.push(`char_${clean.substring(i, i + 3)}`);
  }

  return ngrams;
}

function trainPhishingTextModel() {
  console.log('\n🤖 Training Phishing Text ML Classifier (Multinomial Naive Bayes with TF-IDF Vectorization)...');
  const trainPath = path.join(__dirname, '..', 'ml_data', 'phishing', 'train.json');
  const dataset = JSON.parse(fs.readFileSync(trainPath, 'utf8'));

  const N = dataset.length;
  const df = {};
  const docCounts = { phishing: 0, legitimate: 0 };
  const termTfIdfSum = { phishing: {}, legitimate: {} };
  const totalTfIdfSum = { phishing: 0, legitimate: 0 };

  // 1. Calculate Document Frequency (DF)
  dataset.forEach(item => {
    docCounts[item.label]++;
    const uniqueTokens = new Set(tokenize(item.text));
    uniqueTokens.forEach(t => { df[t] = (df[t] || 0) + 1; });
  });

  // 2. Calculate Smooth IDF: log((N + 1) / (df + 1)) + 1
  const idf = {};
  Object.keys(df).forEach(t => {
    idf[t] = Math.log((N + 1) / (df[t] + 1)) + 1;
  });

  // 3. Compute TF-IDF weights per document
  dataset.forEach(item => {
    const label = item.label;
    const tokens = tokenize(item.text);
    const tf = {};
    tokens.forEach(t => { tf[t] = (tf[t] || 0) + 1; });

    Object.keys(tf).forEach(t => {
      const tfidfWeight = (tf[t] / tokens.length) * idf[t];
      termTfIdfSum[label][t] = (termTfIdfSum[label][t] || 0) + tfidfWeight;
      totalTfIdfSum[label] += tfidfWeight;
    });
  });

  const vocab = Object.keys(df);
  const vocabSize = vocab.length;
  const alpha = 1.0; // Laplace smoothing

  const logPriors = {
    phishing: Math.log(docCounts.phishing / N),
    legitimate: Math.log(docCounts.legitimate / N)
  };

  const logLikelihoods = { phishing: {}, legitimate: {} };

  vocab.forEach(t => {
    logLikelihoods.phishing[t] = Math.log(((termTfIdfSum.phishing[t] || 0) + alpha) / (totalTfIdfSum.phishing + alpha * vocabSize));
    logLikelihoods.legitimate[t] = Math.log(((termTfIdfSum.legitimate[t] || 0) + alpha) / (totalTfIdfSum.legitimate + alpha * vocabSize));
  });

  const modelPayload = {
    model_version: "1.0.0",
    model_type: "multinomial_naive_bayes_tfidf",
    trained_at: new Date().toISOString(),
    dataset_version: "phishing-v1",
    feature_schema: "word_char_1_2_3_grams_tfidf",
    training_samples: N,
    alpha: alpha,
    vocab_size: vocabSize,
    idf: idf,
    log_priors: logPriors,
    log_likelihoods: logLikelihoods
  };

  const outPath = path.join(__dirname, '..', 'models', 'phishing_ml_model.json');
  fs.writeFileSync(outPath, JSON.stringify(modelPayload, null, 2));
  console.log(`  ✓ Saved Phishing Text ML Model to ${outPath}`);
}

function trainAudioModel() {
  console.log('\n🤖 Training Audio Synthetic Speech ML Classifier (Gaussian Acoustic)...');
  const trainPath = path.join(__dirname, '..', 'ml_data', 'audio', 'train.json');
  const dataset = JSON.parse(fs.readFileSync(trainPath, 'utf8'));

  const synthFeatures = [];
  const humanFeatures = [];

  dataset.forEach(item => {
    const f = item.features;
    const vec = [f.zcr, f.spectral_centroid, f.spectral_bandwidth, f.spectral_rolloff, f.energy_variance, ...f.mfccs];
    if (item.label === 'synthetic_speech') synthFeatures.push(vec);
    else humanFeatures.push(vec);
  });

  function computeStats(matrix) {
    const numCols = matrix[0].length;
    const numRows = matrix.length;
    const means = new Array(numCols).fill(0);
    const vars = new Array(numCols).fill(0);

    for (let j = 0; j < numCols; j++) {
      let sum = 0;
      for (let i = 0; i < numRows; i++) sum += matrix[i][j];
      means[j] = sum / numRows;

      let varSum = 0;
      for (let i = 0; i < numRows; i++) varSum += Math.pow(matrix[i][j] - means[j], 2);
      vars[j] = (varSum / numRows) + 1e-9; // variance floor epsilon
    }
    return { means, vars };
  }

  const synthStats = computeStats(synthFeatures);
  const humanStats = computeStats(humanFeatures);

  const modelPayload = {
    model_version: "1.0.0",
    model_type: "gaussian_acoustic_classifier",
    trained_at: new Date().toISOString(),
    dataset_version: "audio-synth-v1",
    feature_schema: "fft_zcr_centroid_bandwidth_rolloff_energy_mfcc1_13",
    training_samples: dataset.length,
    priors: {
      synthetic_speech: synthFeatures.length / dataset.length,
      natural_human: humanFeatures.length / dataset.length
    },
    synth_stats: synthStats,
    human_stats: humanStats
  };

  const outPath = path.join(__dirname, '..', 'models', 'audio_ml_model.json');
  fs.writeFileSync(outPath, JSON.stringify(modelPayload, null, 2));
  console.log(`  ✓ Saved Audio Synthetic Speech ML Model to ${outPath}`);
}

function trainMediaModel() {
  console.log('\n🤖 Training Image Manipulation Artifact ML Classifier (Dynamic Logistic Regression Training)...');
  const trainPath = path.join(__dirname, '..', 'ml_data', 'media', 'train.json');
  const dataset = JSON.parse(fs.readFileSync(trainPath, 'utf8'));

  // Extract feature columns
  const elaVals = dataset.map(d => d.features.ela_variance);
  const dqtVals = dataset.map(d => d.features.dqt_quant_error);
  const metaVals = dataset.map(d => d.features.metadata_anomaly_score);

  const meanEla = elaVals.reduce((a, b) => a + b, 0) / elaVals.length;
  const stdEla = Math.sqrt(elaVals.reduce((a, b) => a + Math.pow(b - meanEla, 2), 0) / elaVals.length) || 1;

  const meanDqt = dqtVals.reduce((a, b) => a + b, 0) / dqtVals.length;
  const stdDqt = Math.sqrt(dqtVals.reduce((a, b) => a + Math.pow(b - meanDqt, 2), 0) / dqtVals.length) || 1;

  const meanMeta = metaVals.reduce((a, b) => a + b, 0) / metaVals.length;
  const stdMeta = Math.sqrt(metaVals.reduce((a, b) => a + Math.pow(b - meanMeta, 2), 0) / metaVals.length) || 1;

  // Batch Gradient Descent Logistic Regression Training
  let w0 = 0.1, w1 = 0.1, w2 = 0.1, b = 0.0;
  const lr = 0.1;
  const epochs = 300;

  for (let epoch = 0; epoch < epochs; epoch++) {
    let dw0 = 0, dw1 = 0, dw2 = 0, db = 0;
    dataset.forEach(item => {
      const x0 = (item.features.ela_variance - meanEla) / stdEla;
      const x1 = (item.features.dqt_quant_error - meanDqt) / stdDqt;
      const x2 = (item.features.metadata_anomaly_score - meanMeta) / stdMeta;
      const y = item.label === 'manipulated' ? 1 : 0;

      const z = w0 * x0 + w1 * x1 + w2 * x2 + b;
      const p = 1 / (1 + Math.exp(-Math.max(-10, Math.min(10, z))));
      const err = p - y;

      dw0 += err * x0;
      dw1 += err * x1;
      dw2 += err * x2;
      db += err;
    });

    const m = dataset.length;
    w0 -= lr * (dw0 / m);
    w1 -= lr * (dw1 / m);
    w2 -= lr * (dw2 / m);
    b -= lr * (db / m);
  }

  const modelPayload = {
    model_version: "1.0.0",
    model_type: "logistic_ela_dqt_classifier",
    trained_at: new Date().toISOString(),
    dataset_version: "media-manipulation-v1",
    feature_schema: "ela_variance_dqt_quant_error_metadata_anomaly",
    training_samples: dataset.length,
    weights: [Number(w0.toFixed(4)), Number(w1.toFixed(4)), Number(w2.toFixed(4))],
    bias: Number(b.toFixed(4)),
    feature_mean: [Number(meanEla.toFixed(4)), Number(meanDqt.toFixed(4)), Number(meanMeta.toFixed(4))],
    feature_std: [Number(stdEla.toFixed(4)), Number(stdDqt.toFixed(4)), Number(stdMeta.toFixed(4))]
  };

  const outPath = path.join(__dirname, '..', 'models', 'media_ml_model.json');
  fs.writeFileSync(outPath, JSON.stringify(modelPayload, null, 2));
  console.log(`  ✓ Dynamically Trained Image Manipulation ML Model saved to ${outPath}`);
}

function generateManifest() {
  console.log('\n🔐 Generating Cryptographic SHA-256 Model Manifest (model_manifest.json)...');
  const modelsDir = path.join(__dirname, '..', 'models');

  const files = ['phishing_ml_model.json', 'audio_ml_model.json', 'media_ml_model.json'];
  const manifest = {
    manifest_version: "1.0.0",
    generated_at: new Date().toISOString(),
    models: {}
  };

  files.forEach(file => {
    const fullPath = path.join(modelsDir, file);
    if (fs.existsSync(fullPath)) {
      const sha256 = computeSha256(fullPath);
      const modelData = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
      manifest.models[file] = {
        sha256: sha256,
        model_version: modelData.model_version || "1.0.0",
        model_type: modelData.model_type
      };
    }
  });

  const manifestPath = path.join(modelsDir, 'model_manifest.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  console.log(`  ✓ Generated SHA-256 Model Manifest at ${manifestPath}`);
}

function runAll() {
  const modelsDir = path.join(__dirname, '..', 'models');
  if (!fs.existsSync(modelsDir)) fs.mkdirSync(modelsDir, { recursive: true });

  trainPhishingTextModel();
  trainAudioModel();
  trainMediaModel();
  generateManifest();
  console.log('\n✅ ALL MULTI-MODAL ML MODELS TRAINED DYNAMICALLY & MANIFEST GENERATED CLEANLY.\n');
}

runAll();
