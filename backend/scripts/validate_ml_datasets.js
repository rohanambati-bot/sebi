const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function hashObject(obj) {
  const str = typeof obj === 'string' ? obj : JSON.stringify(obj);
  return crypto.createHash('sha256').update(str).digest('hex');
}

function validateModality(modalityDir, textField) {
  console.log(`\n🔍 Validating Dataset Integrity for [${path.basename(modalityDir)}]...`);

  const trainPath = path.join(modalityDir, 'train.json');
  const valPath = path.join(modalityDir, 'validation.json');
  const testPath = path.join(modalityDir, 'test.json');

  const trainData = fs.existsSync(trainPath) ? JSON.parse(fs.readFileSync(trainPath, 'utf8')) : [];
  const valData = fs.existsSync(valPath) ? JSON.parse(fs.readFileSync(valPath, 'utf8')) : [];
  const testData = fs.existsSync(testPath) ? JSON.parse(fs.readFileSync(testPath, 'utf8')) : [];

  const trainHashes = new Set(trainData.map(item => hashObject(textField ? item[textField] : item)));
  const valHashes = new Set(valData.map(item => hashObject(textField ? item[textField] : item)));
  const testHashes = new Set(testData.map(item => hashObject(textField ? item[textField] : item)));

  let crossSplitDuplicates = 0;
  for (const h of trainHashes) {
    if (valHashes.has(h) || testHashes.has(h)) crossSplitDuplicates++;
  }
  for (const h of valHashes) {
    if (testHashes.has(h)) crossSplitDuplicates++;
  }

  console.log(`  • Train samples:      ${trainData.length}`);
  console.log(`  • Validation samples: ${valData.length}`);
  console.log(`  • Test samples:       ${testData.length}`);
  console.log(`  • Cross-split leakage duplicates: ${crossSplitDuplicates}`);

  if (crossSplitDuplicates > 0) {
    console.error(`❌ ERROR: Data leakage detected in ${modalityDir}`);
    process.exit(1);
  }
  console.log(`  ✓ DATASET INTEGRITY VERIFIED (0 Leakage)`);
}

function runValidation() {
  const baseDir = path.join(__dirname, '..', 'ml_data');
  validateModality(path.join(baseDir, 'phishing'), 'text');
  validateModality(path.join(baseDir, 'audio'), 'id');
  validateModality(path.join(baseDir, 'media'), 'id');
  console.log('\n✅ ALL DATASETS PASSED INTEGRITY & LEAKAGE VALIDATION CLEANLY.\n');
}

runValidation();
