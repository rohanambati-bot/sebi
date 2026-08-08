const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function hashObject(obj) {
  const str = typeof obj === 'string' ? obj : JSON.stringify(obj);
  return crypto.createHash('sha256').update(str).digest('hex');
}

function validateModality(modalityDir, textField) {
  const modalityName = path.basename(modalityDir);
  console.log(`\n🔍 Validating Dataset & Campaign Leakage Integrity for [${modalityName}]...`);

  const trainPath = path.join(modalityDir, 'train.json');
  const valPath = path.join(modalityDir, 'validation.json');
  const testPath = path.join(modalityDir, 'test.json');

  const trainData = fs.existsSync(trainPath) ? JSON.parse(fs.readFileSync(trainPath, 'utf8')) : [];
  const valData = fs.existsSync(valPath) ? JSON.parse(fs.readFileSync(valPath, 'utf8')) : [];
  const testData = fs.existsSync(testPath) ? JSON.parse(fs.readFileSync(testPath, 'utf8')) : [];

  // 1. Exact Duplicate Content Check
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

  // 2. Campaign & Speaker Group Leakage Check
  const getGroup = item => item.campaign || item.speaker || item.source_group || null;
  const trainCampaigns = new Set(trainData.map(getGroup).filter(Boolean));
  const valCampaigns = new Set(valData.map(getGroup).filter(Boolean));
  const testCampaigns = new Set(testData.map(getGroup).filter(Boolean));

  let campaignLeakage = 0;
  for (const c of trainCampaigns) {
    if (valCampaigns.has(c) || testCampaigns.has(c)) campaignLeakage++;
  }
  for (const c of valCampaigns) {
    if (testCampaigns.has(c)) campaignLeakage++;
  }

  console.log(`  • Train samples:         ${trainData.length} (${trainCampaigns.size} distinct campaigns)`);
  console.log(`  • Validation samples:    ${valData.length} (${valCampaigns.size} distinct campaigns)`);
  console.log(`  • Test samples:          ${testData.length} (${testCampaigns.size} distinct campaigns)`);
  console.log(`  • Cross-split exact duplicates: ${crossSplitDuplicates}`);
  console.log(`  • Campaign/group leakage count: ${campaignLeakage}`);

  if (crossSplitDuplicates > 0 || campaignLeakage > 0) {
    console.error(`❌ ERROR: Data or Campaign leakage detected in ${modalityDir}`);
    process.exit(1);
  }
  console.log(`  ✓ DATASET INTEGRITY & CAMPAIGN LEAKAGE VERIFIED (0 Leakage)`);
}

function runValidation() {
  const baseDir = path.join(__dirname, '..', 'ml_data');
  validateModality(path.join(baseDir, 'phishing'), 'text');
  validateModality(path.join(baseDir, 'audio'), 'id');
  validateModality(path.join(baseDir, 'media'), 'id');
  console.log('\n✅ ALL DATASETS PASSED INTEGRITY, DUPLICATE, AND CAMPAIGN LEAKAGE VALIDATION CLEANLY.\n');
}

runValidation();
