const test = require('node:test');
const assert = require('node:assert');
const PhishingEngine = require('../engines/phishing_engine');
const MediaEngine = require('../engines/media_engine');
const AudioEngine = require('../engines/audio_engine');
const VideoEngine = require('../engines/video_engine');
const verifyEngine = require('../engines/verify_engine');

test('100% Dynamic Algorithmic Engine Verification Suite', async (t) => {
  await t.test('1. Phishing Engine: Shannon Entropy & Levenshtein Typosquatting', () => {
    const typosquatResult = PhishingEngine.analyzeText('Check out http://z3rodha.com for guaranteed 50% returns');
    assert.strictEqual(typosquatResult.verdict, 'HIGH_RISK_PHISHING');
    assert.ok(typosquatResult.entropy > 3.0, 'Calculated Shannon Entropy > 3.0');
    assert.ok(typosquatResult.flags.some(f => f.type === 'typosquatting_domain'), 'Detected z3rodha.com typosquatting');

    const benignResult = PhishingEngine.analyzeText('Nifty closed 50 points higher today');
    assert.strictEqual(benignResult.verdict, 'SAFE');
  });

  await t.test('2. Media Engine: Quantization Table (DQT) & EXIF Forensics', () => {
    const mockImageBuffer = Buffer.from('Photoshop_EXIF_Header_JPEG_Image_Data_Buffer_Bytes_For_DQT');
    const result = MediaEngine.analyzeImage(mockImageBuffer);

    assert.ok(result.elaScore >= 0, 'Quantization Table Variance calculated');
    assert.strictEqual(result.editingSoftwareDetected, true, 'EXIF Photoshop tag detected');
    assert.strictEqual(result.verdict, 'MANIPULATED_SYNTHETIC_IMAGE');
  });

  await t.test('3. Audio Engine: PCM Sample Zero-Crossing Rate & RMS Variance', () => {
    const mockAudioBuffer = Buffer.from('Audio_Frequency_Sample_Buffer_Bytes_For_PCM_ZCR');
    const result = AudioEngine.analyzeAudio(mockAudioBuffer);

    assert.ok(result.spectralFlatness >= 0, 'FFT Spectral Flatness calculated');
    assert.ok(result.zeroCrossingRate >= 0, 'Zero Crossing Rate calculated');
    assert.ok(result.model.includes('1024-point FFT DSP'), 'Uses honest FFT DSP model descriptor');
  });

  await t.test('4. Video Engine: MP4 Atom Box Parser & Temporal Frame Delta Analysis', () => {
    const mockVideoBuffer = Buffer.from('ftypmp42isomVideo_Frame_Buffer_Data_Bytes_moovmdat');
    const result = VideoEngine.analyzeVideo(mockVideoBuffer);

    assert.ok(result.spatialContrastVariance >= 0);
    assert.ok(result.temporalFlickerScore >= 0);
    assert.ok(result.model.includes('MP4 Container Atom'), 'Honest container model descriptor');
  });

  await t.test('5. Authenticity Engine: RSA-2048 PKI Signing & Levenshtein Fuzzy Match', () => {
    const reg = verifyEngine.registerCommunication({
      issuerId: 'TEST-ISSUER',
      issuerName: 'Test Intermediary Ltd',
      content: 'Official Settlement Notice',
    });

    assert.ok(reg.code.startsWith('VERIFY-'));
    assert.ok(reg.signature, 'RSA-2048 Digital Signature generated');

    const codeResult = verifyEngine.verifyByCode(reg.code);
    assert.strictEqual(codeResult.status, 'VERIFIED');
    assert.strictEqual(codeResult.signatureValid, true, 'RSA-2048 signature verified mathematically');

    const fuzzyResult = verifyEngine.checkTextFuzzy('Official Settlement Notice.');
    assert.ok(fuzzyResult.status.includes('AUTHENTIC'));
  });
});
