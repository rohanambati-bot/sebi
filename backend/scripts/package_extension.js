const fs = require('fs');
const path = require('path');

function createZipFile(sourceDir, outPath) {
  const files = fs.readdirSync(sourceDir);
  const zipEntries = [];

  files.forEach(fileName => {
    const filePath = path.join(sourceDir, fileName);
    if (fs.statSync(filePath).isFile()) {
      const content = fs.readFileSync(filePath);
      zipEntries.push({ name: fileName, content });
    }
  });

  const localHeaderBuffers = [];
  const cdHeaderBuffers = [];
  let currentOffset = 0;

  zipEntries.forEach(entry => {
    const nameBuf = Buffer.from(entry.name, 'utf8');
    const contentBuf = entry.content;
    const crc32 = crc32Checksum(contentBuf);
    const size = contentBuf.length;

    const localHeader = Buffer.alloc(30 + nameBuf.length);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0, 6);
    localHeader.writeUInt16LE(0, 8);
    localHeader.writeUInt16LE(0, 10);
    localHeader.writeUInt16LE(0, 12);
    localHeader.writeUInt32LE(crc32, 14);
    localHeader.writeUInt32LE(size, 18);
    localHeader.writeUInt32LE(size, 22);
    localHeader.writeUInt16LE(nameBuf.length, 26);
    localHeader.writeUInt16LE(0, 28);
    nameBuf.copy(localHeader, 30);

    localHeaderBuffers.push(localHeader);
    localHeaderBuffers.push(contentBuf);

    const cdHeader = Buffer.alloc(46 + nameBuf.length);
    cdHeader.writeUInt32LE(0x02014b50, 0);
    cdHeader.writeUInt16LE(20, 4);
    cdHeader.writeUInt16LE(20, 6);
    cdHeader.writeUInt16LE(0, 8);
    cdHeader.writeUInt16LE(0, 10);
    cdHeader.writeUInt16LE(0, 12);
    cdHeader.writeUInt16LE(0, 14);
    cdHeader.writeUInt32LE(crc32, 16);
    cdHeader.writeUInt32LE(size, 20);
    cdHeader.writeUInt32LE(size, 24);
    cdHeader.writeUInt16LE(nameBuf.length, 28);
    cdHeader.writeUInt16LE(0, 30);
    cdHeader.writeUInt16LE(0, 32);
    cdHeader.writeUInt16LE(0, 34);
    cdHeader.writeUInt16LE(0, 36);
    cdHeader.writeUInt32LE(0, 38);
    cdHeader.writeUInt32LE(currentOffset, 42);
    nameBuf.copy(cdHeader, 46);

    cdHeaderBuffers.push(cdHeader);
    currentOffset += localHeader.length + contentBuf.length;
  });

  const cdOffset = currentOffset;
  let cdSize = 0;
  cdHeaderBuffers.forEach(buf => { cdSize += buf.length; });

  const eocdHeader = Buffer.alloc(22);
  eocdHeader.writeUInt32LE(0x06054b50, 0);
  eocdHeader.writeUInt16LE(0, 4);
  eocdHeader.writeUInt16LE(0, 6);
  eocdHeader.writeUInt16LE(zipEntries.length, 8);
  eocdHeader.writeUInt16LE(zipEntries.length, 10);
  eocdHeader.writeUInt32LE(cdSize, 12);
  eocdHeader.writeUInt32LE(cdOffset, 16);
  eocdHeader.writeUInt16LE(0, 20);

  const finalZipBuffer = Buffer.concat([...localHeaderBuffers, ...cdHeaderBuffers, eocdHeader]);
  fs.writeFileSync(outPath, finalZipBuffer);
  return finalZipBuffer;
}

function crc32Checksum(buf) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i];
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
    }
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function ensureExtensionZip() {
  const extDir = path.join(__dirname, '..', '..', 'extension');
  const frontendOut = path.join(__dirname, '..', '..', 'frontend', 'sentinel_sebi_extension.zip');
  return createZipFile(extDir, frontendOut);
}

if (require.main === module) {
  ensureExtensionZip();
  console.log('✓ Extension ZIP packaged cleanly.');
}

module.exports = { ensureExtensionZip };
