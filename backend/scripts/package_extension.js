const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

// Lightweight zip file creator using Store/Deflate method for Chrome Extension files
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

  // Build zip structure using minimal ZIP format headers
  const localHeaderBuffers = [];
  const cdHeaderBuffers = [];
  let currentOffset = 0;

  zipEntries.forEach(entry => {
    const nameBuf = Buffer.from(entry.name, 'utf8');
    const contentBuf = entry.content;
    const crc32 = crc32Checksum(contentBuf);
    const size = contentBuf.length;

    // Local file header (30 bytes + name length + content length)
    const localHeader = Buffer.alloc(30 + nameBuf.length);
    localHeader.writeUInt32LE(0x04034b50, 0); // Local header signature
    localHeader.writeUInt16LE(20, 4);         // Version needed
    localHeader.writeUInt16LE(0, 6);          // General flag
    localHeader.writeUInt16LE(0, 8);          // Compression method (0 = store)
    localHeader.writeUInt16LE(0, 10);         // Last mod time
    localHeader.writeUInt16LE(0, 12);         // Last mod date
    localHeader.writeUInt32LE(crc32, 14);     // CRC-32
    localHeader.writeUInt32LE(size, 18);      // Compressed size
    localHeader.writeUInt32LE(size, 22);      // Uncompressed size
    localHeader.writeUInt16LE(nameBuf.length, 26); // File name length
    localHeader.writeUInt16LE(0, 28);         // Extra field length
    nameBuf.copy(localHeader, 30);

    localHeaderBuffers.push(localHeader);
    localHeaderBuffers.push(contentBuf);

    // Central directory header (46 bytes + name length)
    const cdHeader = Buffer.alloc(46 + nameBuf.length);
    cdHeader.writeUInt32LE(0x02014b50, 0); // CD header signature
    cdHeader.writeUInt16LE(20, 4);         // Version made by
    cdHeader.writeUInt16LE(20, 6);         // Version needed
    cdHeader.writeUInt16LE(0, 8);          // General flag
    cdHeader.writeUInt16LE(0, 10);         // Compression method (0 = store)
    cdHeader.writeUInt16LE(0, 12);         // Last mod time
    cdHeader.writeUInt16LE(0, 14);         // Last mod date
    cdHeader.writeUInt32LE(crc32, 16);     // CRC-32
    cdHeader.writeUInt32LE(size, 20);      // Compressed size
    cdHeader.writeUInt32LE(size, 24);      // Uncompressed size
    cdHeader.writeUInt16LE(nameBuf.length, 28); // File name length
    cdHeader.writeUInt16LE(0, 30);         // Extra field length
    cdHeader.writeUInt16LE(0, 32);         // Comment length
    cdHeader.writeUInt16LE(0, 34);         // Disk start
    cdHeader.writeUInt16LE(0, 36);         // Internal attributes
    cdHeader.writeUInt32LE(0, 38);         // External attributes
    cdHeader.writeUInt32LE(currentOffset, 42); // Local header offset
    nameBuf.copy(cdHeader, 46);

    cdHeaderBuffers.push(cdHeader);
    currentOffset += localHeader.length + contentBuf.length;
  });

  const cdOffset = currentOffset;
  let cdSize = 0;
  cdHeaderBuffers.forEach(buf => { cdSize += buf.length; });

  // End of Central Directory Header (22 bytes)
  const eocdHeader = Buffer.alloc(22);
  eocdHeader.writeUInt32LE(0x06054b50, 0); // EOCD signature
  eocdHeader.writeUInt16LE(0, 4);          // Disk number
  eocdHeader.writeUInt16LE(0, 6);          // Disk with CD
  eocdHeader.writeUInt16LE(zipEntries.length, 8);  // CD entries on disk
  eocdHeader.writeUInt16LE(zipEntries.length, 10); // Total CD entries
  eocdHeader.writeUInt32LE(cdSize, 12);    // CD size
  eocdHeader.writeUInt32LE(cdOffset, 16);  // CD offset
  eocdHeader.writeUInt16LE(0, 20);         // Comment length

  const finalZipBuffer = Buffer.concat([...localHeaderBuffers, ...cdHeaderBuffers, eocdHeader]);
  fs.writeFileSync(outPath, finalZipBuffer);
  console.log(`✓ Packaged Chrome Extension ZIP at ${outPath} (${finalZipBuffer.length} bytes)`);
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

const extDir = path.join(__dirname, '..', '..', 'extension');
const frontendOut = path.join(__dirname, '..', '..', 'frontend', 'sentinel_sebi_extension.zip');
createZipFile(extDir, frontendOut);
