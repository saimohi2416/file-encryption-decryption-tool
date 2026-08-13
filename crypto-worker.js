/**
 * SecureVault — Dedicated Web Worker for Cryptographic Operations
 * Offloads PBKDF2 (600,000 iterations), AES-256-GCM encryption/decryption,
 * and chunked memory-safe streaming from the main UI thread.
 */

"use strict";

const MAGIC = new Uint8Array([0x53, 0x56, 0x43, 0x52]); // "SVCR"
const VERSION_1 = 1;
const VERSION_2 = 2;
const VERSION_3 = 3; // Streaming
const VERSION_4 = 4; // Asymmetric

const SALT_LEN = 16;
const IV_LEN = 12;
const PBKDF2_ITERS = 600_000;
const KEY_LEN_BITS = 256;

// ── Incremental SHA-256 Implementation (Memory Safe for Files > 500 MB) ──────

class IncrementalSHA256 {
  constructor() {
    this.K = new Uint32Array([
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]);
    this.reset();
  }

  reset() {
    this.h = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);
    this.buffer = new Uint8Array(64);
    this.bufLen = 0;
    this.totalLenBytes = 0;
    this.W = new Uint32Array(64);
  }

  update(chunk) {
    const bytes = new Uint8Array(chunk);
    this.totalLenBytes += bytes.length;
    let offset = 0;

    while (offset < bytes.length) {
      const needed = 64 - this.bufLen;
      const available = bytes.length - offset;
      const copyLen = Math.min(needed, available);

      this.buffer.set(bytes.subarray(offset, offset + copyLen), this.bufLen);
      this.bufLen += copyLen;
      offset += copyLen;

      if (this.bufLen === 64) {
        this._processBlock(this.buffer);
        this.bufLen = 0;
      }
    }
  }

  _processBlock(block) {
    const W = this.W;
    const view = new DataView(block.buffer, block.byteOffset, 64);
    for (let i = 0; i < 16; i++) {
      W[i] = view.getUint32(i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = (W[i - 15] >>> 7 | W[i - 15] << 25) ^ (W[i - 15] >>> 18 | W[i - 15] << 14) ^ (W[i - 15] >>> 3);
      const s1 = (W[i - 2] >>> 17 | W[i - 2] << 15) ^ (W[i - 2] >>> 19 | W[i - 2] << 13) ^ (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }

    let [a, b, c, d, e, f, g, h] = this.h;

    for (let i = 0; i < 64; i++) {
      const S1 = (e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + this.K[i] + W[i]) >>> 0;
      const S0 = (a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    this.h[0] = (this.h[0] + a) >>> 0;
    this.h[1] = (this.h[1] + b) >>> 0;
    this.h[2] = (this.h[2] + c) >>> 0;
    this.h[3] = (this.h[3] + d) >>> 0;
    this.h[4] = (this.h[4] + e) >>> 0;
    this.h[5] = (this.h[5] + f) >>> 0;
    this.h[6] = (this.h[6] + g) >>> 0;
    this.h[7] = (this.h[7] + h) >>> 0;
  }

  digest() {
    const totalBits = BigInt(this.totalLenBytes) * 8n;
    const pad = new Uint8Array(128);
    pad[0] = 0x80;
    let padLen = 1;
    while (((this.totalLenBytes + padLen + 8) % 64) !== 0) {
      padLen++;
    }
    const view = new DataView(pad.buffer, padLen, 8);
    view.setBigUint64(0, totalBits, false);
    padLen += 8;

    this.update(pad.subarray(0, padLen));

    const result = new Uint8Array(32);
    const resView = new DataView(result.buffer);
    for (let i = 0; i < 8; i++) {
      resView.setUint32(i * 4, this.h[i], false);
    }
    return result;
  }
}

// Helper utilities in worker
function strToBytes(str) {
  return new TextEncoder().encode(str);
}

function bufToHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function randomBytes(len) {
  const buf = new Uint8Array(len);
  self.crypto.getRandomValues(buf);
  return buf;
}

function concatBytes(...arrays) {
  const normalized = arrays.map(a => a instanceof ArrayBuffer ? new Uint8Array(a) : a);
  const totalLen = normalized.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of normalized) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

function writeUint64(num) {
  const buf = new Uint8Array(8);
  const view = new DataView(buf.buffer);
  view.setBigUint64(0, BigInt(num), false);
  return buf;
}

function writeUint32(num) {
  const buf = new Uint8Array(4);
  const view = new DataView(buf.buffer);
  view.setUint32(0, num, false);
  return buf;
}

async function deriveKey(password, salt, keyFileHash = null) {
  let pwBytes = strToBytes(password);
  if (keyFileHash) {
    pwBytes = concatBytes(pwBytes, keyFileHash);
  }

  const keyMaterial = await self.crypto.subtle.importKey(
    'raw',
    pwBytes,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  const key = await self.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: PBKDF2_ITERS,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: KEY_LEN_BITS },
    false,
    ['encrypt', 'decrypt']
  );

  return key;
}

// ── Streaming Encryption Handler (Version 3) ──────────────────────────────────

async function handleEncryptStream(id, file, options) {
  const { password, keyFileHash, chunkSize = 2 * 1024 * 1024 } = options;

  self.postMessage({ id, type: 'step', phase: 'integrity', message: 'Calculating SHA-256 file integrity hash (incremental chunked mode)...' });

  const hasher = new IncrementalSHA256();
  const totalChunks = Math.ceil(file.size / chunkSize) || 1;

  // Pass 1: Compute hash incrementally in small slices
  for (let i = 0; i < totalChunks; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, file.size);
    const slice = file.slice(start, end);
    const chunkBuf = await slice.arrayBuffer();
    hasher.update(chunkBuf);

    const pct = Math.round(((i + 1) / totalChunks) * 50);
    self.postMessage({ id, type: 'progress', percent: pct, detail: `Hashing chunk ${i + 1}/${totalChunks} (${pct}%)` });
  }

  const originalHash = hasher.digest();
  const originalHashHex = bufToHex(originalHash);
  self.postMessage({ id, type: 'step', phase: 'saltGen', message: `SHA-256 hash verified: 0x${originalHashHex.slice(0, 8)}... Generating salt & IV` });

  const salt = randomBytes(SALT_LEN);
  const iv = randomBytes(IV_LEN);

  self.postMessage({ id, type: 'step', phase: 'keyDerive', message: `Deriving key with PBKDF2 (600,000 iterations, SHA-256)...` });
  const key = await deriveKey(password, salt, keyFileHash);

  self.postMessage({ id, type: 'step', phase: 'encrypt', message: `Encrypting stream (${(file.size / (1024 * 1024)).toFixed(2)} MB) in ${chunkSize / 1024} KB chunks...` });

  const versionByte = new Uint8Array([VERSION_3]);
  const sizeBytes = writeUint64(file.size);
  const chunkSizeBytes = writeUint32(chunkSize);
  const header = concatBytes(MAGIC, versionByte, salt, iv, originalHash, sizeBytes, chunkSizeBytes);

  const outputParts = [header];

  // Pass 2: Encrypt chunk by chunk
  for (let i = 0; i < totalChunks; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, file.size);
    const slice = file.slice(start, end);
    const chunkBuffer = await slice.arrayBuffer();

    const isLast = (i === totalChunks - 1);

    const chunkIv = new Uint8Array(iv);
    const ivView = new DataView(chunkIv.buffer);
    ivView.setUint32(8, i, false);

    const aad = new Uint8Array(5);
    const aadView = new DataView(aad.buffer);
    aadView.setUint32(0, i, false);
    aadView.setUint8(4, isLast ? 1 : 0);

    const encChunk = await self.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: chunkIv, additionalData: aad, tagLength: 128 },
      key,
      chunkBuffer
    );

    outputParts.push(new Uint8Array(encChunk));

    const pct = 50 + Math.round(((i + 1) / totalChunks) * 50);
    self.postMessage({ id, type: 'progress', percent: pct, detail: `Encrypted chunk ${i + 1}/${totalChunks} (${pct}%)` });
  }

  self.postMessage({ id, type: 'step', phase: 'package', message: 'Finalizing encrypted stream blob...' });
  const finalBlob = new Blob(outputParts, { type: 'application/octet-stream' });

  self.postMessage({
    id,
    type: 'complete',
    result: {
      encryptedBlob: finalBlob,
      sha256: originalHashHex,
      originalSize: file.size,
      encryptedSize: finalBlob.size
    }
  });
}

// ── Streaming Decryption Handler (Version 3) ──────────────────────────────────

async function handleDecryptStream(id, file, options) {
  const { password, keyFileHash } = options;

  self.postMessage({ id, type: 'step', phase: 'validate', message: 'Reading encrypted stream headers...' });

  const headerSlice = file.slice(0, 77);
  const headerBuf = await headerSlice.arrayBuffer();
  const headerBytes = new Uint8Array(headerBuf);

  if (headerBytes.length < 77 || headerBytes[0] !== 0x53 || headerBytes[1] !== 0x56 || headerBytes[2] !== 0x43 || headerBytes[3] !== 0x52 || headerBytes[4] !== VERSION_3) {
    throw new Error('Invalid file format: Expected SecureVault Version 3 (Streaming) encrypted file.');
  }

  const salt = headerBytes.slice(5, 21);
  const iv = headerBytes.slice(21, 33);
  const expectedHash = headerBytes.slice(33, 65);
  const sizeView = new DataView(headerBytes.buffer, 65, 8);
  const fileSize = Number(sizeView.getBigUint64(0, false));
  const chunkView = new DataView(headerBytes.buffer, 73, 4);
  const chunkSize = chunkView.getUint32(0, false);

  self.postMessage({ id, type: 'step', phase: 'keyDerive', message: 'Deriving stream decryption key (PBKDF2 600,000 iterations)...' });
  const key = await deriveKey(password, salt, keyFileHash);

  self.postMessage({ id, type: 'step', phase: 'decrypt', message: `Decrypting ${(fileSize / (1024 * 1024)).toFixed(2)} MB in chunks...` });

  const encChunkSize = chunkSize + 16;
  const numChunks = Math.ceil(fileSize / chunkSize) || 1;
  const outputParts = [];
  let fileOffset = 77;

  const hasher = new IncrementalSHA256();

  for (let i = 0; i < numChunks; i++) {
    const isLast = (i === numChunks - 1);
    const currentChunkEncSize = isLast ? (file.size - fileOffset) : encChunkSize;

    if (currentChunkEncSize <= 0) {
      throw new Error(`Streaming error: Reached EOF prematurely at chunk ${i + 1}/${numChunks}`);
    }

    const chunkSlice = file.slice(fileOffset, fileOffset + currentChunkEncSize);
    const encChunkBuffer = await chunkSlice.arrayBuffer();
    fileOffset += currentChunkEncSize;

    const chunkIv = new Uint8Array(iv);
    const ivView = new DataView(chunkIv.buffer);
    ivView.setUint32(8, i, false);

    const aad = new Uint8Array(5);
    const aadView = new DataView(aad.buffer);
    aadView.setUint32(0, i, false);
    aadView.setUint8(4, isLast ? 1 : 0);

    let decChunk;
    try {
      decChunk = await self.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: chunkIv, additionalData: aad, tagLength: 128 },
        key,
        encChunkBuffer
      );
    } catch (err) {
      throw new Error(`Decryption failed at chunk ${i + 1}/${numChunks}. Invalid password, corrupted tag, or tampered file.`);
    }

    const decUint8 = new Uint8Array(decChunk);
    hasher.update(decUint8);
    outputParts.push(decUint8);

    const pct = Math.round(((i + 1) / numChunks) * 90);
    self.postMessage({ id, type: 'progress', percent: pct, detail: `Decrypted chunk ${i + 1}/${numChunks} (${pct}%)` });
  }

  self.postMessage({ id, type: 'step', phase: 'integrity', message: 'Verifying SHA-256 integrity hash...' });
  const computedHash = hasher.digest();
  const computedHex = bufToHex(computedHash);
  const expectedHex = bufToHex(expectedHash);

  if (computedHex !== expectedHex) {
    throw new Error('INTEGRITY FAILURE: Decrypted file SHA-256 hash does not match original header hash!');
  }

  self.postMessage({ id, type: 'step', phase: 'package', message: 'Packaging decrypted file...' });
  const decryptedBlob = new Blob(outputParts, { type: 'application/octet-stream' });

  self.postMessage({
    id,
    type: 'complete',
    result: {
      decryptedBlob: decryptedBlob,
      sha256: computedHex,
      originalSize: fileSize
    }
  });
}

// ── Standard In-Memory Worker Handlers ────────────────────────────────────────

async function handleEncrypt(id, fileData, options) {
  const { password, keyFileHash } = options;

  self.postMessage({ id, type: 'step', phase: 'integrity', message: 'Computing SHA-256 file integrity hash...' });
  const hasher = new IncrementalSHA256();
  hasher.update(fileData);
  const sha256 = hasher.digest();
  const sha256Hex = bufToHex(sha256);

  self.postMessage({ id, type: 'step', phase: 'saltGen', message: 'Generating cryptographic salt & IV...' });
  const salt = randomBytes(SALT_LEN);
  const iv = randomBytes(IV_LEN);

  self.postMessage({ id, type: 'step', phase: 'keyDerive', message: 'Deriving key with PBKDF2 (600,000 iterations, SHA-256)...' });
  const key = await deriveKey(password, salt, keyFileHash);

  self.postMessage({ id, type: 'step', phase: 'encrypt', message: 'Executing AES-256-GCM encryption...' });
  const ciphertext = await self.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv, tagLength: 128 },
    key,
    fileData
  );

  const versionByte = new Uint8Array([VERSION_2]);
  const finalEncrypted = concatBytes(MAGIC, versionByte, salt, iv, sha256, ciphertext);

  self.postMessage({
    id,
    type: 'complete',
    result: {
      encrypted: finalEncrypted.buffer,
      sha256: sha256Hex
    }
  }, [finalEncrypted.buffer]);
}

async function handleDecrypt(id, fileBuffer, options) {
  const { password, keyFileHash } = options;
  const bytes = new Uint8Array(fileBuffer);

  self.postMessage({ id, type: 'step', phase: 'validate', message: 'Parsing encrypted file header...' });

  if (bytes.length < 5 || bytes[0] !== 0x53 || bytes[1] !== 0x56 || bytes[2] !== 0x43 || bytes[3] !== 0x52) {
    throw new Error('Invalid file format: SecureVault magic header missing.');
  }

  const version = bytes[4];
  let offset = 5;
  const salt = bytes.slice(offset, offset + SALT_LEN);
  offset += SALT_LEN;
  const iv = bytes.slice(offset, offset + IV_LEN);
  offset += IV_LEN;

  let expectedHash = null;
  if (version >= VERSION_2) {
    expectedHash = bytes.slice(offset, offset + 32);
    offset += 32;
  }

  const ciphertext = bytes.slice(offset);

  self.postMessage({ id, type: 'step', phase: 'keyDerive', message: 'Deriving PBKDF2 decryption key (600,000 iterations)...' });
  const key = await deriveKey(password, salt, keyFileHash);

  self.postMessage({ id, type: 'step', phase: 'decrypt', message: 'Decrypting AES-256-GCM payload...' });
  let plaintext;
  try {
    plaintext = await self.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv, tagLength: 128 },
      key,
      ciphertext
    );
  } catch (err) {
    throw new Error('Decryption failed: Incorrect password/keyfile or corrupted payload.');
  }

  if (expectedHash) {
    self.postMessage({ id, type: 'step', phase: 'integrity', message: 'Verifying SHA-256 integrity...' });
    const hasher = new IncrementalSHA256();
    hasher.update(plaintext);
    const computedHex = bufToHex(hasher.digest());
    const expectedHex = bufToHex(expectedHash);

    if (computedHex !== expectedHex) {
      throw new Error('INTEGRITY FAILURE: Decrypted hash does not match original header hash!');
    }
  }

  self.postMessage({
    id,
    type: 'complete',
    result: {
      decrypted: plaintext,
      sha256: expectedHash ? bufToHex(expectedHash) : null
    }
  }, [plaintext]);
}

// ── Message Listener ──────────────────────────────────────────────────────────

self.onmessage = async function (e) {
  const { id, action, file, fileData, fileBuffer, options } = e.data;

  try {
    if (action === 'encryptStream') {
      await handleEncryptStream(id, file, options);
    } else if (action === 'decryptStream') {
      await handleDecryptStream(id, file, options);
    } else if (action === 'encrypt') {
      await handleEncrypt(id, fileData, options);
    } else if (action === 'decrypt') {
      await handleDecrypt(id, fileBuffer, options);
    } else {
      throw new Error(`Unknown worker action: ${action}`);
    }
  } catch (err) {
    self.postMessage({ id, type: 'error', error: err.message || 'Worker processing failed' });
  }
};
