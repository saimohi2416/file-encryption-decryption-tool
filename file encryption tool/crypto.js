/**
 * SecureVault — Cryptographic Engine
 * AES-256-GCM + PBKDF2 Key Derivation
 * Uses Web Crypto API (no external dependencies)
 *
 * File Format (.enc):
 *   [4 bytes: magic "SVCR"] [1 byte: version] [16 bytes: salt] [12 bytes: IV] [N bytes: ciphertext+GCM tag]
 */

"use strict";

// ── Constants ─────────────────────────────────────────────────────────────────

const MAGIC = new Uint8Array([0x53, 0x56, 0x43, 0x52]); // "SVCR"
const VERSION = 1;
const SALT_LEN = 16;   // bytes
const IV_LEN = 12;   // bytes (GCM recommended)
const PBKDF2_ITERS = 310_000;
const KEY_LEN_BITS = 256;
const KEY_LEN_BYTES = 32;
const HEADER_SIZE = MAGIC.length + 1 + SALT_LEN + IV_LEN; // 33 bytes

// ── Utilities ─────────────────────────────────────────────────────────────────

/**
 * Convert an ArrayBuffer to a hex string for display
 */
function bufToHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Format bytes as a human-readable string
 */
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Encode a string as UTF-8 bytes
 */
function strToBytes(str) {
  return new TextEncoder().encode(str);
}

/**
 * Generate cryptographically secure random bytes
 */
function randomBytes(len) {
  const buf = new Uint8Array(len);
  crypto.getRandomValues(buf);
  return buf;
}

/**
 * Concatenate multiple Uint8Arrays / ArrayBuffers into one
 */
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

// ── Key Derivation ─────────────────────────────────────────────────────────────

/**
 * Derive an AES-256-GCM CryptoKey from a password using PBKDF2
 * @param {string} password - User password
 * @param {Uint8Array} salt  - Random 16-byte salt
 * @returns {Promise<CryptoKey>}
 */
async function deriveKey(password, salt) {
  // 1. Import raw password material
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    strToBytes(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  // 2. Derive AES-256 key using PBKDF2 + SHA-256
  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: PBKDF2_ITERS,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: KEY_LEN_BITS },
    false,          // non-extractable
    ['encrypt', 'decrypt']
  );

  return key;
}

// ── Encryption ─────────────────────────────────────────────────────────────────

/**
 * Encrypt file data with AES-256-GCM
 *
 * Output binary format:
 *   MAGIC (4) | VERSION (1) | SALT (16) | IV (12) | CIPHERTEXT+TAG (N)
 *
 * @param {ArrayBuffer} fileData  - Raw file bytes
 * @param {string}      password  - Encryption password
 * @param {Function}    onStep    - Progress callback(stepName, detail)
 * @returns {Promise<{encrypted: Uint8Array, salt: Uint8Array, iv: Uint8Array, keyHex: string}>}
 */
async function encryptFile(fileData, password, onStep) {
  // Step A: Generate salt
  onStep('saltGen', 'Generating 16-byte cryptographic salt...');
  const salt = randomBytes(SALT_LEN);
  await delay(120);
  onStep('saltGen', `Salt: 0x${bufToHex(salt.buffer.slice(0, 8))}... (truncated)`);

  // Step B: Derive key
  onStep('keyDerive', `Deriving 256-bit key using PBKDF2 (${PBKDF2_ITERS.toLocaleString()} iterations)...`);
  const tStart = performance.now();
  const key = await deriveKey(password, salt);
  const tEnd = performance.now();
  onStep('keyDerive', `Key derived in ${(tEnd - tStart).toFixed(0)}ms — non-extractable AES-256 key ready`);

  // Step C: Generate IV
  onStep('ivGen', 'Generating 12-byte random IV for GCM mode...');
  const iv = randomBytes(IV_LEN);
  onStep('ivGen', `IV: 0x${bufToHex(iv.buffer.slice(0, 8))}... (truncated)`);

  // Step D: Encrypt
  onStep('encrypt', `Encrypting ${formatBytes(fileData.byteLength)} with AES-256-GCM...`);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv, tagLength: 128 },
    key,
    fileData
  );
  onStep('encrypt', `Encrypted! Ciphertext: ${formatBytes(ciphertext.byteLength)} (includes 16-byte auth tag)`);

  // Step E: Package
  onStep('package', 'Packaging: MAGIC + VERSION + SALT + IV + CIPHERTEXT...');
  const versionByte = new Uint8Array([VERSION]);
  const output = concatBytes(MAGIC, versionByte, salt, iv, new Uint8Array(ciphertext));
  onStep('package', `Total output: ${formatBytes(output.byteLength)}`);

  return {
    encrypted: output,
    salt: salt,
    iv: iv
  };
}

// ── Decryption ─────────────────────────────────────────────────────────────────

/**
 * Decrypt a SecureVault-encrypted file
 *
 * @param {ArrayBuffer} fileData  - Encrypted file bytes
 * @param {string}      password  - Decryption password
 * @param {Function}    onStep    - Progress callback
 * @returns {Promise<{decrypted: ArrayBuffer}>}
 */
async function decryptFile(fileData, password, onStep) {
  const fileBytes = new Uint8Array(fileData);

  // Validate magic number
  onStep('validate', 'Validating file header and magic bytes...');
  if (fileBytes.length < HEADER_SIZE) {
    throw new Error('File too small — not a valid .enc file');
  }
  const magic = fileBytes.slice(0, 4);
  for (let i = 0; i < MAGIC.length; i++) {
    if (magic[i] !== MAGIC[i]) {
      throw new Error('Invalid file format — magic number mismatch. Is this a SecureVault file?');
    }
  }
  const version = fileBytes[4];
  onStep('validate', `File valid — SecureVault v${version} format`);

  // Extract salt and IV
  onStep('extract', 'Extracting salt and IV from file header...');
  const salt = fileBytes.slice(5, 5 + SALT_LEN);
  const iv = fileBytes.slice(5 + SALT_LEN, 5 + SALT_LEN + IV_LEN);
  const ciphertext = fileBytes.slice(HEADER_SIZE);
  onStep('extract', `Salt: 0x${bufToHex(salt.buffer.slice(salt.byteOffset, salt.byteOffset + 8))}...`);
  onStep('extract', `IV:   0x${bufToHex(iv.buffer.slice(iv.byteOffset, iv.byteOffset + 8))}...`);
  onStep('extract', `Ciphertext: ${formatBytes(ciphertext.byteLength)} (includes GCM auth tag)`);

  // Derive key from password
  onStep('keyDerive', `Deriving decryption key using PBKDF2 (${PBKDF2_ITERS.toLocaleString()} iterations)...`);
  const tStart = performance.now();
  const key = await deriveKey(password, salt);
  const tEnd = performance.now();
  onStep('keyDerive', `Key derived in ${(tEnd - tStart).toFixed(0)}ms`);

  // Decrypt
  onStep('decrypt', `Decrypting with AES-256-GCM (verifying auth tag)...`);
  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv, tagLength: 128 },
      key,
      ciphertext
    );
  } catch (e) {
    throw new Error('Decryption failed — wrong password or corrupted file. GCM authentication tag mismatch.');
  }
  onStep('decrypt', `Decrypted! Plaintext: ${formatBytes(plaintext.byteLength)}`);

  return { decrypted: plaintext };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Determine output filename for encryption/decryption
 */
function getOutputFilename(originalName, mode) {
  if (mode === 'encrypt') {
    return originalName + '.enc';
  } else {
    // Strip .enc extension if present
    return originalName.endsWith('.enc')
      ? originalName.slice(0, -4)
      : 'decrypted_' + originalName;
  }
}
