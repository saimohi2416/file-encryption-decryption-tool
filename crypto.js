/**
 * SecureVault — Cryptographic Engine
 * AES-256-GCM + PBKDF2 Key Derivation + RSA Asymmetric Hybrid Encryption
 * Uses Web Crypto API (no external dependencies)
 *
 * File Formats (.enc):
 *   Version 1 (Legacy):
 *     [4B: "SVCR"] [1B: 0x01] [16B: salt] [12B: base_IV] [N bytes: ciphertext+16B GCM tag]
 *
 *   Version 2 (Integrity Hash):
 *     [4B: "SVCR"] [1B: 0x02] [16B: salt] [12B: base_IV] [32B: original SHA-256 hash] [N bytes: ciphertext+16B GCM tag]
 *
 *   Version 3 (Streaming):
 *     [4B: "SVCR"] [1B: 0x03] [16B: salt] [12B: base_IV] [32B: original SHA-256 hash] [8B: original file size] [4B: chunk size] [N bytes: encrypted chunks]
 *     - Each encrypted chunk format: [chunk_ciphertext + 16B GCM tag] (size: chunk_plaintext_size + 16)
 *     - IV for chunk i: base_IV with last 4 bytes replaced by big-endian i.
 *     - AAD for chunk i: [4B: big-endian i] [1B: is_last (0 or 1)].
 *
 *   Version 4 (Asymmetric RSA hybrid):
 *     [4B: "SVCR"] [1B: 0x04] [256B: RSA-OAEP encrypted AES key] [12B: base_IV] [32B: original SHA-256 hash] [N bytes: ciphertext+16B GCM tag]
 */

"use strict";

// ── Constants ─────────────────────────────────────────────────────────────────

const MAGIC = new Uint8Array([0x53, 0x56, 0x43, 0x52]); // "SVCR"
const VERSION_1 = 1;
const VERSION_2 = 2;
const VERSION_3 = 3; // Streaming
const VERSION_4 = 4; // Asymmetric

const SALT_LEN = 16;
const IV_LEN = 12;
const PBKDF2_ITERS = 600_000;
const KEY_LEN_BITS = 256;
const KEY_LEN_BYTES = 32;

// ── Utilities ─────────────────────────────────────────────────────────────────

function bufToHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function strToBytes(str) {
  return new TextEncoder().encode(str);
}

function randomBytes(len) {
  const buf = new Uint8Array(len);
  crypto.getRandomValues(buf);
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

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function getOutputFilename(originalName, mode) {
  if (mode === 'encrypt') {
    return originalName + '.enc';
  } else {
    return originalName.endsWith('.enc')
      ? originalName.slice(0, -4)
      : 'decrypted_' + originalName;
  }
}

// Write integer helpers
function writeUint64(num) {
  const buf = new Uint8Array(8);
  const view = new DataView(buf.buffer);
  view.setBigUint64(0, BigInt(num), false); // Big-endian
  return buf;
}

function readUint64(bytes, offset) {
  const view = new DataView(bytes.buffer, bytes.byteOffset + offset, 8);
  return Number(view.getBigUint64(0, false));
}

function writeUint32(num) {
  const buf = new Uint8Array(4);
  const view = new DataView(buf.buffer);
  view.setUint32(0, num, false); // Big-endian
  return buf;
}

function readUint32(bytes, offset) {
  const view = new DataView(bytes.buffer, bytes.byteOffset + offset, 4);
  return view.getUint32(0, false);
}

// ── File Hashing ──────────────────────────────────────────────────────────────

async function computeSHA256(buffer) {
  const hashBuf = await crypto.subtle.digest('SHA-256', buffer);
  return new Uint8Array(hashBuf);
}

// ── Key Derivation & 2FA ───────────────────────────────────────────────────────

/**
 * Derive an AES-256-GCM CryptoKey from a password + optional keyfile using PBKDF2
 */
async function deriveKey(password, salt, keyFileHash = null) {
  let pwBytes = strToBytes(password);
  if (keyFileHash) {
    // 2-Factor: Concatenate password bytes with the key file hash
    pwBytes = concatBytes(pwBytes, keyFileHash);
  }

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    pwBytes,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  const key = await crypto.subtle.deriveKey(
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

// ── Asymmetric PEM Utilities ──────────────────────────────────────────────────

function pemToBinary(pem, header, footer) {
  const clean = pem.replace(header, '').replace(footer, '').replace(/\s/g, '');
  const raw = atob(clean);
  const buf = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) {
    buf[i] = raw.charCodeAt(i);
  }
  return buf.buffer;
}

async function importPublicKeyPem(pem) {
  const cleanPem = pem.replace(/-----\s*BEGIN PUBLIC KEY\s*-----/, '')
                     .replace(/-----\s*END PUBLIC KEY\s*-----/, '')
                     .replace(/\s/g, '');
  const der = pemToBinary(cleanPem, '', '');
  return await crypto.subtle.importKey(
    'spki',
    der,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt']
  );
}

async function importPrivateKeyPem(pem) {
  const cleanPem = pem.replace(/-----\s*BEGIN PRIVATE KEY\s*-----/, '')
                     .replace(/-----\s*END PRIVATE KEY\s*-----/, '')
                     .replace(/\s/g, '');
  const der = pemToBinary(cleanPem, '', '');
  return await crypto.subtle.importKey(
    'pkcs8',
    der,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['decrypt']
  );
}

function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function exportPublicKeyPem(keyBuffer) {
  const b64 = arrayBufferToBase64(keyBuffer);
  const formatted = b64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN PUBLIC KEY-----\n${formatted}\n-----END PUBLIC KEY-----`;
}

function exportPrivateKeyPem(keyBuffer) {
  const b64 = arrayBufferToBase64(keyBuffer);
  const formatted = b64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN PRIVATE KEY-----\n${formatted}\n-----END PRIVATE KEY-----`;
}

// Generate RSA Keypair
async function generateRSAKeypair() {
  const keypair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-256'
    },
    true,
    ['encrypt', 'decrypt']
  );

  const pubExport = await crypto.subtle.exportKey('spki', keypair.publicKey);
  const privExport = await crypto.subtle.exportKey('pkcs8', keypair.privateKey);

  return {
    publicKeyPem: exportPublicKeyPem(pubExport),
    privateKeyPem: exportPrivateKeyPem(privExport)
  };
}

// ── Metadata Parsing (No Decrypt) ─────────────────────────────────────────────

function parseEncryptedHeader(fileBuffer) {
  const bytes = new Uint8Array(fileBuffer);
  if (bytes.length < 5) return null;

  // Verify magic
  const magic = bytes.slice(0, 4);
  for (let i = 0; i < 4; i++) {
    if (magic[i] !== MAGIC[i]) return null;
  }

  const version = bytes[4];
  const meta = {
    version,
    salt: null,
    iv: null,
    integrityHash: null,
    fileSize: null,
    chunkSize: null,
    asymmetric: false
  };

  if (version === VERSION_1) {
    if (bytes.length < 33) return null;
    meta.salt = bytes.slice(5, 21);
    meta.iv = bytes.slice(21, 33);
  } else if (version === VERSION_2) {
    if (bytes.length < 65) return null;
    meta.salt = bytes.slice(5, 21);
    meta.iv = bytes.slice(21, 33);
    meta.integrityHash = bytes.slice(33, 65);
  } else if (version === VERSION_3) {
    if (bytes.length < 77) return null;
    meta.salt = bytes.slice(5, 21);
    meta.iv = bytes.slice(21, 33);
    meta.integrityHash = bytes.slice(33, 65);
    meta.fileSize = readUint64(bytes, 65);
    meta.chunkSize = readUint32(bytes, 73);
  } else if (version === VERSION_4) {
    if (bytes.length < 305) return null;
    meta.asymmetric = true;
    meta.encryptedKey = bytes.slice(5, 261);
    meta.iv = bytes.slice(261, 273);
    meta.integrityHash = bytes.slice(273, 305);
  }

  return meta;
}

// ── Standard Encryption (Symmetric/Asymmetric) ─────────────────────────────────

/**
 * Encrypt file data
 */
async function encryptFile(fileData, options, onStep) {
  const { password, keyFileHash, recipientPublicKeyPem } = options;
  const isAsymmetric = !!recipientPublicKeyPem;

  // 1. Calculate integrity hash
  onStep('integrity', 'Calculating SHA-256 file integrity hash...');
  const originalHash = await computeSHA256(fileData);
  onStep('integrity', `Integrity hash: 0x${bufToHex(originalHash.buffer.slice(0, 8))}...`);
  await delay(100);

  let output;
  let salt = null;
  let iv = randomBytes(IV_LEN);

  if (isAsymmetric) {
    // Asymmetric Mode (Version 4)
    onStep('keyDerive', 'Generating random 256-bit symmetric key...');
    const aesKeyBytes = randomBytes(KEY_LEN_BYTES);
    const aesKey = await crypto.subtle.importKey(
      'raw',
      aesKeyBytes,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );

    onStep('keyDerive', 'Importing recipient public key and wrapping symmetric key...');
    const pubKey = await importPublicKeyPem(recipientPublicKeyPem);
    const encAesKey = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      pubKey,
      aesKeyBytes
    );
    onStep('keyDerive', 'Symmetric key wrapped securely inside RSA block (256 bytes).');

    onStep('encrypt', 'Encrypting file payload with ephemeral key...');
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv, tagLength: 128 },
      aesKey,
      fileData
    );

    onStep('package', 'Packaging: MAGIC + VERSION_4 + RSA_ENC_KEY + IV + HASH + CIPHERTEXT...');
    const versionByte = new Uint8Array([VERSION_4]);
    output = concatBytes(MAGIC, versionByte, encAesKey, iv, originalHash, new Uint8Array(ciphertext));
  } else {
    // Symmetric Mode (Version 2)
    onStep('saltGen', 'Generating 16-byte cryptographic salt...');
    salt = randomBytes(SALT_LEN);
    onStep('saltGen', `Salt: 0x${bufToHex(salt.buffer.slice(0, 8))}...`);

    onStep('keyDerive', 'Deriving key using PBKDF2 + SHA-256...');
    const key = await deriveKey(password, salt, keyFileHash);
    onStep('keyDerive', 'PBKDF2 complete. Ready for encryption.');

    onStep('encrypt', 'Encrypting file data with AES-256-GCM...');
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv, tagLength: 128 },
      key,
      fileData
    );

    onStep('package', 'Packaging: MAGIC + VERSION_2 + SALT + IV + HASH + CIPHERTEXT...');
    const versionByte = new Uint8Array([VERSION_2]);
    output = concatBytes(MAGIC, versionByte, salt, iv, originalHash, new Uint8Array(ciphertext));
  }

  onStep('package', `Total output: ${formatBytes(output.byteLength)}`);
  return {
    encrypted: output,
    salt: salt,
    iv: iv,
    sha256: bufToHex(originalHash)
  };
}

// ── Standard Decryption (Symmetric/Asymmetric) ─────────────────────────────────

async function decryptFile(fileData, options, onStep) {
  const { password, keyFileHash, recipientPrivateKeyPem } = options;
  const fileBytes = new Uint8Array(fileData);

  onStep('validate', 'Validating file header...');
  const header = parseEncryptedHeader(fileData);
  if (!header) {
    throw new Error('Invalid file format — magic number mismatch. Is this a SecureVault file?');
  }
  onStep('validate', `Header valid — SecureVault v${header.version} file detected`);

  let aesKey;
  let ciphertextOffset;

  if (header.version === VERSION_1) {
    const salt = header.salt;
    const iv = header.iv;
    ciphertextOffset = 33;

    onStep('keyDerive', 'Deriving decryption key using PBKDF2...');
    const key = await deriveKey(password, salt, keyFileHash);
    aesKey = key;
  } else if (header.version === VERSION_2) {
    const salt = header.salt;
    const iv = header.iv;
    ciphertextOffset = 65;

    onStep('keyDerive', 'Deriving decryption key using PBKDF2...');
    const key = await deriveKey(password, salt, keyFileHash);
    aesKey = key;
  } else if (header.version === VERSION_4) {
    if (!recipientPrivateKeyPem) {
      throw new Error('This file is asymmetrically encrypted. You must upload/provide your Private Key to decrypt it.');
    }
    ciphertextOffset = 305;

    onStep('keyDerive', 'Importing private key and unwrapping AES key...');
    const privKey = await importPrivateKeyPem(recipientPrivateKeyPem);
    const unwrappedAesKeyBytes = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      privKey,
      header.encryptedKey
    );

    aesKey = await crypto.subtle.importKey(
      'raw',
      unwrappedAesKeyBytes,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
  } else {
    throw new Error(`Unsupported standard version: v${header.version}. Use streaming decryption for streaming formats.`);
  }

  const ciphertext = fileBytes.slice(ciphertextOffset);

  onStep('decrypt', 'Decrypting with AES-256-GCM (verifying authenticity tag)...');
  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: header.iv, tagLength: 128 },
      aesKey,
      ciphertext
    );
  } catch (e) {
    throw new Error('Decryption failed — wrong password/private key or file corruption. GCM authentication tag mismatch.');
  }

  // Integrity validation (for Version 2 & 4)
  if (header.integrityHash) {
    onStep('integrity', 'Checking SHA-256 integrity hash...');
    const computedHash = await computeSHA256(plaintext);
    const computedHex = bufToHex(computedHash);
    const expectedHex = bufToHex(header.integrityHash);
    if (computedHex !== expectedHex) {
      throw new Error('INTEGRITY FAILURE: The decrypted file hash does not match the original hash! The file may have been tampered with.');
    }
    onStep('integrity', 'SHA-256 Integrity Verified! No tampering detected.');
  }

  return {
    decrypted: plaintext,
    sha256: header.integrityHash ? bufToHex(header.integrityHash) : null
  };
}

// ── Chunked / Streaming Encryption (Version 3) ───────────────────────────────

async function encryptFileStream(file, options, onStep, onProgress) {
  const { password, keyFileHash, chunkSize = 1024 * 1024 } = options;

  onStep('integrity', 'Calculating SHA-256 file integrity hash...');
  const fullBuffer = await file.arrayBuffer();
  const originalHash = await computeSHA256(fullBuffer);
  const originalHashHex = bufToHex(originalHash);
  onStep('integrity', `Integrity hash: 0x${originalHashHex.slice(0, 8)}...`);

  onStep('saltGen', 'Generating cryptographic salt...');
  const salt = randomBytes(SALT_LEN);
  const iv = randomBytes(IV_LEN);

  onStep('keyDerive', 'Deriving PBKDF2 streaming key...');
  const key = await deriveKey(password, salt, keyFileHash);

  onStep('encrypt', `Initializing streaming: ${formatBytes(file.size)} in chunks of ${formatBytes(chunkSize)}...`);

  // Build header
  const versionByte = new Uint8Array([VERSION_3]);
  const sizeBytes = writeUint64(file.size);
  const chunkSizeBytes = writeUint32(chunkSize);

  const header = concatBytes(MAGIC, versionByte, salt, iv, originalHash, sizeBytes, chunkSizeBytes);
  const outputParts = [header];

  const numChunks = Math.ceil(file.size / chunkSize);

  for (let i = 0; i < numChunks; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, file.size);
    const slice = file.slice(start, end);
    const chunkBuffer = await slice.arrayBuffer();

    const isLast = (i === numChunks - 1);

    // Derive IV for this chunk
    const chunkIv = new Uint8Array(iv);
    const ivView = new DataView(chunkIv.buffer);
    ivView.setUint32(8, i, false);

    // AAD: chunk index + is_last flag
    const aad = new Uint8Array(5);
    const aadView = new DataView(aad.buffer);
    aadView.setUint32(0, i, false);
    aadView.setUint8(4, isLast ? 1 : 0);

    const encChunk = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: chunkIv, additionalData: aad, tagLength: 128 },
      key,
      chunkBuffer
    );

    outputParts.push(new Uint8Array(encChunk));
    
    const pct = Math.round(((i + 1) / numChunks) * 100);
    onProgress(pct, `Encrypted chunk ${i+1}/${numChunks} (${pct}%)`);
  }

  onStep('package', 'Packaging and finalizing encrypted stream blob...');
  const finalBlob = new Blob(outputParts, { type: 'application/octet-stream' });
  onStep('package', `Finished! Encrypted stream size: ${formatBytes(finalBlob.size)}`);

  return {
    encryptedBlob: finalBlob,
    sha256: originalHashHex
  };
}

// ── Chunked / Streaming Decryption (Version 3) ───────────────────────────────

async function decryptFileStream(file, options, onStep, onProgress) {
  const { password, keyFileHash } = options;

  onStep('validate', 'Reading encrypted file stream headers...');
  
  const headerSlice = file.slice(0, 77);
  const headerBuffer = await headerSlice.arrayBuffer();
  
  const header = parseEncryptedHeader(headerBuffer);
  if (!header || header.version !== VERSION_3) {
    throw new Error('Invalid file format: Not a valid SecureVault Version 3 (Streaming) file.');
  }

  onStep('validate', `Header valid — Version 3 Stream, Original size: ${formatBytes(header.fileSize)}`);

  onStep('keyDerive', 'Deriving PBKDF2 stream decryption key...');
  const key = await deriveKey(password, header.salt, keyFileHash);

  onStep('decrypt', 'Decrypting stream data in chunks...');
  
  const chunkSize = header.chunkSize;
  const encChunkSize = chunkSize + 16; 
  const numChunks = Math.ceil(header.fileSize / chunkSize);

  const outputParts = [];
  let fileOffset = 77; 

  for (let i = 0; i < numChunks; i++) {
    const isLast = (i === numChunks - 1);
    
    const currentChunkEncSize = isLast 
      ? file.size - fileOffset 
      : encChunkSize;

    if (currentChunkEncSize <= 0) {
      throw new Error(`Streaming error: Expected chunk ${i + 1} but reached end of file.`);
    }

    const chunkSlice = file.slice(fileOffset, fileOffset + currentChunkEncSize);
    const encChunkBuffer = await chunkSlice.arrayBuffer();
    fileOffset += currentChunkEncSize;

    // Chunk IV
    const chunkIv = new Uint8Array(header.iv);
    const ivView = new DataView(chunkIv.buffer);
    ivView.setUint32(8, i, false);

    // AAD
    const aad = new Uint8Array(5);
    const aadView = new DataView(aad.buffer);
    aadView.setUint32(0, i, false);
    aadView.setUint8(4, isLast ? 1 : 0);

    let decChunk;
    try {
      decChunk = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: chunkIv, additionalData: aad, tagLength: 128 },
        key,
        encChunkBuffer
      );
    } catch (err) {
      throw new Error(`Decryption failed at chunk ${i + 1}/${numChunks}. Wrong password/keyfile or chunk corrupted.`);
    }

    outputParts.push(new Uint8Array(decChunk));

    const pct = Math.round(((i + 1) / numChunks) * 100);
    onProgress(pct, `Decrypted chunk ${i+1}/${numChunks} (${pct}%)`);
  }

  onStep('integrity', 'Checking SHA-256 integrity hash...');
  const finalBlob = new Blob(outputParts, { type: 'application/octet-stream' });
  const finalBuffer = await finalBlob.arrayBuffer();
  const computedHash = await computeSHA256(finalBuffer);
  const computedHex = bufToHex(computedHash);
  const expectedHex = bufToHex(header.integrityHash);

  if (computedHex !== expectedHex) {
    throw new Error('INTEGRITY FAILURE: Streaming decrypted file hash does not match original! Tampering suspected.');
  }

  onStep('integrity', 'SHA-256 Integrity Verified! Streaming decryption successful.');

  return {
    decryptedBlob: finalBlob,
    sha256: expectedHex
  };
}
