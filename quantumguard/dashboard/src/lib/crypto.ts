import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { x25519 } from '@noble/curves/ed25519.js';

export interface HybridKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export const KYBER_PK_SIZE = 1184;
export const KYBER_SK_SIZE = 2400;
export const KYBER_CT_SIZE = 1088;
export const X25519_SIZE = 32;

/**
 * Generates a hybrid Post-Quantum key pair (Kyber-768 + X25519).
 */
export async function generateHybridKeyPair(): Promise<HybridKeyPair> {
  // Kyber
  const kyberSeed = crypto.getRandomValues(new Uint8Array(64));
  const kyberKeys = ml_kem768.keygen(kyberSeed);

  // X25519
  const xPriv = x25519.utils.randomSecretKey();
  const xPub = x25519.getPublicKey(xPriv);

  // Concatenate (Matching Go circl hybrid implementation)
  const publicKey = new Uint8Array(KYBER_PK_SIZE + X25519_SIZE);
  publicKey.set(kyberKeys.publicKey);
  publicKey.set(xPub, KYBER_PK_SIZE);

  const privateKey = new Uint8Array(KYBER_SK_SIZE + X25519_SIZE);
  privateKey.set(kyberKeys.secretKey);
  privateKey.set(xPriv, KYBER_SK_SIZE);

  return { publicKey, privateKey };
}

/**
 * Encapsulates a shared secret for a recipient.
 */
export async function encapsulatePackage(recipientPubKey: Uint8Array) {
  const kyberPK = recipientPubKey.slice(0, KYBER_PK_SIZE);
  const xPub = recipientPubKey.slice(KYBER_PK_SIZE);

  // Kyber Encapsulation
  const kyberSeed = crypto.getRandomValues(new Uint8Array(32));
  const { ciphertext: kyberCT, sharedSecret: kyberSS } = ml_kem768.encapsulate(kyberPK, kyberSeed);

  // X25519 Encapsulation (Simple ECDH)
  const xEphemeralPriv = x25519.utils.randomSecretKey();
  const xEphemeralPub = x25519.getPublicKey(xEphemeralPriv);
  const xSS = x25519.getSharedSecret(xEphemeralPriv, xPub);

  // Concatenate
  const ct = new Uint8Array(KYBER_CT_SIZE + X25519_SIZE);
  ct.set(kyberCT);
  ct.set(xEphemeralPub, KYBER_CT_SIZE);

  const ss = new Uint8Array(32 + 32); // 64 bytes total shared secret
  ss.set(kyberSS);
  ss.set(xSS, 32);

  return { ct, ss };
}

/**
 * Decapsulates a shared secret using a hybrid private key.
 */
export async function decapsulatePackage(privateKey: Uint8Array, ct: Uint8Array): Promise<Uint8Array> {
  const kyberSK = privateKey.slice(0, KYBER_SK_SIZE);
  const xPriv = privateKey.slice(KYBER_SK_SIZE);

  const kyberCT = ct.slice(0, KYBER_CT_SIZE);
  const xEphemeralPub = ct.slice(KYBER_CT_SIZE);

  // Kyber Decapsulation
  const kyberSS = ml_kem768.decapsulate(kyberCT, kyberSK);

  // X25519 Decapsulation
  const xSS = x25519.getSharedSecret(xPriv, xEphemeralPub);

  const ss = new Uint8Array(32 + 32);
  ss.set(kyberSS);
  ss.set(xSS, 32);

  return ss;
}

/**
 * AES-256-GCM Encryption.
 */
export async function encrypt(plaintext: Uint8Array, sharedSecret: Uint8Array): Promise<Uint8Array> {
  // Use first 32 bytes of the hybrid shared secret for AES-256 (matches Go engine.go)
  const key = await crypto.subtle.importKey(
    'raw',
    sharedSecret.slice(0, 32),
    'AES-GCM',
    false,
    ['encrypt']
  );

  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    key,
    plaintext
  );

  const result = new Uint8Array(nonce.length + encrypted.byteLength);
  result.set(nonce);
  result.set(new Uint8Array(encrypted), nonce.length);
  return result;
}

/**
 * AES-256-GCM Decryption.
 */
export async function decrypt(ciphertext: Uint8Array, sharedSecret: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    sharedSecret.slice(0, 32),
    'AES-GCM',
    false,
    ['decrypt']
  );

  const nonce = ciphertext.slice(0, 12);
  const data = ciphertext.slice(12);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce },
    key,
    data
  );

  return new Uint8Array(decrypted);
}

// Utility to convert hex to Uint8Array
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// Utility to convert Uint8Array to hex
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
