// Typed wrapper over the core BBS functions of @digitalbazaar/bbs-signatures.
//
// The bbs-2023 cryptosuite calls this library itself; the functions here are
// for the known-answer tests, for the Prover's base-proof check, and for a
// possible core-BBS baseline. Sign is deterministic in the draft: the same key,
// header and messages always give the same signature.

import * as bbs from '@digitalbazaar/bbs-signatures';

/** bbs-2023 fixes the ciphersuite (W3C vc-di-bbs, "requiredAlgorithm"). */
export const CIPHERSUITE = 'BLS12-381-SHA-256';
export type Ciphersuite = typeof CIPHERSUITE;

export const SECRET_KEY_LEN = 32;
export const PUBLIC_KEY_LEN = 96;
export const SIGNATURE_LEN = 80;
/** Minimum `key_material` length required by the draft's KeyGen. */
export const MIN_KEY_MATERIAL_LEN = 32;

export interface KeyPairBytes {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

/**
 * The draft's KeyGen with an empty `key_info`. With no `keyMaterial`, random
 * key material is used. The library does not expose `key_info`.
 */
export async function keygen(keyMaterial?: Uint8Array): Promise<KeyPairBytes> {
  if (keyMaterial !== undefined && keyMaterial.length < MIN_KEY_MATERIAL_LEN) {
    throw new Error(
      `key material must be at least ${MIN_KEY_MATERIAL_LEN} octets, got ${keyMaterial.length}`
    );
  }
  return bbs.generateKeyPair({
    ...(keyMaterial === undefined ? {} : {seed: keyMaterial}),
    ciphersuite: CIPHERSUITE
  });
}

/** The draft's SkToPk. */
export async function publicKeyOf(secretKey: Uint8Array): Promise<Uint8Array> {
  return bbs.secretKeyToPublicKey({secretKey, ciphersuite: CIPHERSUITE});
}

/** The draft's Sign. */
export async function sign(args: {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  header: Uint8Array;
  messages: Uint8Array[];
}): Promise<Uint8Array> {
  return bbs.sign({...args, ciphersuite: CIPHERSUITE});
}

/** The draft's Verify. Returns false for an invalid signature instead of throwing. */
export async function verify(args: {
  publicKey: Uint8Array;
  signature: Uint8Array;
  header: Uint8Array;
  messages: Uint8Array[];
}): Promise<boolean> {
  if (args.signature.length !== SIGNATURE_LEN) {
    return false;
  }
  try {
    return await bbs.verifySignature({...args, ciphersuite: CIPHERSUITE});
  } catch {
    return false;
  }
}

/** The draft's ProofGen. */
export async function proofGen(args: {
  publicKey: Uint8Array;
  signature: Uint8Array;
  header: Uint8Array;
  messages: Uint8Array[];
  presentationHeader: Uint8Array;
  disclosedIndexes: number[];
}): Promise<Uint8Array> {
  const {disclosedIndexes, ...rest} = args;
  return bbs.deriveProof({
    ...rest,
    disclosedMessageIndexes: disclosedIndexes,
    ciphersuite: CIPHERSUITE
  });
}

/** The draft's ProofVerify. Returns false for an invalid proof instead of throwing. */
export async function proofVerify(args: {
  publicKey: Uint8Array;
  proof: Uint8Array;
  header: Uint8Array;
  presentationHeader: Uint8Array;
  disclosedMessages: Uint8Array[];
  disclosedIndexes: number[];
}): Promise<boolean> {
  const {disclosedIndexes, ...rest} = args;
  try {
    return await bbs.verifyProof({
      ...rest,
      disclosedMessageIndexes: disclosedIndexes,
      ciphersuite: CIPHERSUITE
    });
  } catch {
    return false;
  }
}

/** Number of undisclosed messages U, from the proof length (272 + 32U octets). */
export function undisclosedCount(proof: Uint8Array): number {
  const u = (proof.length - 272) / 32;
  if (!Number.isInteger(u) || u < 0) {
    throw new Error(`a BBS proof of ${proof.length} octets does not match 272 + 32U`);
  }
  return u;
}
