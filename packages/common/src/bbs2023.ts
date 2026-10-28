// Typed wrapper over Digital Bazaar's bbs-2023 stack (@digitalbazaar/vc,
// data-integrity, bbs-2023-cryptosuite, di-sd-primitives).
//
// Issuing, deriving and verifying derived proofs call the library as-is. The
// library has no Holder-side check of a base proof, so `inspectBaseProof`
// rebuilds the BBS Sign inputs the way the cryptosuite's sign step does (same
// di-sd-primitives calls, same HMAC label shuffle) and runs the draft's Verify
// on them. The tests cross-check it against the library's derive and verify.

import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import {
  createDiscloseCryptosuite,
  createSignCryptosuite,
  createVerifyCryptosuite
} from '@digitalbazaar/bbs-2023-cryptosuite';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {
  canonicalizeAndGroup,
  createHmac,
  createHmacIdLabelMapFunction,
  hashCanonizedProof,
  hashMandatory,
  stringToUtf8Bytes,
  type Hmac,
  type LabelMapFactory
} from '@digitalbazaar/di-sd-primitives';
import * as vc from '@digitalbazaar/vc';
import * as base64url from 'base64url-universal';
import * as cborg from 'cborg';
import * as bbs from './bbs.ts';
import {createDocumentLoader, type DocumentLoader} from './contexts.ts';
import {bytesEqual, fromHex, toHex} from './hex.ts';
import type {Credential, IssuerKeyFile, PublicKeyFile, SignedCredential} from './types.ts';

export const CRYPTOSUITE = 'bbs-2023';
const ALGORITHM = Bls12381Multikey.ALGORITHMS.BBS_BLS12381_SHA256;

/** The default Issuer id for a key id. */
export function defaultController(keyId: string): string {
  return `https://issuer.example/issuers/${keyId}`;
}

/** The key's `publicKeyMultibase`, as used in its Multikey document. */
export async function multikeyOf(key: PublicKeyFile): Promise<string> {
  const kp = await Bls12381Multikey.fromRaw({
    algorithm: ALGORITHM,
    publicKey: fromHex(key.public_key, 'public_key')
  });
  return kp.publicKeyMultibase;
}

/** Verification method id for a key: `<controller>#<publicKeyMultibase>`. */
export async function verificationMethodId(controller: string, publicKey: Uint8Array): Promise<string> {
  const kp = await Bls12381Multikey.fromRaw({algorithm: ALGORITHM, publicKey});
  return `${controller}#${kp.publicKeyMultibase}`;
}

/** Key ids name files, so they are restricted to [A-Za-z0-9_-]. */
export function validateKeyId(keyId: string): void {
  if (!/^[A-Za-z0-9_-]+$/.test(keyId)) {
    throw new Error(`key id ${JSON.stringify(keyId)} must be non-empty and use [A-Za-z0-9_-]`);
  }
}

/** Generates an Issuer key pair. With `keyMaterial` the key is reproducible. */
export async function generateIssuerKey(args: {
  keyId: string;
  keyMaterial?: Uint8Array;
  controller?: string;
}): Promise<IssuerKeyFile> {
  validateKeyId(args.keyId);
  const kp = await bbs.keygen(args.keyMaterial);
  const controller = args.controller ?? defaultController(args.keyId);
  return {
    key_id: args.keyId,
    ciphersuite: bbs.CIPHERSUITE,
    secret_key: toHex(kp.secretKey),
    public_key: toHex(kp.publicKey),
    controller,
    verification_method: await verificationMethodId(controller, kp.publicKey)
  };
}

/** A document loader that also resolves the given keys' documents. */
export async function documentLoaderFor(keys: PublicKeyFile[]): Promise<DocumentLoader> {
  const entries = await Promise.all(
    keys.map(async key => ({key, publicKeyMultibase: await multikeyOf(key)}))
  );
  return createDocumentLoader(entries);
}

// ---------------------------------------------------------------------------
// Issuing
// ---------------------------------------------------------------------------

/** Signs `credential` with a bbs-2023 base proof. */
export async function signCredential(args: {
  key: IssuerKeyFile;
  credential: Credential;
  mandatoryPointers: string[];
  documentLoader: DocumentLoader;
}): Promise<SignedCredential> {
  const {key, credential, mandatoryPointers, documentLoader} = args;
  const keyPair = await Bls12381Multikey.fromRaw({
    algorithm: ALGORITHM,
    secretKey: fromHex(key.secret_key, 'secret_key'),
    publicKey: fromHex(key.public_key, 'public_key')
  });
  // The signer reads its id from the key pair; it must be the verification method.
  keyPair.id = key.verification_method;
  const suite = new DataIntegrityProof({
    signer: keyPair.signer(),
    cryptosuite: createSignCryptosuite({mandatoryPointers: [...mandatoryPointers]})
  });
  const signed = await vc.issue({credential: structuredClone(credential), suite, documentLoader});
  return signed as unknown as SignedCredential;
}

// ---------------------------------------------------------------------------
// Base proofs
// ---------------------------------------------------------------------------

/** CBOR tag prefixes of bbs-2023 base and derived proof values. */
const BASE_PREFIX = Uint8Array.of(0xd9, 0x5d, 0x02);
const DERIVED_PREFIX = Uint8Array.of(0xd9, 0x5d, 0x03);

export interface BaseProofValue {
  bbsSignature: Uint8Array;
  bbsHeader: Uint8Array;
  publicKey: Uint8Array;
  hmacKey: Uint8Array;
  mandatoryPointers: string[];
}

export function parseBaseProofValue(proofValue: string): BaseProofValue {
  const [bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers] = decodeProofValue(
    proofValue,
    BASE_PREFIX,
    'base'
  );
  for (const [name, v] of [
    ['bbsSignature', bbsSignature],
    ['bbsHeader', bbsHeader],
    ['publicKey', publicKey],
    ['hmacKey', hmacKey]
  ] as const) {
    if (!(v instanceof Uint8Array)) {
      throw new Error(`base proof value: ${name} is not a byte string`);
    }
  }
  if (!Array.isArray(mandatoryPointers) || !mandatoryPointers.every(p => typeof p === 'string')) {
    throw new Error('base proof value: mandatoryPointers is not an array of strings');
  }
  return {
    bbsSignature: bbsSignature as Uint8Array,
    bbsHeader: bbsHeader as Uint8Array,
    publicKey: publicKey as Uint8Array,
    hmacKey: hmacKey as Uint8Array,
    mandatoryPointers: mandatoryPointers as string[]
  };
}

/** What a base proof commits to, recomputed from the credential. */
export interface BaseProofInspection {
  /** `bbsHeader` as stored in the proof value. */
  storedHeader: Uint8Array;
  /** `proofHash || mandatoryHash`, recomputed from the credential. */
  header: Uint8Array;
  mandatoryPointers: string[];
  /** Number of mandatory N-Quads. */
  mandatoryCount: number;
  /** Number of BBS messages L: the non-mandatory N-Quads. */
  messageCount: number;
  /** All N-Quads of the credential: mandatoryCount + messageCount. */
  totalStatements: number;
  /** The BBS messages (non-mandatory N-Quads, after the HMAC label shuffle). */
  messages: string[];
  bbsSignature: Uint8Array;
  publicKey: Uint8Array;
}

/**
 * Recomputes the BBS header and messages a base proof was signed over, as the
 * cryptosuite's sign step does. Does not verify
 * the signature; `checkBaseProof` does.
 */
export async function inspectBaseProof(
  credential: SignedCredential,
  documentLoader: DocumentLoader
): Promise<BaseProofInspection> {
  const {proof, ...document} = credential;
  if (proof?.type !== 'DataIntegrityProof' || proof.cryptosuite !== CRYPTOSUITE) {
    throw new Error(`proof is not a ${CRYPTOSUITE} DataIntegrityProof`);
  }
  const parsed = parseBaseProofValue(proof.proofValue);
  const {proofValue: _value, ...proofOptions} = proof;
  const options = {documentLoader};

  // proofHash: the proof options canonicalized under the document's context.
  const proofHash = await hashCanonizedProof({
    document,
    proof: {...proofOptions, '@context': document['@context']},
    options
  });

  // Canonicalize with the HMAC-shuffled blank node labels and split the
  // N-Quads into mandatory and non-mandatory.
  const hmac = await createHmac({key: parsed.hmacKey});
  const {groups} = await canonicalizeAndGroup({
    document,
    labelMapFactoryFunction: shuffledIdLabelMap(hmac),
    groups: {mandatory: parsed.mandatoryPointers},
    options
  });
  const group = groups['mandatory'];
  if (group === undefined) {
    throw new Error('canonicalizeAndGroup returned no mandatory group');
  }
  const mandatory = [...group.matching.values()];
  const messages = [...group.nonMatching.values()];
  const {mandatoryHash} = await hashMandatory({mandatory});

  const header = new Uint8Array(proofHash.length + mandatoryHash.length);
  header.set(proofHash, 0);
  header.set(mandatoryHash, proofHash.length);

  return {
    storedHeader: parsed.bbsHeader,
    header,
    mandatoryPointers: parsed.mandatoryPointers,
    mandatoryCount: mandatory.length,
    messageCount: messages.length,
    totalStatements: mandatory.length + messages.length,
    messages,
    bbsSignature: parsed.bbsSignature,
    publicKey: parsed.publicKey
  };
}

export type BaseProofCheck =
  | {ok: true; inspection: BaseProofInspection}
  | {ok: false; reason: string};

/**
 * The Holder's check of a received credential: the proof names the given key,
 * and the draft's Verify accepts the signature over the header and messages
 * recomputed from the credential.
 */
export async function checkBaseProof(
  credential: SignedCredential,
  key: PublicKeyFile,
  documentLoader: DocumentLoader
): Promise<BaseProofCheck> {
  const vm = credential.proof?.verificationMethod;
  if (vm !== key.verification_method) {
    return {ok: false, reason: `proof is under verification method ${vm}, not ${key.verification_method}`};
  }
  if (credential.issuer !== key.controller) {
    return {ok: false, reason: `issuer is ${credential.issuer}, not ${key.controller}`};
  }
  let inspection: BaseProofInspection;
  try {
    inspection = await inspectBaseProof(credential, documentLoader);
  } catch (e) {
    return {ok: false, reason: (e as Error).message};
  }
  const publicKey = fromHex(key.public_key, 'public_key');
  if (!bytesEqual(inspection.publicKey, publicKey)) {
    return {ok: false, reason: 'proof value carries a different public key'};
  }
  if (!bytesEqual(inspection.storedHeader, inspection.header)) {
    return {ok: false, reason: 'BBS header does not match the credential (proof options or mandatory statements changed)'};
  }
  const valid = await bbs.verify({
    publicKey,
    signature: inspection.bbsSignature,
    header: inspection.header,
    messages: inspection.messages.map(stringToUtf8Bytes)
  });
  return valid ? {ok: true, inspection} : {ok: false, reason: 'BBS signature does not verify'};
}

/**
 * The cryptosuite's createShuffledIdLabelMapFunction: HMAC each canonical blank node id, sort the HMAC outputs, and relabel each
 * node `b<rank>`. The library does not export it, so it is repeated here.
 */
function shuffledIdLabelMap(hmac: Hmac): LabelMapFactory {
  const hmacIds = createHmacIdLabelMapFunction({hmac});
  return async ({canonicalIdMap}) => {
    const map = await hmacIds({canonicalIdMap});
    const sorted = [...map.values()].sort();
    for (const [k, v] of map) {
      map.set(k, 'b' + sorted.indexOf(v));
    }
    return map;
  };
}

// ---------------------------------------------------------------------------
// Derived proofs
// ---------------------------------------------------------------------------

/** Derives a presentation of `credential` revealing the selective pointers. */
export async function deriveCredential(args: {
  credential: SignedCredential;
  selectivePointers: string[];
  presentationHeader?: Uint8Array;
  documentLoader: DocumentLoader;
}): Promise<SignedCredential> {
  const suite = new DataIntegrityProof({
    cryptosuite: createDiscloseCryptosuite({
      selectivePointers: [...args.selectivePointers],
      presentationHeader: args.presentationHeader ?? new Uint8Array()
    })
  });
  const derived = await vc.derive({
    verifiableCredential: args.credential,
    suite,
    documentLoader: args.documentLoader
  });
  return derived as unknown as SignedCredential;
}

/** Verifies a derived credential with the library. */
export async function verifyDerivedCredential(
  credential: SignedCredential,
  documentLoader: DocumentLoader,
  expectedPresentationHeader?: Uint8Array
): Promise<{verified: boolean; error?: string}> {
  const suite = new DataIntegrityProof({
    cryptosuite: createVerifyCryptosuite(
      expectedPresentationHeader === undefined ? {} : {expectedPresentationHeader}
    )
  });
  const result = await vc.verifyCredential({credential, suite, documentLoader});
  const error = result.error?.errors?.map(e => e.message).join('; ') ?? result.error?.message;
  return error === undefined ? {verified: result.verified} : {verified: result.verified, error};
}

export interface DerivedProofValue {
  bbsProof: Uint8Array;
  /** Canonical blank node number (c14n<k>) to HMAC-shuffled label number (b<v>). */
  compressedLabelMap: Map<number, number>;
  /** Positions of the mandatory N-Quads among the revealed N-Quads, ascending. */
  mandatoryIndexes: number[];
  /** BBS indexes of the disclosed non-mandatory messages, ascending. */
  selectiveIndexes: number[];
  presentationHeader: Uint8Array;
  /** Undisclosed message count U, from the length of `bbsProof`. */
  undisclosedCount: number;
}

/**
 * Parses and validates a derived proof value. The Verifier observer reads the
 * observation tuple from it, so anything malformed is an error here rather
 * than a wrong tuple later.
 *
 * Checks the library makes (`_validateDerivedProofParams` in the
 * cryptosuite's `proofValue.js`): byte strings for `bbsProof` and
 * `presentationHeader`, a map for the label map, integer arrays for the
 * indexes. Checks added here:
 * - `bbsProof` is 272 + 32U octets, as the draft's octets_to_proof requires;
 * - label map keys and values are non-negative integers, and no two keys map
 *   to the same label;
 * - both index arrays are non-negative and strictly ascending. The draft
 *   requires ascending disclosed indexes; the cryptosuite produces both
 *   arrays in ascending order.
 */
export function parseDerivedProofValue(proofValue: string): DerivedProofValue {
  const [bbsProof, compressedLabelMap, mandatoryIndexes, selectiveIndexes, presentationHeader] =
    decodeProofValue(proofValue, DERIVED_PREFIX, 'derived');

  if (!(bbsProof instanceof Uint8Array)) {
    throw new Error('derived proof value: bbsProof is not a byte string');
  }
  let u: number;
  try {
    u = bbs.undisclosedCount(bbsProof);
  } catch (e) {
    throw new Error(`derived proof value: ${(e as Error).message}`);
  }
  if (!(presentationHeader instanceof Uint8Array)) {
    throw new Error('derived proof value: presentationHeader is not a byte string');
  }
  return {
    bbsProof,
    compressedLabelMap: checkLabelMap(compressedLabelMap),
    mandatoryIndexes: checkIndexes(mandatoryIndexes, 'mandatoryIndexes'),
    selectiveIndexes: checkIndexes(selectiveIndexes, 'selectiveIndexes'),
    presentationHeader,
    undisclosedCount: u
  };
}

function isIndex(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
}

function checkLabelMap(value: unknown): Map<number, number> {
  if (!(value instanceof Map)) {
    throw new Error('derived proof value: label map is not a CBOR map');
  }
  const labels = new Set<number>();
  for (const [k, v] of value as Map<unknown, unknown>) {
    if (!isIndex(k) || !isIndex(v)) {
      throw new Error('derived proof value: label map entries must be non-negative integers');
    }
    if (labels.has(v)) {
      throw new Error(`derived proof value: label map maps two blank nodes to b${v}`);
    }
    labels.add(v);
  }
  return value as Map<number, number>;
}

function checkIndexes(value: unknown, name: string): number[] {
  if (!Array.isArray(value) || !value.every(isIndex)) {
    throw new Error(`derived proof value: ${name} must be an array of non-negative integers`);
  }
  const indexes: number[] = value;
  if (indexes.some((x, i) => i > 0 && x <= indexes[i - 1]!)) {
    throw new Error(`derived proof value: ${name} is not strictly ascending`);
  }
  return indexes;
}

/**
 * Some implementations encode byte strings as CBOR tag 64 (an RFC 8746 typed
 * array of uint8) instead of major type 2. The cryptosuite accepts both, so
 * this does too.
 */
const CBOR_TAGS: Array<(inner: unknown) => unknown> = [];
CBOR_TAGS[64] = inner => inner;

/** Decodes a proof value to its 5-element CBOR array, after checking the tag prefix. */
function decodeProofValue(proofValue: string, prefix: Uint8Array, kind: string): unknown[] {
  if (typeof proofValue !== 'string' || !proofValue.startsWith('u')) {
    throw new Error('proofValue is not a base64url multibase string');
  }
  const bytes = base64url.decode(proofValue.slice(1));
  if (!bytesEqual(bytes.subarray(0, prefix.length), prefix)) {
    throw new Error(`proofValue is not a ${kind} proof`);
  }
  let decoded: unknown;
  try {
    decoded = cborg.decode(bytes.subarray(prefix.length), {useMaps: true, tags: CBOR_TAGS});
  } catch (e) {
    throw new Error(`${kind} proof value is not valid CBOR: ${(e as Error).message}`);
  }
  if (!Array.isArray(decoded) || decoded.length !== 5) {
    throw new Error(`${kind} proof value is not a 5-element CBOR array`);
  }
  return decoded;
}
