// Type declarations for the untyped Digital Bazaar packages and their helpers.
//
// They cover only what packages/common uses, and they are only used from
// packages/common/src/bbs.ts and packages/common/src/bbs2023.ts. Everything
// else in the repo imports the typed wrappers in those two files.

declare module '@digitalbazaar/bbs-signatures' {
  export type Ciphersuite = 'BLS12-381-SHA-256' | 'BLS12-381-SHAKE-256';
  export function generateKeyPair(args: {
    seed?: Uint8Array;
    ciphersuite: Ciphersuite;
  }): Promise<{secretKey: Uint8Array; publicKey: Uint8Array}>;
  export function secretKeyToPublicKey(args: {
    secretKey: Uint8Array;
    ciphersuite: Ciphersuite;
  }): Promise<Uint8Array>;
  export function sign(args: {
    secretKey: Uint8Array;
    publicKey: Uint8Array;
    header: Uint8Array;
    messages: Uint8Array[];
    ciphersuite: Ciphersuite;
  }): Promise<Uint8Array>;
  export function verifySignature(args: {
    publicKey: Uint8Array;
    signature: Uint8Array;
    header: Uint8Array;
    messages: Uint8Array[];
    ciphersuite: Ciphersuite;
  }): Promise<boolean>;
  export function deriveProof(args: {
    publicKey: Uint8Array;
    signature: Uint8Array;
    header: Uint8Array;
    messages: Uint8Array[];
    presentationHeader: Uint8Array;
    disclosedMessageIndexes: number[];
    ciphersuite: Ciphersuite;
  }): Promise<Uint8Array>;
  export function verifyProof(args: {
    publicKey: Uint8Array;
    proof: Uint8Array;
    header: Uint8Array;
    presentationHeader: Uint8Array;
    disclosedMessages: Uint8Array[];
    disclosedMessageIndexes: number[];
    ciphersuite: Ciphersuite;
  }): Promise<boolean>;
}

declare module '@digitalbazaar/bls12-381-multikey' {
  export const ALGORITHMS: {readonly BBS_BLS12381_SHA256: 'BBS-BLS12-381-SHA-256'};
  export interface Signer {
    id: string;
    algorithm: string;
  }
  export interface KeyPair {
    id?: string;
    controller?: string;
    publicKeyMultibase: string;
    signer(): Signer;
    export(args: {publicKey?: boolean; secretKey?: boolean; includeContext?: boolean}): Promise<
      Record<string, unknown>
    >;
  }
  export function fromRaw(args: {
    algorithm: string;
    secretKey?: Uint8Array;
    publicKey: Uint8Array;
  }): Promise<KeyPair>;
}

declare module '@digitalbazaar/bbs-2023-cryptosuite' {
  export interface Cryptosuite {
    readonly name: string;
  }
  export function createSignCryptosuite(args?: {mandatoryPointers?: string[]}): Cryptosuite;
  export function createDiscloseCryptosuite(args?: {
    proofId?: string;
    selectivePointers?: string[];
    presentationHeader?: Uint8Array;
  }): Cryptosuite;
  export function createVerifyCryptosuite(args?: {
    expectedPresentationHeader?: Uint8Array;
  }): Cryptosuite;
}

declare module '@digitalbazaar/data-integrity' {
  import type {Signer} from '@digitalbazaar/bls12-381-multikey';
  import type {Cryptosuite} from '@digitalbazaar/bbs-2023-cryptosuite';
  export class DataIntegrityProof {
    constructor(args: {signer?: Signer; cryptosuite: Cryptosuite});
  }
}

declare module '@digitalbazaar/vc' {
  import type {DataIntegrityProof} from '@digitalbazaar/data-integrity';
  export type DocumentLoader = (url: string) => Promise<{
    contextUrl: string | null;
    documentUrl: string;
    document: unknown;
  }>;
  export function issue(args: {
    credential: object;
    suite: DataIntegrityProof;
    documentLoader: DocumentLoader;
  }): Promise<Record<string, unknown>>;
  export function derive(args: {
    verifiableCredential: object;
    suite: DataIntegrityProof;
    documentLoader: DocumentLoader;
  }): Promise<Record<string, unknown>>;
  export function verifyCredential(args: {
    credential: object;
    suite: DataIntegrityProof;
    documentLoader: DocumentLoader;
  }): Promise<{verified: boolean; error?: {errors?: Error[]; message?: string}}>;
}

declare module '@digitalbazaar/di-sd-primitives' {
  import type {DocumentLoader} from '@digitalbazaar/vc';
  export interface Hmac {
    export(): Promise<Uint8Array>;
  }
  export type LabelMapFactory = (args: {
    canonicalIdMap: Map<string, string>;
  }) => Promise<Map<string, string>>;
  export interface Group {
    matching: Map<number, string>;
    nonMatching: Map<number, string>;
  }
  export function createHmac(args: {key: Uint8Array | null}): Promise<Hmac>;
  export function createHmacIdLabelMapFunction(args: {hmac: Hmac}): LabelMapFactory;
  export function canonicalizeAndGroup(args: {
    document: object;
    labelMapFactoryFunction: LabelMapFactory;
    groups: Record<string, string[]>;
    options: {documentLoader: DocumentLoader};
  }): Promise<{groups: Record<string, Group>; labelMap: Map<string, string>}>;
  export function hashCanonizedProof(args: {
    document: object;
    proof: object;
    options: {documentLoader: DocumentLoader};
  }): Promise<Uint8Array>;
  export function hashMandatory(args: {mandatory: string[]}): Promise<{mandatoryHash: Uint8Array}>;
  export function stringToUtf8Bytes(s: string): Uint8Array;
}

declare module '@digitalbazaar/credentials-context' {
  export const contexts: Map<string, object>;
}

declare module '@digitalbazaar/multikey-context' {
  export const CONTEXT_URL: string;
  export const CONTEXT: object;
}

declare module '@digitalbazaar/security-context' {
  export const SECURITY_CONTEXT_V2_URL: string;
  export const contexts: Map<string, object>;
}

declare module 'base64url-universal' {
  export function encode(bytes: Uint8Array): string;
  export function decode(s: string): Uint8Array;
}
