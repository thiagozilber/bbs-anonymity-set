// Everything that crosses a process boundary (key files, population records,
// credential records) is defined here, so the Issuer, Prover and Verifier
// cannot drift apart. All of it is written as JSON or JSON Lines.

import type {Ciphersuite} from './bbs.ts';

/** An Issuer key pair as written by `issuer keygen`. Contains the secret key. */
export interface IssuerKeyFile extends PublicKeyFile {
  /** Hex-encoded secret key (32 octets). */
  secret_key: string;
}

/** An Issuer public key, as distributed to Provers and Verifiers. */
export interface PublicKeyFile {
  key_id: string;
  ciphersuite: Ciphersuite;
  /** Hex-encoded public key (96 octets, compressed G2 point). */
  public_key: string;
  /** The Issuer's id, used as the credential's `issuer`. */
  controller: string;
  /** Id of the Multikey verification method, referenced by every proof. */
  verification_method: string;
}

export function publicPart(key: IssuerKeyFile): PublicKeyFile {
  const {secret_key: _secret, ...pub} = key;
  return pub;
}

export type Scalar = string | number | boolean;

/**
 * One Prover in the input population, as produced by the population generator.
 * Attribute values must be JSON scalars; `null` is treated as absent.
 */
export interface PopulationRecord {
  prover_id: string;
  attributes: Record<string, Scalar | null>;
}

/** A Data Integrity proof as it appears in a credential. */
export interface DataIntegrityProof {
  type: 'DataIntegrityProof';
  cryptosuite: string;
  verificationMethod: string;
  proofPurpose: string;
  proofValue: string;
  [other: string]: unknown;
}

export interface Credential {
  '@context': string[];
  type: string[];
  issuer: string;
  credentialSubject: Record<string, Scalar>;
  [other: string]: unknown;
}

export interface SignedCredential extends Credential {
  proof: DataIntegrityProof;
}

/** One issued credential, as written by `issuer issue`. */
export interface CredentialRecord {
  /** Ground-truth label. Carried for the analysis; never part of what is signed. */
  prover_id: string;
  key_id: string;
  /** The credential with its bbs-2023 base proof. */
  credential: SignedCredential;
}

/**
 * One presentation, as written by `prover present`. The Verifier observer
 * reads only `presentation` and `verifier_nonce`, which a real Verifier has;
 * the other fields are ground truth for the analysis.
 */
export interface PresentationRecord {
  prover_id: string;
  key_id: string;
  /** 0-based index among the presentations made from this credential. */
  presentation_index: number;
  /** Index of the presented option in the policy's claim_sets; null without claim_sets. */
  claim_set: number | null;
  /** Hex. Only with presentation header mode "nonce": the Verifier's nonce. */
  verifier_nonce?: string;
  /** The derived credential with its bbs-2023 disclosure proof. */
  presentation: SignedCredential;
}
