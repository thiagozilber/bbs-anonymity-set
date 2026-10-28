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
 * One line of `prover present` output: a presentation, or a request the
 * Prover could not answer. The Verifier observer reads only `presentation`
 * and `verifier_nonce`, which a real Verifier has; the other fields are
 * ground truth for the analysis.
 */
export type PresentationRecord = AnsweredPresentation | NonAnswer;

interface PresentationRecordBase {
  prover_id: string;
  key_id: string;
  /** 0-based index among the requests made to this credential. */
  presentation_index: number;
}

export interface AnsweredPresentation extends PresentationRecordBase {
  /** Index of the presented option in the policy's claim_sets; null without claim_sets. */
  claim_set: number | null;
  /** Hex. Only with presentation header mode "nonce": the Verifier's nonce. */
  verifier_nonce?: string;
  /** The derived credential with its bbs-2023 disclosure proof. */
  presentation: SignedCredential;
}

export interface NonAnswer extends PresentationRecordBase {
  claim_set: null;
  /** The Verifier receives nothing. */
  presentation: null;
  /** Ground truth: why the Prover could not answer. */
  reason: string;
}

/** Disclosed values, as the Verifier reads them from the revealed credential. */
export type DisclosedValues = Record<string, Scalar>;

/**
 * What one Verifier records for one request, as written by `verifier observe`.
 * `observation` holds only what the Verifier computes; `truth` is carried
 * through for the analysis and must not be used to form tuples.
 */
export interface ObservationRecord {
  verifier_id: string;
  /** False when the Prover made no presentation. */
  answered: boolean;
  observation: Observation | null;
  truth: {
    prover_id: string;
    key_id: string;
    presentation_index: number;
    claim_set: number | null;
    /** Only for non-answers. */
    reason?: string;
  };
}

/** Every channel a Verifier sees in a verified bbs-2023 presentation. */
export interface Observation {
  /** Undisclosed BBS messages, from the proof length (272 + 32U octets). */
  u: number;
  /** BBS messages L = U + R. */
  l: number;
  /** Disclosed BBS messages R. */
  disclosed_count: number;
  mandatory_count: number;
  /** mandatory_count + L. */
  total_statements: number;
  /** BBS indexes of the disclosed messages. */
  selective_indexes: number[];
  /** Positions of the mandatory statements among the revealed ones. */
  mandatory_indexes: number[];
  /** Hex BBS header, proofHash || mandatoryHash. */
  header: string;
  /**
   * Compressed label map as [canonical, shuffled] pairs, sorted by canonical.
   * The canonical side depends on what was revealed, so the map is fixed for
   * one credential and one request, not across requests.
   */
  label_map: Array<[number, number]>;
  /**
   * The revealed N-Quads with the HMAC-shuffled blank node labels, as used to
   * verify. A blank node has the same label in every presentation of a
   * credential, whatever the request.
   */
  revealed_nquads: string[];
  /** Hex presentation header. */
  presentation_header: string;
  proof_length: number;
  issuer: string;
  verification_method: string;
  /** credentialSubject of the revealed credential. */
  disclosed: DisclosedValues;
}
