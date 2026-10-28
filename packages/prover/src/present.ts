// Presentation generation: answer the disclosure policy's query from one
// credential by deriving bbs-2023 disclosure proofs.

import {webcrypto} from 'node:crypto';
import {
  bytesEqual,
  deriveCredential,
  parseDerivedProofValue,
  toHex,
  verifyDerivedCredential,
  type CredentialRecord,
  type AnsweredPresentation,
  type DocumentLoader,
  type NonAnswer,
  type SignedCredential
} from '@bbs-anonymity-set/common';
import type {ClaimQuery, DisclosurePolicy} from './policy.ts';

/** What the Prover discloses for one credential, or why it cannot answer. */
export type Selection =
  | {ok: true; claimSet: number | null; pointers: string[]}
  | {ok: false; reason: string};

/**
 * Applies the DCQL claim selection rules (OpenID4VP §6.4.1):
 * - no claims: disclose only the mandatory statements;
 * - claims without claim_sets: all claims are required;
 * - claim_sets: the first option whose claims are all present.
 * A claim whose value does not match its `values` counts as absent. If the
 * query cannot be satisfied, nothing is returned.
 */
export function selectClaims(policy: DisclosurePolicy, credential: SignedCredential): Selection {
  const claims = policy.query.claims;
  if (claims === undefined) {
    return {ok: true, claimSet: null, pointers: []};
  }
  const present = new Map(claims.map(c => [c.id, claimPresent(c, credential)]));
  const pointersFor = (ids: string[]) =>
    ids.map(id => jsonPointer(claims.find(c => c.id === id)!.path));

  const sets = policy.query.claimSets;
  if (sets === undefined) {
    const missing = claims.filter(c => !present.get(c.id)).map(c => c.id);
    return missing.length === 0
      ? {ok: true, claimSet: null, pointers: pointersFor(claims.map(c => c.id))}
      : {ok: false, reason: `claims not present: ${missing.join(', ')}`};
  }
  const index = sets.findIndex(set => set.every(id => present.get(id)));
  if (index === -1) {
    return {ok: false, reason: 'no claim set can be satisfied'};
  }
  return {ok: true, claimSet: index, pointers: pointersFor(sets[index]!)};
}

/** Whether the claim exists in the credential and, if `values` is given, matches one. */
function claimPresent(claim: ClaimQuery, credential: SignedCredential): boolean {
  const value = resolvePath(credential, claim.path);
  if (value === undefined) {
    return false;
  }
  return claim.values === undefined || claim.values.some(v => v === value);
}

/**
 * Claims path pointer processing (OpenID4VP §7.1.1) for strings and indexes.
 * Returns undefined when the claim does not exist. A path that steps into a
 * value of the wrong type is an error, as in the spec.
 */
export function resolvePath(document: unknown, path: Array<string | number>): unknown {
  let current: unknown = document;
  for (const component of path) {
    if (typeof component === 'string') {
      if (typeof current !== 'object' || current === null || Array.isArray(current)) {
        throw new Error(`claims path ${JSON.stringify(path)} selects a key in a non-object`);
      }
      if (!Object.hasOwn(current, component)) {
        return undefined;
      }
      current = (current as Record<string, unknown>)[component];
    } else {
      if (!Array.isArray(current)) {
        throw new Error(`claims path ${JSON.stringify(path)} selects an index in a non-array`);
      }
      if (component >= current.length) {
        return undefined;
      }
      current = current[component];
    }
  }
  return current;
}

/** The JSON Pointer (RFC 6901) for a claims path. */
export function jsonPointer(path: Array<string | number>): string {
  return path.map(c => '/' + String(c).replaceAll('~', '~0').replaceAll('/', '~1')).join('');
}

export type PresentOutcome =
  | {ok: true; records: AnsweredPresentation[]}
  | {ok: false; reason: string};

/**
 * Makes `policy.presentation.count` presentations from one credential. With
 * `verify`, each is checked with the library's verifier before it is
 * returned (against the Verifier's nonce in "nonce" mode).
 */
export async function present(
  record: CredentialRecord,
  policy: DisclosurePolicy,
  documentLoader: DocumentLoader,
  verify: boolean
): Promise<PresentOutcome> {
  const selection = selectClaims(policy, record.credential);
  if (!selection.ok) {
    return selection;
  }
  const records: AnsweredPresentation[] = [];
  for (let i = 0; i < policy.presentation.count; i++) {
    const presentationHeader = presentationHeaderFor(policy);
    const derived = await deriveCredential({
      credential: record.credential,
      selectivePointers: selection.pointers,
      presentationHeader,
      documentLoader
    }).catch((e: Error) => {
      throw new Error(`deriving for prover ${record.prover_id}: ${e.message}`);
    });

    const parsed = parseDerivedProofValue(derived.proof.proofValue);
    if (!bytesEqual(parsed.presentationHeader, presentationHeader)) {
      throw new Error(`prover ${record.prover_id}: derived proof carries a different presentation header`);
    }
    const nonce = policy.presentation.header.mode === 'nonce' ? presentationHeader : undefined;
    if (verify) {
      const result = await verifyDerivedCredential(derived, documentLoader, nonce);
      if (!result.verified) {
        throw new Error(
          `verifying the presentation just made for prover ${record.prover_id}: ${result.error ?? 'invalid'}`
        );
      }
    }
    records.push({
      prover_id: record.prover_id,
      key_id: record.key_id,
      presentation_index: i,
      claim_set: selection.claimSet,
      ...(nonce === undefined ? {} : {verifier_nonce: toHex(nonce)}),
      presentation: derived
    });
  }
  return {ok: true, records};
}

/**
 * The records for a credential that cannot answer the query: one per request,
 * so non-answers are counted the same way as presentations.
 */
export function nonAnswers(record: CredentialRecord, policy: DisclosurePolicy, reason: string): NonAnswer[] {
  return Array.from({length: policy.presentation.count}, (_, i) => ({
    prover_id: record.prover_id,
    key_id: record.key_id,
    presentation_index: i,
    claim_set: null,
    presentation: null,
    reason
  }));
}

function presentationHeaderFor(policy: DisclosurePolicy): Uint8Array {
  const header = policy.presentation.header;
  switch (header.mode) {
    case 'empty':
      return new Uint8Array();
    case 'fixed':
      return header.value.slice();
    case 'random':
    case 'nonce':
      return webcrypto.getRandomValues(new Uint8Array(32));
  }
}

/** Counts for the end-of-run summary; sanity checks, not the analysis. */
export interface PresentationSummary {
  credentials: number;
  presentations: number;
  /** Provers that could not answer, with the reason. */
  unanswered: Array<{prover_id: string; reason: string}>;
  /** Presentations per claim set index (null: no claim_sets). */
  perClaimSet: Map<number | null, number>;
  /** Presentations per undisclosed message count U. */
  perU: Map<number, number>;
  /** Presentations per number of disclosed BBS messages. */
  perDisclosed: Map<number, number>;
}

export function summarize(
  credentials: number,
  records: AnsweredPresentation[],
  unanswered: Array<{prover_id: string; reason: string}>
): PresentationSummary {
  const s: PresentationSummary = {
    credentials,
    presentations: records.length,
    unanswered,
    perClaimSet: new Map(),
    perU: new Map(),
    perDisclosed: new Map()
  };
  const bump = <K>(m: Map<K, number>, k: K) => m.set(k, (m.get(k) ?? 0) + 1);
  for (const r of records) {
    const p = parseDerivedProofValue(r.presentation.proof.proofValue);
    bump(s.perClaimSet, r.claim_set);
    bump(s.perU, p.undisclosedCount);
    bump(s.perDisclosed, p.selectiveIndexes.length);
  }
  return s;
}
