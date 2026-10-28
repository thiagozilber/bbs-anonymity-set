// The Verifier observer: verifies each presentation as an honest Verifier
// does and records every channel it can see. Which channels form the
// observation tuple is decided in the analysis, not here.

import {
  fromHex,
  inspectDerivedProof,
  toHex,
  verifyDerivedCredential,
  type DocumentLoader,
  type Observation,
  type ObservationRecord,
  type PresentationRecord
} from '@bbs-anonymity-set/common';

export type ObserveOutcome = {ok: true; record: ObservationRecord} | {ok: false; reason: string};

/**
 * Observes one line of `prover present` output. A non-answer is passed
 * through with no observation. A presentation is verified first (against the
 * Verifier's nonce, if there is one); one that fails is rejected.
 */
export async function observe(
  input: PresentationRecord,
  verifierId: string,
  documentLoader: DocumentLoader
): Promise<ObserveOutcome> {
  if (input.presentation === null) {
    return {
      ok: true,
      record: {
        verifier_id: verifierId,
        answered: false,
        observation: null,
        truth: {
          prover_id: input.prover_id,
          key_id: input.key_id,
          presentation_index: input.presentation_index,
          claim_set: null,
          reason: input.reason
        }
      }
    };
  }

  const presentation = input.presentation;
  let nonce: Uint8Array | undefined;
  try {
    nonce = input.verifier_nonce === undefined ? undefined : fromHex(input.verifier_nonce, 'verifier_nonce');
  } catch (e) {
    return {ok: false, reason: (e as Error).message};
  }
  const verified = await verifyDerivedCredential(presentation, documentLoader, nonce).catch(
    (e: Error) => ({verified: false, error: e.message})
  );
  if (!verified.verified) {
    return {ok: false, reason: verified.error ?? 'proof does not verify'};
  }

  let observation: Observation;
  try {
    const i = await inspectDerivedProof(presentation, documentLoader);
    const p = i.proofValue;
    observation = {
      u: p.undisclosedCount,
      l: i.messageCount,
      disclosed_count: i.disclosedCount,
      mandatory_count: i.mandatoryCount,
      total_statements: i.totalStatements,
      selective_indexes: p.selectiveIndexes,
      mandatory_indexes: p.mandatoryIndexes,
      header: toHex(i.header),
      label_map: [...p.compressedLabelMap].sort((a, b) => a[0] - b[0]),
      revealed_nquads: i.nquads,
      presentation_header: toHex(p.presentationHeader),
      proof_length: p.bbsProof.length,
      issuer: presentation.issuer,
      verification_method: presentation.proof.verificationMethod,
      disclosed: {...presentation.credentialSubject}
    };
  } catch (e) {
    return {ok: false, reason: (e as Error).message};
  }

  return {
    ok: true,
    record: {
      verifier_id: verifierId,
      answered: true,
      observation,
      truth: {
        prover_id: input.prover_id,
        key_id: input.key_id,
        presentation_index: input.presentation_index,
        claim_set: input.claim_set
      }
    }
  };
}

/** Counts for the end-of-run summary; sanity checks, not the analysis. */
export interface ObservationSummary {
  records: number;
  answered: number;
  nonAnswers: number;
  perU: Map<number, number>;
  /** Distinct BBS header values. */
  headers: number;
  /** Distinct (U, total statements, disclosed index set, header) tuples. */
  coreTuples: number;
}

export function summarize(records: ObservationRecord[]): ObservationSummary {
  const s: ObservationSummary = {
    records: records.length,
    answered: 0,
    nonAnswers: 0,
    perU: new Map(),
    headers: 0,
    coreTuples: 0
  };
  const headers = new Set<string>();
  const tuples = new Set<string>();
  for (const r of records) {
    const o = r.observation;
    if (o === null) {
      s.nonAnswers++;
      continue;
    }
    s.answered++;
    s.perU.set(o.u, (s.perU.get(o.u) ?? 0) + 1);
    headers.add(o.header);
    tuples.add(JSON.stringify([o.u, o.total_statements, o.selective_indexes, o.header]));
  }
  s.headers = headers.size;
  s.coreTuples = tuples.size;
  return s;
}
