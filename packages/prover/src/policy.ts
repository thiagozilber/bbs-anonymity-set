// Disclosure policy, read from a TOML file: what the Verifier asks for and
// how the Prover answers. One file per sweep point.
//
// The query is a subset of a DCQL Credential Query (OpenID4VP §6): `claims`
// with `id`, `path` and optional `values`, and optional `claim_sets`. Only one
// credential is queried, so there are no `credentials` or `credential_sets`
// arrays. Claims path pointers may contain strings and non-negative integers;
// `null` (all array elements) is rejected because the PID credential has no
// arrays.

import {readFileSync} from 'node:fs';
import {fromHex, type Scalar} from '@bbs-anonymity-set/common';
import {parse} from 'smol-toml';

export interface ClaimQuery {
  id: string;
  path: Array<string | number>;
  /** If present, the claim only counts as present when its value is one of these. */
  values?: Scalar[];
}

export type PresentationHeaderMode =
  | {mode: 'empty'}
  /** A fresh 32-octet value per proof, chosen by the Prover. */
  | {mode: 'random'}
  /** A fresh 32-octet value per proof, chosen by the Verifier and recorded for it. */
  | {mode: 'nonce'}
  /** The same value for every proof (models presentation-header reuse). */
  | {mode: 'fixed'; value: Uint8Array};

export interface DisclosurePolicy {
  query: {
    /** Absent: only mandatory statements are disclosed. */
    claims?: ClaimQuery[];
    /** Alternatives in the Verifier's order of preference, as claim ids. */
    claimSets?: string[][];
  };
  presentation: {
    /** Presentations per credential. */
    count: number;
    header: PresentationHeaderMode;
  };
}

export function loadPolicy(path: string): DisclosurePolicy {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    throw new Error(`reading ${path}: ${(e as Error).message}`);
  }
  try {
    return parsePolicy(parse(text));
  } catch (e) {
    throw new Error(`${path}: ${(e as Error).message}`);
  }
}

const CLAIM_ID = /^[A-Za-z0-9_-]+$/;

/** Validates a parsed TOML document. Unknown keys are errors. */
export function parsePolicy(raw: unknown): DisclosurePolicy {
  const top = table(raw, 'policy', ['query', 'presentation']);
  const query = table(top['query'] ?? {}, 'query', ['claims', 'claim_sets']);
  const presentation = table(top['presentation'] ?? {}, 'presentation', ['count', 'header', 'header_value']);

  const policy: DisclosurePolicy = {query: {}, presentation: {count: 1, header: {mode: 'empty'}}};

  if (query['claims'] !== undefined) {
    if (!Array.isArray(query['claims']) || query['claims'].length === 0) {
      throw new Error('query.claims must be a non-empty array of tables');
    }
    const ids = new Set<string>();
    policy.query.claims = query['claims'].map((c, i) => {
      const where = `query.claims[${i}]`;
      const t = table(c, where, ['id', 'path', 'values']);
      const id = t['id'];
      if (typeof id !== 'string' || !CLAIM_ID.test(id)) {
        throw new Error(`${where}.id must be a non-empty string of [A-Za-z0-9_-]`);
      }
      if (ids.has(id)) {
        throw new Error(`claim id ${JSON.stringify(id)} is used twice`);
      }
      ids.add(id);
      const claim: ClaimQuery = {id, path: parsePath(t['path'], where)};
      if (t['values'] !== undefined) {
        const values = t['values'];
        if (
          !Array.isArray(values) ||
          values.length === 0 ||
          !values.every(v => ['string', 'number', 'boolean'].includes(typeof v))
        ) {
          throw new Error(`${where}.values must be a non-empty array of strings, integers or booleans`);
        }
        claim.values = values as Scalar[];
      }
      return claim;
    });
  }

  if (query['claim_sets'] !== undefined) {
    const claims = policy.query.claims;
    if (claims === undefined) {
      throw new Error('query.claim_sets requires query.claims');
    }
    const sets = query['claim_sets'];
    if (!Array.isArray(sets) || sets.length === 0) {
      throw new Error('query.claim_sets must be a non-empty array of arrays of claim ids');
    }
    policy.query.claimSets = sets.map((set, i) => {
      if (!Array.isArray(set) || set.length === 0 || !set.every(id => typeof id === 'string')) {
        throw new Error(`query.claim_sets[${i}] must be a non-empty array of claim ids`);
      }
      for (const id of set) {
        if (!claims.some(c => c.id === id)) {
          throw new Error(`query.claim_sets[${i}] names unknown claim ${JSON.stringify(id)}`);
        }
      }
      return set as string[];
    });
  }

  const count = presentation['count'] ?? 1;
  if (typeof count !== 'number' || !Number.isSafeInteger(count) || count < 1) {
    throw new Error('presentation.count must be a positive integer');
  }
  policy.presentation.count = count;

  const mode = presentation['header'] ?? 'empty';
  const value = presentation['header_value'];
  if (mode === 'fixed') {
    if (typeof value !== 'string') {
      throw new Error('presentation.header = "fixed" needs presentation.header_value (hex)');
    }
    policy.presentation.header = {mode: 'fixed', value: fromHex(value, 'presentation.header_value')};
  } else if (mode === 'empty' || mode === 'random' || mode === 'nonce') {
    if (value !== undefined) {
      throw new Error('presentation.header_value is only used with header = "fixed"');
    }
    policy.presentation.header = {mode};
  } else {
    throw new Error('presentation.header must be "empty", "random", "nonce" or "fixed"');
  }
  return policy;
}

function parsePath(value: unknown, where: string): Array<string | number> {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${where}.path must be a non-empty array`);
  }
  return value.map(component => {
    if (typeof component === 'string') {
      return component;
    }
    if (typeof component === 'number' && Number.isSafeInteger(component) && component >= 0) {
      return component;
    }
    throw new Error(`${where}.path components must be strings or non-negative integers`);
  });
}

function table(value: unknown, where: string, keys: string[]): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${where} must be a table`);
  }
  for (const k of Object.keys(value)) {
    if (!keys.includes(k)) {
      throw new Error(`${where}: unknown key ${JSON.stringify(k)}`);
    }
  }
  return value as Record<string, unknown>;
}
