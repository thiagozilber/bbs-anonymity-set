import {spawnSync} from 'node:child_process';
import {mkdtempSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {beforeAll, describe, expect, it} from 'vitest';
import {
  documentLoaderFor,
  fromHex,
  generateIssuerKey,
  inspectBaseProof,
  parseDerivedProofValue,
  pidCredential,
  publicPart,
  readJsonl,
  signCredential,
  toHex,
  verifyDerivedCredential,
  writeJson,
  writeJsonl,
  type CredentialRecord,
  type DocumentLoader,
  type IssuerKeyFile,
  type PresentationRecord,
  type Scalar
} from '@bbs-anonymity-set/common';
import {parsePolicy} from '../src/policy.ts';
import {jsonPointer, present, resolvePath, selectClaims} from '../src/present.ts';

const repo = join(import.meta.dirname, '../../..');
const cli = join(import.meta.dirname, '../src/cli.ts');
const MANDATORY = ['/issuer', '/credentialSubject/issuing_country'];

let key: IssuerKeyFile;
let loader: DocumentLoader;
let full: CredentialRecord;
let noCity: CredentialRecord;

const issue = async (prover_id: string, subject: Record<string, Scalar>): Promise<CredentialRecord> => ({
  prover_id,
  key_id: key.key_id,
  credential: await signCredential({
    key,
    credential: pidCredential(key.controller, subject),
    mandatoryPointers: MANDATORY,
    documentLoader: loader
  })
});

const policy = (raw: object) => parsePolicy(raw);
const claim = (id: string, field: string, extra: object = {}) => ({
  id,
  path: ['credentialSubject', field],
  ...extra
});
const QUERY = {
  claims: [
    claim('adult', 'age_over_18', {values: [true]}),
    claim('country', 'resident_country'),
    claim('city', 'resident_city')
  ],
  claim_sets: [['adult', 'city'], ['adult', 'country']]
};

beforeAll(async () => {
  key = await generateIssuerKey({keyId: 'k0', keyMaterial: new Uint8Array(32).fill(4)});
  loader = await documentLoaderFor([publicPart(key)]);
  const base = {birth_date: '1994-03-12', age_over_18: true, resident_country: 'BR', issuing_country: 'BR'};
  full = await issue('p1', {...base, resident_city: 'Porto Alegre'});
  noCity = await issue('p2', base);
});

describe('claim selection', () => {
  it('without claims, discloses only mandatory statements', () => {
    expect(selectClaims(policy({}), full.credential)).toEqual({ok: true, claimSet: null, pointers: []});
  });

  it('without claim_sets, requires every claim', () => {
    const p = policy({query: {claims: QUERY.claims}});
    expect(selectClaims(p, full.credential)).toEqual({
      ok: true,
      claimSet: null,
      pointers: [
        '/credentialSubject/age_over_18',
        '/credentialSubject/resident_country',
        '/credentialSubject/resident_city'
      ]
    });
    expect(selectClaims(p, noCity.credential)).toEqual({ok: false, reason: 'claims not present: city'});
  });

  it('presents the first satisfiable claim set', () => {
    const p = policy({query: QUERY});
    expect(selectClaims(p, full.credential)).toMatchObject({ok: true, claimSet: 0});
    expect(selectClaims(p, noCity.credential)).toEqual({
      ok: true,
      claimSet: 1,
      pointers: ['/credentialSubject/age_over_18', '/credentialSubject/resident_country']
    });
  });

  it('treats a value outside `values` as absent', () => {
    const minor = structuredClone(full.credential);
    minor.credentialSubject['age_over_18'] = false;
    expect(selectClaims(policy({query: QUERY}), minor)).toEqual({ok: false, reason: 'no claim set can be satisfied'});
    // Matching is by type and value: "true" is not true.
    const stringly = structuredClone(full.credential);
    stringly.credentialSubject['age_over_18'] = 'true';
    expect(selectClaims(policy({query: QUERY}), stringly)).toMatchObject({ok: false});
  });

  it('resolves claims paths and escapes JSON pointers', () => {
    expect(resolvePath({a: [{b: 1}]}, ['a', 0, 'b'])).toBe(1);
    expect(resolvePath({a: [{b: 1}]}, ['a', 1, 'b'])).toBeUndefined();
    expect(resolvePath({a: {}}, ['a', 'missing'])).toBeUndefined();
    expect(() => resolvePath({a: 1}, ['a', 'b'])).toThrow(/non-object/);
    expect(() => resolvePath({a: {}}, ['a', 0])).toThrow(/non-array/);
    expect(jsonPointer(['credentialSubject', 'a/b', 'c~d', 2])).toBe('/credentialSubject/a~1b/c~0d/2');
  });
});

describe('present', () => {
  it('discloses the selected claims and verifies', async () => {
    const out = await present(noCity, policy({query: QUERY}), loader, true);
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    const [r] = out.records;
    expect(r!.claim_set).toBe(1);
    expect(r!.presentation.credentialSubject).toEqual({
      issuing_country: 'BR',
      age_over_18: true,
      resident_country: 'BR'
    });
    // L = 3 (birth_date, age_over_18, resident_country), 2 disclosed.
    const p = parseDerivedProofValue(r!.presentation.proof.proofValue);
    expect(p.selectiveIndexes).toHaveLength(2);
    expect(p.undisclosedCount).toBe(1);
  });

  it('returns no presentation when the query cannot be answered', async () => {
    const strict = policy({query: {claims: [claim('city', 'resident_city')]}});
    expect(await present(noCity, strict, loader, true)).toEqual({ok: false, reason: 'claims not present: city'});
  });

  it('asking for a mandatory statement discloses no extra message', async () => {
    const p = policy({query: {claims: [claim('country', 'issuing_country')]}});
    const out = await present(full, p, loader, true);
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    const parsed = parseDerivedProofValue(out.records[0]!.presentation.proof.proofValue);
    expect(parsed.selectiveIndexes).toEqual([]);
    const base = await inspectBaseProof(full.credential, loader);
    expect(parsed.undisclosedCount).toBe(base.messageCount);
  });

  it('keeps index sets and labels fixed across one credential\'s presentations', async () => {
    const out = await present(full, policy({query: QUERY, presentation: {count: 3, header: 'random'}}), loader, true);
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.records.map(r => r.presentation_index)).toEqual([0, 1, 2]);
    const parsed = out.records.map(r => parseDerivedProofValue(r.presentation.proof.proofValue));
    for (const p of parsed.slice(1)) {
      expect(p.selectiveIndexes).toEqual(parsed[0]!.selectiveIndexes);
      expect(p.mandatoryIndexes).toEqual(parsed[0]!.mandatoryIndexes);
      expect(p.compressedLabelMap).toEqual(parsed[0]!.compressedLabelMap);
      expect(toHex(p.bbsProof)).not.toBe(toHex(parsed[0]!.bbsProof));
    }
  });

  it('applies each presentation header mode', async () => {
    const headers = async (presentation: object) => {
      const out = await present(full, policy({query: QUERY, presentation: {count: 2, ...presentation}}), loader, true);
      if (!out.ok) throw new Error(out.reason);
      return out.records.map(r => ({
        record: r,
        header: toHex(parseDerivedProofValue(r.presentation.proof.proofValue).presentationHeader)
      }));
    };

    const empty = await headers({header: 'empty'});
    expect(empty.map(h => h.header)).toEqual(['', '']);
    expect(empty[0]!.record).not.toHaveProperty('verifier_nonce');

    const fixed = await headers({header: 'fixed', header_value: 'c0ffee'});
    expect(fixed.map(h => h.header)).toEqual(['c0ffee', 'c0ffee']);

    const random = await headers({header: 'random'});
    expect(random[0]!.header).toHaveLength(64);
    expect(random[0]!.header).not.toBe(random[1]!.header);
    expect(random[0]!.record).not.toHaveProperty('verifier_nonce');

    const nonce = await headers({header: 'nonce'});
    expect(nonce[0]!.header).not.toBe(nonce[1]!.header);
    for (const {record, header} of nonce) {
      expect(record.verifier_nonce).toBe(header);
    }
    // The Verifier's check against its own nonce.
    const r = nonce[0]!.record;
    expect(await verifyDerivedCredential(r.presentation, loader, fromHex(r.verifier_nonce!))).toEqual({verified: true});
    expect((await verifyDerivedCredential(r.presentation, loader, new Uint8Array(32))).verified).toBe(false);
  });
});

describe('prover present CLI', () => {
  it('presents the example population under the example policy', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'present-'));
    const run = (args: string[]) => spawnSync(process.execPath, args, {encoding: 'utf8'});
    const issuerCli = join(repo, 'packages/issuer/src/cli.ts');
    expect(run([issuerCli, 'keygen', '--key-id', 'issuer-0', '--out-dir', dir]).status).toBe(0);
    expect(
      run([
        issuerCli, 'issue',
        '--config', join(repo, 'configs/examples/pid-age.toml'),
        '--key', join(dir, 'issuer-0.key.json'),
        '--population', join(repo, 'data/examples/population.jsonl'),
        '--out', join(dir, 'credentials.jsonl')
      ]).status
    ).toBe(0);
    const out = join(dir, 'presentations.jsonl');
    const result = run([
      cli, 'present',
      '--policy', join(repo, 'configs/examples/age-check.toml'),
      '--public-key', join(dir, 'issuer-0.pub.json'),
      '--credentials', join(dir, 'credentials.jsonl'),
      '--out', out
    ]);
    expect(result.status, result.stderr).toBe(0);
    // p0002 is under 18; p0003 and p0006 have neither residence attribute.
    expect(result.stderr).toMatch(/no presentation \(3\)/);
    for (const id of ['p0002', 'p0003', 'p0006']) {
      expect(result.stderr).toContain(`${id}: no claim set can be satisfied`);
    }
    const records = readJsonl<PresentationRecord>(out);
    expect(records.map(r => r.prover_id)).toEqual(['p0001', 'p0004', 'p0005']);
    expect(records.every(r => r.claim_set === 0 && r.verifier_nonce?.length === 64)).toBe(true);
  });

  it('rejects credentials under another key', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'present-'));
    writeJson(join(dir, 'other.pub.json'), {...publicPart(key), key_id: 'k9'});
    writeJsonl(join(dir, 'c.jsonl'), [full]);
    const result = spawnSync(
      process.execPath,
      [cli, 'present', '--policy', join(repo, 'configs/examples/age-check.toml'),
        '--public-key', join(dir, 'other.pub.json'), '--credentials', join(dir, 'c.jsonl'), '--out', join(dir, 'o.jsonl')],
      {encoding: 'utf8'}
    );
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/not "k9"/);
  });
});
