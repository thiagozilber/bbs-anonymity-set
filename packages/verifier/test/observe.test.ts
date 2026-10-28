import {spawnSync} from 'node:child_process';
import {mkdtempSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import * as base64url from 'base64url-universal';
import * as cborg from 'cborg';
import {beforeAll, describe, expect, it} from 'vitest';
import {
  documentLoaderFor,
  generateIssuerKey,
  inspectBaseProof,
  inspectDerivedProof,
  parseDerivedProofValue,
  pidCredential,
  publicPart,
  readJsonl,
  signCredential,
  toHex,
  writeJson,
  writeJsonl,
  type AnsweredPresentation,
  type BaseProofInspection,
  type CredentialRecord,
  type DocumentLoader,
  type IssuerKeyFile,
  type ObservationRecord,
  type PresentationRecord
} from '@bbs-anonymity-set/common';
import {parsePolicy} from '../../prover/src/policy.ts';
import {present} from '../../prover/src/present.ts';
import {observe} from '../src/observe.ts';

const repo = join(import.meta.dirname, '../../..');
const cli = join(import.meta.dirname, '../src/cli.ts');

let key: IssuerKeyFile;
let other: IssuerKeyFile;
let loader: DocumentLoader;
let credential: CredentialRecord;
let base: BaseProofInspection;

const claim = (id: string, field: string) => ({id, path: ['credentialSubject', field]});
const ageAndCountry = parsePolicy({
  query: {claims: [claim('adult', 'age_over_18'), claim('country', 'resident_country')]},
  presentation: {count: 2, header: 'random'}
});
const birthDate = parsePolicy({query: {claims: [claim('dob', 'birth_date')]}, presentation: {header: 'nonce'}});

async function presentations(policy = ageAndCountry): Promise<AnsweredPresentation[]> {
  const out = await present(credential, policy, loader, false);
  if (!out.ok) throw new Error(out.reason);
  return out.records;
}

async function observed(input: PresentationRecord, verifierId = 'v0', l = loader) {
  const out = await observe(input, verifierId, l);
  if (!out.ok) throw new Error(out.reason);
  return out.record;
}

beforeAll(async () => {
  key = await generateIssuerKey({keyId: 'k0', keyMaterial: new Uint8Array(32).fill(6)});
  other = await generateIssuerKey({keyId: 'k1', keyMaterial: new Uint8Array(32).fill(7)});
  loader = await documentLoaderFor([publicPart(key)]);
  const signed = await signCredential({
    key,
    credential: pidCredential(key.controller, {
      family_name: 'Gomes',
      birth_date: '1999-01-17',
      age_over_18: true,
      resident_country: 'PT',
      resident_city: 'Porto',
      issuing_country: 'PT'
    }),
    mandatoryPointers: ['/issuer', '/credentialSubject/issuing_country'],
    documentLoader: loader
  });
  credential = {prover_id: 'p1', key_id: 'k0', credential: signed};
  base = await inspectBaseProof(signed, loader);
});

describe('inspectDerivedProof', () => {
  it('recomputes the header and counts the Issuer signed over', async () => {
    const [p] = await presentations();
    const i = await inspectDerivedProof(p!.presentation, loader);
    expect(toHex(i.header)).toBe(toHex(base.header));
    expect(i.mandatoryCount).toBe(base.mandatoryCount);
    expect(i.messageCount).toBe(base.messageCount);
    expect(i.totalStatements).toBe(base.totalStatements);
    expect(i.disclosedCount).toBe(2);
    expect(i.revealedStatements).toBe(base.mandatoryCount + 2);
  });

  it('gives a different header when a mandatory statement is changed', async () => {
    const [p] = await presentations();
    const tampered = structuredClone(p!.presentation);
    tampered.credentialSubject['issuing_country'] = 'BR';
    const i = await inspectDerivedProof(tampered, loader);
    expect(toHex(i.header)).not.toBe(toHex(base.header));
  });

  it('rejects mandatory indexes past the revealed statements', async () => {
    const [p] = await presentations();
    const v = parseDerivedProofValue(p!.presentation.proof.proofValue);
    const fields = [v.bbsProof, v.compressedLabelMap, [...v.mandatoryIndexes, 99], v.selectiveIndexes, v.presentationHeader];
    const cbor = cborg.encode(fields);
    const tampered = structuredClone(p!.presentation);
    tampered.proof.proofValue = 'u' + base64url.encode(Uint8Array.of(0xd9, 0x5d, 0x03, ...cbor));
    await expect(inspectDerivedProof(tampered, loader)).rejects.toThrow(/past the revealed/);
  });
});

describe('observe', () => {
  it('records every channel of a verified presentation', async () => {
    const [p] = await presentations();
    const r = await observed(p!, 'rp1');
    expect(r).toMatchObject({verifier_id: 'rp1', answered: true});
    expect(r.truth).toEqual({prover_id: 'p1', key_id: 'k0', presentation_index: 0, claim_set: null});
    const o = r.observation!;
    expect(o.header).toBe(toHex(base.header));
    expect(o.l).toBe(base.messageCount);
    expect(o.total_statements).toBe(base.totalStatements);
    expect(o.u + o.disclosed_count).toBe(o.l);
    expect(o.proof_length).toBe(272 + 32 * o.u);
    expect(o.selective_indexes).toHaveLength(2);
    expect(o.presentation_header).toHaveLength(64);
    expect(o.label_map.map(([c]) => c)).toEqual([...o.label_map.map(([c]) => c)].sort((a, b) => a - b));
    expect(o.disclosed).toEqual({issuing_country: 'PT', age_over_18: true, resident_country: 'PT'});
    expect(o.issuer).toBe(key.controller);
    expect(o.verification_method).toBe(key.verification_method);
  });

  it('passes non-answers through without an observation', async () => {
    const r = await observed({
      prover_id: 'p9',
      key_id: 'k0',
      presentation_index: 1,
      claim_set: null,
      presentation: null,
      reason: 'claims not present: city'
    });
    expect(r).toEqual({
      verifier_id: 'v0',
      answered: false,
      observation: null,
      truth: {prover_id: 'p9', key_id: 'k0', presentation_index: 1, claim_set: null, reason: 'claims not present: city'}
    });
  });

  it('rejects tampered values, a wrong nonce and an untrusted key', async () => {
    const [p] = await presentations();
    const tampered = structuredClone(p!);
    tampered.presentation.credentialSubject['resident_country'] = 'BR';
    expect(await observe(tampered, 'v0', loader)).toMatchObject({ok: false});

    const [n] = await presentations(birthDate);
    expect(await observe(n!, 'v0', loader)).toMatchObject({ok: true});
    expect(await observe({...n!, verifier_nonce: '00'.repeat(32)}, 'v0', loader)).toMatchObject({ok: false});

    const otherLoader = await documentLoaderFor([publicPart(other)]);
    expect(await observe(p!, 'v0', otherLoader)).toMatchObject({ok: false});
  });

  it('sees the same constants in every presentation for the same request', async () => {
    const [a, b] = await Promise.all((await presentations()).map(p => observed(p)));
    for (const field of ['header', 'label_map', 'revealed_nquads', 'selective_indexes', 'mandatory_indexes', 'u', 'total_statements'] as const) {
      expect(b!.observation![field]).toEqual(a!.observation![field]);
    }
    expect(b!.observation!.presentation_header).not.toBe(a!.observation!.presentation_header);
  });

  it('two Verifiers asking for different claims share the credential constants', async () => {
    const [a] = await presentations();
    const [b] = await presentations(birthDate);
    const [rp1, rp2] = [await observed(a!, 'rp1'), await observed(b!, 'rp2')];
    const [o1, o2] = [rp1.observation!, rp2.observation!];
    // The credential -> subject link, with the shuffled labels of both nodes.
    const link = (nquads: string[]) =>
      nquads.find(q => q.includes('<https://www.w3.org/2018/credentials#credentialSubject>'));
    // What colluding Verifiers can join on.
    expect(o2.header).toBe(o1.header);
    expect(link(o1.revealed_nquads)).toBeDefined();
    expect(link(o2.revealed_nquads)).toBe(link(o1.revealed_nquads));
    expect(o2.mandatory_indexes.length).toBe(o1.mandatory_indexes.length);
    expect(o2.total_statements).toBe(o1.total_statements);
    // What differs with the request.
    expect(o2.selective_indexes).not.toEqual(o1.selective_indexes);
    expect(o2.u).not.toBe(o1.u);
  });
});

describe('verifier observe CLI', () => {
  const run = (args: string[]) => spawnSync(process.execPath, args, {encoding: 'utf8'});

  it('observes the example run, including non-answers', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'observe-'));
    const issuerCli = join(repo, 'packages/issuer/src/cli.ts');
    const proverCli = join(repo, 'packages/prover/src/cli.ts');
    expect(run([issuerCli, 'keygen', '--key-id', 'issuer-0', '--out-dir', dir]).status).toBe(0);
    expect(run([issuerCli, 'issue', '--config', join(repo, 'configs/examples/pid-age.toml'),
      '--key', join(dir, 'issuer-0.key.json'), '--population', join(repo, 'data/examples/population.jsonl'),
      '--out', join(dir, 'credentials.jsonl'), '--no-verify']).status).toBe(0);
    expect(run([proverCli, 'present', '--policy', join(repo, 'configs/examples/age-check.toml'),
      '--public-key', join(dir, 'issuer-0.pub.json'), '--credentials', join(dir, 'credentials.jsonl'),
      '--out', join(dir, 'presentations.jsonl'), '--no-verify']).status).toBe(0);

    const out = join(dir, 'observations.jsonl');
    const result = run([cli, 'observe', '--public-key', join(dir, 'issuer-0.pub.json'),
      '--presentations', join(dir, 'presentations.jsonl'), '--out', out, '--verifier-id', 'rp1']);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toMatch(/3 presentations, 3 non-answers/);
    const records = readJsonl<ObservationRecord>(out);
    expect(records.map(r => [r.truth.prover_id, r.answered])).toEqual([
      ['p0001', true], ['p0002', false], ['p0003', false], ['p0004', true], ['p0005', true], ['p0006', false]
    ]);
    expect(records.every(r => r.verifier_id === 'rp1')).toBe(true);
  });

  it('leaves out invalid presentations, lists them and exits non-zero', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'observe-'));
    const [good, second] = await presentations();
    const bad = structuredClone(second!);
    bad.prover_id = 'p2';
    bad.presentation.credentialSubject['age_over_18'] = false;
    writeJson(join(dir, 'k1.pub.json'), publicPart(other));
    writeJson(join(dir, 'k0.pub.json'), publicPart(key));
    writeJsonl(join(dir, 'in.jsonl'), [good, bad]);
    const out = join(dir, 'out.jsonl');
    // Two trusted keys; the presentation is under the second.
    const result = run([cli, 'observe', '--public-key', join(dir, 'k1.pub.json'), '--public-key', join(dir, 'k0.pub.json'),
      '--presentations', join(dir, 'in.jsonl'), '--out', out]);
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/invalid {2}p2#1/);
    expect(readJsonl<ObservationRecord>(out).map(r => r.truth.prover_id)).toEqual(['p1']);
  });

  it('rejects a bad verifier id and a missing key', () => {
    expect(run([cli, 'observe', '--presentations', 'x', '--out', 'y']).stderr).toMatch(/--public-key is required/);
    expect(run([cli, 'observe', '--public-key', 'k', '--presentations', 'x', '--out', 'y', '--verifier-id', 'a b']).stderr)
      .toMatch(/verifier-id/);
  });
});
