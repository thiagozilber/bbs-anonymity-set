import {spawnSync} from 'node:child_process';
import {mkdtempSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {beforeAll, describe, expect, it} from 'vitest';
import {
  documentLoaderFor,
  generateIssuerKey,
  pidCredential,
  publicPart,
  signCredential,
  writeJson,
  writeJsonl,
  type CredentialRecord,
  type DocumentLoader,
  type IssuerKeyFile
} from '@bbs-anonymity-set/common';
import {checkCredential} from '../src/check.ts';

const cli = join(import.meta.dirname, '../src/cli.ts');
let key: IssuerKeyFile;
let loader: DocumentLoader;
let good: CredentialRecord;

beforeAll(async () => {
  key = await generateIssuerKey({keyId: 'k0', keyMaterial: new Uint8Array(32).fill(3)});
  loader = await documentLoaderFor([publicPart(key)]);
  const credential = await signCredential({
    key,
    credential: pidCredential(key.controller, {birth_date: '1994-03-12', age_over_18: true, issuing_country: 'BR'}),
    mandatoryPointers: ['/issuer', '/credentialSubject/issuing_country'],
    documentLoader: loader
  });
  good = {prover_id: 'p0001', key_id: 'k0', credential};
});

describe('checkCredential', () => {
  it('accepts a valid credential', async () => {
    expect(await checkCredential(publicPart(key), good, loader)).toMatchObject({ok: true});
  });

  it('rejects a changed message, a changed header and a dropped message', async () => {
    const changed = structuredClone(good);
    changed.credential.credentialSubject['birth_date'] = '2010-01-01';
    const header = structuredClone(good);
    header.credential.credentialSubject['issuing_country'] = 'DE';
    const dropped = structuredClone(good);
    delete dropped.credential.credentialSubject['age_over_18'];
    for (const r of [changed, header, dropped]) {
      expect(await checkCredential(publicPart(key), r, loader)).toMatchObject({ok: false});
    }
  });

  it('rejects another key id', async () => {
    const other = {...publicPart(key), key_id: 'k1'};
    expect(await checkCredential(other, good, loader)).toMatchObject({ok: false, reason: expect.stringMatching(/k1/)});
  });
});

describe('prover CLI', () => {
  it('lists failures by prover id and exits non-zero', () => {
    const dir = mkdtempSync(join(tmpdir(), 'prover-'));
    const bad = structuredClone(good);
    bad.prover_id = 'p0002';
    bad.credential.credentialSubject['birth_date'] = '2010-01-01';
    writeJson(join(dir, 'k0.pub.json'), publicPart(key));
    writeJsonl(join(dir, 'ok.jsonl'), [good]);
    writeJsonl(join(dir, 'mixed.jsonl'), [good, bad]);
    const run = (file: string) =>
      spawnSync(process.execPath, [cli, 'check', '--public-key', join(dir, 'k0.pub.json'), '--credentials', join(dir, file)], {encoding: 'utf8'});
    expect(run('ok.jsonl').status).toBe(0);
    const mixed = run('mixed.jsonl');
    expect(mixed.status).toBe(1);
    expect(mixed.stderr).toMatch(/invalid {2}p0002/);
    expect(mixed.stderr).not.toMatch(/invalid {2}p0001/);
  });
});
