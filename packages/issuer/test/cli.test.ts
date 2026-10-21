// End-to-end: run the issuer CLI on the example config and population.

import {execFileSync, spawnSync} from 'node:child_process';
import {chmodSync, mkdtempSync, statSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {describe, expect, it} from 'vitest';
import {
  checkBaseProof,
  documentLoaderFor,
  inspectBaseProof,
  readJson,
  readJsonl,
  toHex,
  type CredentialRecord,
  type PublicKeyFile
} from '@bbs-anonymity-set/common';

const repo = join(import.meta.dirname, '../../..');
const cli = join(repo, 'packages/issuer/src/cli.ts');
const SEED = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';

const issuer = (args: string[]) => spawnSync(process.execPath, [cli, ...args], {encoding: 'utf8'});
const keygen = (dir: string, extra: string[] = []) =>
  issuer(['keygen', '--key-id', 'issuer-0', '--seed', SEED, '--out-dir', dir, ...extra]);
const scratch = () => mkdtempSync(join(tmpdir(), 'issuer-'));

describe('issuer CLI', () => {
  it('issues and verifies the example population', async () => {
    const dir = scratch();
    expect(keygen(dir).status).toBe(0);
    const out = join(dir, 'credentials.jsonl');
    execFileSync(process.execPath, [
      cli, 'issue',
      '--config', join(repo, 'configs/examples/pid-age.toml'),
      '--key', join(dir, 'issuer-0.key.json'),
      '--population', join(repo, 'data/examples/population.jsonl'),
      '--out', out
    ], {stdio: 'pipe'});

    const pub = readJson<PublicKeyFile>(join(dir, 'issuer-0.pub.json'));
    const loader = await documentLoaderFor([pub]);
    const creds = readJsonl<CredentialRecord>(out);
    expect(creds.map(c => c.prover_id)).toEqual(['p0001', 'p0002', 'p0003', 'p0004', 'p0005', 'p0006']);

    const L: Record<string, number> = {};
    const headerByCountryAndLabel = new Map<string, string>();
    const countriesByHeader = new Map<string, Set<string>>();
    for (const c of creds) {
      // Every credential verifies against the public key file alone.
      const check = await checkBaseProof(c.credential, pub, loader);
      expect(check, c.prover_id).toMatchObject({ok: true});
      const i = await inspectBaseProof(c.credential, loader);
      L[c.prover_id] = i.messageCount;
      const country = String(c.credential.credentialSubject['issuing_country']);
      const label = i.messages[0]!.split(' ')[0]!;
      const header = toHex(i.header);
      const k = `${country} ${label}`;
      expect(headerByCountryAndLabel.get(k) ?? header).toBe(header);
      headerByCountryAndLabel.set(k, header);
      countriesByHeader.set(header, (countriesByHeader.get(header) ?? new Set()).add(country));
    }
    // With absent_optional = "omit", L is the number of attributes minus the
    // mandatory issuing_country.
    expect(L).toEqual({p0001: 7, p0002: 6, p0003: 5, p0004: 7, p0005: 6, p0006: 5});
    // No header value is shared across issuing countries.
    for (const countries of countriesByHeader.values()) {
      expect(countries.size).toBe(1);
    }
  });

  it('seeded keygen is reproducible and does not overwrite', () => {
    const dir = scratch();
    expect(keygen(dir).status).toBe(0);
    const first = readJson<PublicKeyFile>(join(dir, 'issuer-0.pub.json'));
    const again = keygen(dir);
    expect(again.status).not.toBe(0);
    expect(again.stderr).toMatch(/--force/);
    expect(keygen(dir, ['--force']).status).toBe(0);
    expect(readJson<PublicKeyFile>(join(dir, 'issuer-0.pub.json'))).toEqual(first);
    expect(readJson<Record<string, unknown>>(join(dir, 'issuer-0.pub.json'))).not.toHaveProperty('secret_key');
  });

  it('secret key file is owner-only, also when overwritten', () => {
    const dir = scratch();
    const secret = join(dir, 'issuer-0.key.json');
    const mode = () => statSync(secret).mode & 0o777;
    expect(keygen(dir).status).toBe(0);
    expect(mode()).toBe(0o600);
    chmodSync(secret, 0o644);
    expect(keygen(dir, ['--force']).status).toBe(0);
    expect(mode()).toBe(0o600);
  });

  it('rejects bad key ids and short seeds', () => {
    const dir = scratch();
    expect(issuer(['keygen', '--key-id', 'a/b', '--out-dir', dir]).status).toBe(1);
    expect(issuer(['keygen', '--key-id', 'k', '--seed', 'abcd', '--out-dir', dir]).stderr).toMatch(/at least 32/);
  });
});
