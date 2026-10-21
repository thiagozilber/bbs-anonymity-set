// Known-answer tests against the draft's BLS12-381-SHA-256 fixtures. They check
// that the wrapper in src/bbs.ts calls the library the way the draft specifies.

import {readFileSync, readdirSync} from 'node:fs';
import {join} from 'node:path';
import {describe, expect, it} from 'vitest';
import * as bbs from '../src/bbs.ts';
import {fromHex, toHex} from '../src/hex.ts';

const dir = join(import.meta.dirname, 'fixtures', 'bls12-381-sha-256');
const load = (path: string): any => JSON.parse(readFileSync(join(dir, path), 'utf8'));
const files = (sub: string): string[] =>
  readdirSync(join(dir, sub))
    .filter(f => f.endsWith('.json'))
    .sort()
    .map(f => join(sub, f));

describe('draft fixtures', () => {
  it('SkToPk matches the key pair fixture', async () => {
    const {keyPair} = load('keypair.json');
    expect(toHex(await bbs.publicKeyOf(fromHex(keyPair.secretKey)))).toBe(keyPair.publicKey);
  });

  for (const file of files('signature')) {
    const f = load(file);
    it(`${file}: ${f.caseName}`, async () => {
      const args = {
        publicKey: fromHex(f.signerKeyPair.publicKey),
        header: fromHex(f.header),
        messages: f.messages.map((m: string) => fromHex(m))
      };
      expect(await bbs.verify({...args, signature: fromHex(f.signature)})).toBe(f.result.valid);
      if (f.result.valid) {
        const signature = await bbs.sign({...args, secretKey: fromHex(f.signerKeyPair.secretKey)});
        expect(toHex(signature)).toBe(f.signature);
      }
    });
  }

  for (const file of files('proof')) {
    const f = load(file);
    it(`${file}: ${f.caseName}`, async () => {
      const messages: Uint8Array[] = f.messages.map((m: string) => fromHex(m));
      const ok = await bbs.proofVerify({
        publicKey: fromHex(f.signerPublicKey),
        proof: fromHex(f.proof),
        header: fromHex(f.header),
        presentationHeader: fromHex(f.presentationHeader),
        disclosedMessages: f.disclosedIndexes.map((i: number) => messages[i]),
        disclosedIndexes: f.disclosedIndexes
      });
      expect(ok).toBe(f.result.valid);
    });
  }
});

describe('wrapper', () => {
  it('proof size is 272 + 32U', async () => {
    const kp = await bbs.keygen(new Uint8Array(32).fill(7));
    const header = new TextEncoder().encode('h');
    const messages = ['a', 'b', 'c', 'd'].map(m => new TextEncoder().encode(m));
    const signature = await bbs.sign({...kp, header, messages});
    const proof = await bbs.proofGen({
      publicKey: kp.publicKey,
      signature,
      header,
      messages,
      presentationHeader: new Uint8Array(),
      disclosedIndexes: [1]
    });
    expect(proof.length).toBe(272 + 32 * 3);
    expect(bbs.undisclosedCount(proof)).toBe(3);
  });

  it('keygen is reproducible from key material and rejects short material', async () => {
    const a = await bbs.keygen(new Uint8Array(32).fill(1));
    const b = await bbs.keygen(new Uint8Array(32).fill(1));
    expect(toHex(a.publicKey)).toBe(toHex(b.publicKey));
    await expect(bbs.keygen(new Uint8Array(31))).rejects.toThrow(/at least 32/);
  });
});
