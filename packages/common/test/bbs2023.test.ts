// Tests of the bbs-2023 wrapper: issuing, the base-proof check, and its
// agreement with the library's own derive and verify.

import {beforeAll, describe, expect, it} from 'vitest';
import {
  checkBaseProof,
  deriveCredential,
  documentLoaderFor,
  generateIssuerKey,
  inspectBaseProof,
  parseDerivedProofValue,
  pidCredential,
  publicPart,
  signCredential,
  toHex,
  verifyDerivedCredential,
  type DocumentLoader,
  type IssuerKeyFile,
  type SignedCredential
} from '../src/index.ts';
import {undisclosedCount} from '../src/bbs.ts';

const ANA = {
  family_name: 'Almeida',
  given_name: 'Ana',
  birth_date: '1994-03-12',
  age_over_18: true,
  nationality: 'BR',
  resident_country: 'BR',
  resident_city: 'Porto Alegre',
  issuing_country: 'BR'
};
const MANDATORY = ['/issuer', '/credentialSubject/issuing_country'];

let key: IssuerKeyFile;
let other: IssuerKeyFile;
let loader: DocumentLoader;
let signed: SignedCredential;

const issue = (subject: Record<string, string | boolean>, mandatoryPointers = MANDATORY) =>
  signCredential({
    key,
    credential: pidCredential(key.controller, subject),
    mandatoryPointers,
    documentLoader: loader
  });

beforeAll(async () => {
  key = await generateIssuerKey({keyId: 'issuer-0', keyMaterial: new Uint8Array(32).fill(1)});
  other = await generateIssuerKey({keyId: 'issuer-1', keyMaterial: new Uint8Array(32).fill(2)});
  loader = await documentLoaderFor([publicPart(key), publicPart(other)]);
  signed = await issue(ANA);
});

describe('signCredential', () => {
  it('produces a bbs-2023 base proof under the key', () => {
    expect(signed.proof.cryptosuite).toBe('bbs-2023');
    expect(signed.proof.verificationMethod).toBe(key.verification_method);
    expect(signed.proof.proofValue.startsWith('u')).toBe(true);
    // The library removes `created` from base proofs.
    expect(signed.proof['created']).toBeUndefined();
  });

  it('splits statements into mandatory and BBS messages', async () => {
    const i = await inspectBaseProof(signed, loader);
    expect(i.mandatoryPointers).toEqual(MANDATORY);
    // 8 subject attributes, plus 2 type statements and the issuer and
    // credentialSubject links on the credential node.
    expect(i.totalStatements).toBe(12);
    expect(i.messageCount).toBe(7);
    expect(i.mandatoryCount).toBe(5);
    expect(toHex(i.header)).toBe(toHex(i.storedHeader));
    expect(i.header.length).toBe(64);
  });
});

describe('checkBaseProof', () => {
  it('accepts an untouched credential', async () => {
    const r = await checkBaseProof(signed, publicPart(key), loader);
    expect(r).toMatchObject({ok: true});
  });

  it('rejects a changed BBS message', async () => {
    const c = structuredClone(signed);
    c.credentialSubject['birth_date'] = '2010-01-01';
    expect(await checkBaseProof(c, publicPart(key), loader)).toMatchObject({
      ok: false,
      reason: 'BBS signature does not verify'
    });
  });

  it('rejects a changed mandatory statement (header)', async () => {
    const c = structuredClone(signed);
    c.credentialSubject['issuing_country'] = 'DE';
    expect(await checkBaseProof(c, publicPart(key), loader)).toMatchObject({
      ok: false,
      reason: expect.stringMatching(/header/)
    });
  });

  it('rejects a dropped statement (message count)', async () => {
    const c = structuredClone(signed);
    delete c.credentialSubject['resident_city'];
    expect(await checkBaseProof(c, publicPart(key), loader)).toMatchObject({ok: false});
  });

  it('rejects an added statement (message count)', async () => {
    const {resident_city: _drop, ...noCity} = ANA;
    const grown = structuredClone(await issue(noCity));
    grown.credentialSubject['resident_city'] = 'Porto Alegre';
    expect(await checkBaseProof(grown, publicPart(key), loader)).toMatchObject({ok: false});
  });

  it('rejects a changed proof option (header)', async () => {
    const c = structuredClone(signed);
    c.proof['created'] = '2026-10-20T00:00:00Z';
    expect(await checkBaseProof(c, publicPart(key), loader)).toMatchObject({ok: false});
  });

  it('rejects another key', async () => {
    expect(await checkBaseProof(signed, publicPart(other), loader)).toMatchObject({ok: false});
    const c = structuredClone(signed);
    c.proof.verificationMethod = other.verification_method;
    c.issuer = other.controller;
    expect(await checkBaseProof(c, publicPart(other), loader)).toMatchObject({
      ok: false,
      reason: 'proof value carries a different public key'
    });
  });

  it('agrees with the library on derive and verify', async () => {
    const derived = await deriveCredential({
      credential: signed,
      selectivePointers: ['/credentialSubject/age_over_18'],
      documentLoader: loader
    });
    expect(derived.credentialSubject).toEqual({issuing_country: 'BR', age_over_18: true});
    expect(await verifyDerivedCredential(derived, loader)).toEqual({verified: true});

    // U = L minus the disclosed messages.
    const p = parseDerivedProofValue(derived.proof.proofValue);
    expect(p.selectiveIndexes).toHaveLength(1);
    expect(undisclosedCount(p.bbsProof)).toBe(6);

    const tampered = structuredClone(derived);
    tampered.credentialSubject['age_over_18'] = false;
    expect((await verifyDerivedCredential(tampered, loader)).verified).toBe(false);
  });
});

describe('binding channels', () => {
  // The subject's blank node label after the HMAC shuffle (b0 or b1 here, as
  // the credential and its subject are the only two blank nodes).
  const subjectLabel = (messages: string[]) => messages[0]!.split(' ')[0]!;

  it('header is fixed by proof options, mandatory statements and the label shuffle', async () => {
    const sameContent = await Promise.all(Array.from({length: 8}, () => issue(ANA)));
    const otherCountry = await issue({...ANA, issuing_country: 'PT'});
    const headerByLabel = new Map<string, string>();
    for (const c of sameContent) {
      const i = await inspectBaseProof(c, loader);
      const label = subjectLabel(i.messages);
      const header = toHex(i.header);
      // Same content and same label permutation give the same header.
      expect(headerByLabel.get(label) ?? header).toBe(header);
      headerByLabel.set(label, header);
    }
    // proofHash (first 32 octets) does not depend on the shuffle.
    const proofHashes = new Set([...headerByLabel.values()].map(h => h.slice(0, 64)));
    expect(proofHashes.size).toBe(1);
    const pt = toHex((await inspectBaseProof(otherCountry, loader)).header);
    expect([...headerByLabel.values()]).not.toContain(pt);
  });

  it('HMAC key is fresh per credential, so issuance is not deterministic', async () => {
    const again = await issue(ANA);
    expect(again.proof.proofValue).not.toBe(signed.proof.proofValue);
    const [a, b] = await Promise.all([signed, again].map(x => inspectBaseProof(x, loader)));
    expect(a!.messageCount).toBe(b!.messageCount);
    expect(a!.mandatoryCount).toBe(b!.mandatoryCount);
  });

  it('a mandatory pointer to an absent attribute fails at issuance', async () => {
    const {resident_city: _drop, ...noCity} = ANA;
    await expect(issue(noCity, ['/credentialSubject/resident_city'])).rejects.toThrow();
  });
});
