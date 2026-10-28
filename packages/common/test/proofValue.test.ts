// Validation of derived proof values. Malformed values are built by
// re-encoding the fields of a real derived proof with one field changed.

import * as base64url from 'base64url-universal';
import * as cborg from 'cborg';
import {beforeAll, describe, expect, it} from 'vitest';
import {
  deriveCredential,
  documentLoaderFor,
  generateIssuerKey,
  parseDerivedProofValue,
  pidCredential,
  publicPart,
  signCredential,
  type DerivedProofValue,
  type SignedCredential
} from '../src/index.ts';

const DERIVED_PREFIX = Uint8Array.of(0xd9, 0x5d, 0x03);
const BASE_PREFIX = Uint8Array.of(0xd9, 0x5d, 0x02);

function encode(items: unknown[], prefix = DERIVED_PREFIX, options: object = {}): string {
  const cbor = cborg.encode(items, options);
  const bytes = new Uint8Array(prefix.length + cbor.length);
  bytes.set(prefix, 0);
  bytes.set(cbor, prefix.length);
  return 'u' + base64url.encode(bytes);
}

let derived: SignedCredential;
let valid: DerivedProofValue;
let fields: unknown[];

/** The five CBOR fields of the valid proof, with field `i` replaced. */
const withField = (i: number, value: unknown) => {
  const copy = [...fields];
  copy[i] = value;
  return encode(copy);
};

beforeAll(async () => {
  const key = await generateIssuerKey({keyId: 'k', keyMaterial: new Uint8Array(32).fill(5)});
  const loader = await documentLoaderFor([publicPart(key)]);
  const signed = await signCredential({
    key,
    credential: pidCredential(key.controller, {
      family_name: 'Almeida',
      birth_date: '1994-03-12',
      age_over_18: true,
      issuing_country: 'BR'
    }),
    mandatoryPointers: ['/issuer', '/credentialSubject/issuing_country'],
    documentLoader: loader
  });
  derived = await deriveCredential({
    credential: signed,
    selectivePointers: ['/credentialSubject/age_over_18'],
    presentationHeader: Uint8Array.of(1, 2, 3),
    documentLoader: loader
  });
  valid = parseDerivedProofValue(derived.proof.proofValue);
  fields = [
    valid.bbsProof,
    valid.compressedLabelMap,
    valid.mandatoryIndexes,
    valid.selectiveIndexes,
    valid.presentationHeader
  ];
});

describe('parseDerivedProofValue', () => {
  it('parses a library-derived proof', () => {
    // L = 3 (family_name, birth_date, age_over_18), one disclosed.
    expect(valid.undisclosedCount).toBe(2);
    expect(valid.bbsProof.length).toBe(272 + 32 * 2);
    expect(valid.selectiveIndexes).toHaveLength(1);
    expect(valid.compressedLabelMap.size).toBe(2);
    expect([...valid.presentationHeader]).toEqual([1, 2, 3]);
    expect(valid.mandatoryIndexes.length).toBeGreaterThan(0);
  });

  it('round-trips through re-encoding', () => {
    expect(parseDerivedProofValue(encode(fields))).toEqual(valid);
  });

  it('accepts byte strings encoded as CBOR tag 64', () => {
    const tagged = encode(fields, DERIVED_PREFIX, {
      typeEncoders: {
        Uint8Array: (bytes: Uint8Array) => [
          new cborg.Token(cborg.Type.tag, 64),
          new cborg.Token(cborg.Type.bytes, bytes)
        ]
      }
    });
    expect(tagged).not.toBe(encode(fields));
    expect(parseDerivedProofValue(tagged)).toEqual(valid);
  });

  it('rejects the wrong encoding, prefix, CBOR or arity', () => {
    expect(() => parseDerivedProofValue('z' + derived.proof.proofValue.slice(1))).toThrow(/multibase/);
    expect(() => parseDerivedProofValue(encode(fields, BASE_PREFIX))).toThrow(/not a derived proof/);
    expect(() =>
      parseDerivedProofValue('u' + base64url.encode(Uint8Array.of(...DERIVED_PREFIX, 0xff, 0xff)))
    ).toThrow(/not valid CBOR/);
    expect(() => parseDerivedProofValue(encode(fields.slice(0, 4)))).toThrow(/5-element/);
    expect(() => parseDerivedProofValue(encode([...fields, 0]))).toThrow(/5-element/);
  });

  it('rejects a bbsProof that is not 272 + 32U octets', () => {
    expect(() => parseDerivedProofValue(withField(0, valid.bbsProof.subarray(1)))).toThrow(/272 \+ 32U/);
    expect(() => parseDerivedProofValue(withField(0, new Uint8Array(240)))).toThrow(/272 \+ 32U/);
    expect(() => parseDerivedProofValue(withField(0, [...valid.bbsProof]))).toThrow(/bbsProof is not a byte string/);
  });

  it('rejects a malformed label map', () => {
    expect(() => parseDerivedProofValue(withField(1, [0, 1]))).toThrow(/not a CBOR map/);
    expect(() => parseDerivedProofValue(withField(1, new Map([[-1, 0]])))).toThrow(/non-negative integers/);
    expect(() => parseDerivedProofValue(withField(1, new Map([['0', 0]])))).toThrow(/non-negative integers/);
    expect(() => parseDerivedProofValue(withField(1, new Map([[0, 1.5]])))).toThrow(/non-negative integers/);
    expect(() => parseDerivedProofValue(withField(1, new Map([[0, 1], [1, 1]])))).toThrow(/two blank nodes to b1/);
  });

  it('rejects malformed index arrays', () => {
    for (const i of [2, 3]) {
      const name = i === 2 ? 'mandatoryIndexes' : 'selectiveIndexes';
      expect(() => parseDerivedProofValue(withField(i, 0))).toThrow(name);
      expect(() => parseDerivedProofValue(withField(i, [0, -1]))).toThrow(/non-negative integers/);
      expect(() => parseDerivedProofValue(withField(i, [0, 1.5]))).toThrow(/non-negative integers/);
      expect(() => parseDerivedProofValue(withField(i, ['0']))).toThrow(/non-negative integers/);
      expect(() => parseDerivedProofValue(withField(i, [2, 1]))).toThrow(/strictly ascending/);
      expect(() => parseDerivedProofValue(withField(i, [1, 1]))).toThrow(/strictly ascending/);
    }
    expect(parseDerivedProofValue(withField(3, [])).selectiveIndexes).toEqual([]);
  });

  it('rejects a presentationHeader that is not a byte string', () => {
    expect(() => parseDerivedProofValue(withField(4, 'abc'))).toThrow(/presentationHeader/);
    expect(() => parseDerivedProofValue(withField(4, [1, 2, 3]))).toThrow(/presentationHeader/);
  });
});
