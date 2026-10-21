import {join} from 'node:path';
import {beforeAll, describe, expect, it} from 'vitest';
import {generateIssuerKey, type IssuerKeyFile, type PopulationRecord} from '@bbs-anonymity-set/common';
import {loadConfig, parseConfig} from '../src/config.ts';
import {Issuer} from '../src/issuer.ts';

const repo = join(import.meta.dirname, '../../..');

const config = (overrides: {fields?: unknown[]; pointers?: unknown; absent?: string} = {}) =>
  parseConfig({
    schema: {
      absent_optional: overrides.absent ?? 'omit',
      fields: overrides.fields ?? [
        {name: 'birth_date'},
        {name: 'resident_city', optional: true},
        {name: 'issuing_country'}
      ]
    },
    proof: {mandatory_pointers: overrides.pointers ?? ['/issuer', '/credentialSubject/issuing_country']}
  });

const record = (prover_id: string, attributes: PopulationRecord['attributes']): PopulationRecord => ({
  prover_id,
  attributes
});

let key: IssuerKeyFile;
beforeAll(async () => {
  key = await generateIssuerKey({keyId: 'test', keyMaterial: new Uint8Array(32).fill(9)});
});

describe('config', () => {
  it('loads the example policy', () => {
    const c = loadConfig(join(repo, 'configs/examples/pid-age.toml'));
    expect(c.schema.fields).toHaveLength(8);
    expect(c.proof.mandatoryPointers).toEqual(['/issuer', '/credentialSubject/issuing_country']);
  });

  it('rejects pad, unknown terms, duplicates and unknown keys', () => {
    expect(() => config({absent: 'pad'})).toThrow(/not implemented/);
    expect(() => config({fields: [{name: 'shoe_size'}]})).toThrow(/not a term/);
    expect(() => config({fields: [{name: 'birth_date'}, {name: 'birth_date'}]})).toThrow(/twice/);
    expect(() => config({fields: [{name: 'birth_date', colour: 'red'}]})).toThrow(/unknown key/);
  });

  it('rejects mandatory pointers to optional or unlisted fields', () => {
    expect(() => config({pointers: ['/credentialSubject/resident_city']})).toThrow(/optional/);
    expect(() => config({pointers: ['/credentialSubject/nationality']})).toThrow(/no schema field/);
    expect(() => config({pointers: ['issuer']})).toThrow(/start with/);
  });
});

describe('Issuer', () => {
  it('omits absent optional attributes', async () => {
    const issuer = await Issuer.create(config(), key);
    expect(issuer.subjectFor(record('a', {birth_date: '1990-01-01', issuing_country: 'BR'}))).toEqual({
      birth_date: '1990-01-01',
      issuing_country: 'BR'
    });
    expect(
      issuer.subjectFor(record('b', {birth_date: '1990-01-01', resident_city: null, issuing_country: 'BR'}))
    ).toEqual({birth_date: '1990-01-01', issuing_country: 'BR'});
  });

  it('omission shrinks L by one per absent attribute', async () => {
    const issuer = await Issuer.create(config(), key);
    const full = await issuer.issue(
      record('a', {birth_date: '1990-01-01', resident_city: 'POA', issuing_country: 'BR'}),
      true
    );
    const partial = await issuer.issue(record('b', {birth_date: '1990-01-01', issuing_country: 'BR'}), true);
    expect(full.inspection.messageCount - partial.inspection.messageCount).toBe(1);
    expect(full.inspection.mandatoryCount).toBe(partial.inspection.mandatoryCount);
  });

  it('rejects missing required and unknown attributes', async () => {
    const issuer = await Issuer.create(config(), key);
    expect(() => issuer.subjectFor(record('a', {birth_date: 'x'}))).toThrow(/required attribute "issuing_country"/);
    expect(() =>
      issuer.subjectFor(record('a', {birth_date: 'x', issuing_country: 'BR', shoe_size: 42}))
    ).toThrow(/not in the schema/);
  });

  it('rejects non-scalar values and duplicate prover ids', async () => {
    const issuer = await Issuer.create(config(), key);
    expect(() =>
      issuer.subjectFor(record('a', {birth_date: ['x'] as never, issuing_country: 'BR'}))
    ).toThrow(/scalars/);
    const r = record('a', {birth_date: 'x', issuing_country: 'BR'});
    await expect(issuer.issueAll([r, r], false)).rejects.toThrow(/more than once/);
  });

  it('records the prover id outside the signed credential', async () => {
    const issuer = await Issuer.create(config(), key);
    const {record: c} = await issuer.issue(record('p0042', {birth_date: '1990-01-01', issuing_country: 'BR'}), false);
    expect(c.prover_id).toBe('p0042');
    expect(JSON.stringify(c.credential)).not.toContain('p0042');
  });
});
