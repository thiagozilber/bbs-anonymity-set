import {join} from 'node:path';
import {describe, expect, it} from 'vitest';
import {loadPolicy, parsePolicy} from '../src/policy.ts';

const repo = join(import.meta.dirname, '../../..');
const claim = (id: string, field: string, extra: object = {}) => ({
  id,
  path: ['credentialSubject', field],
  ...extra
});

describe('disclosure policy', () => {
  it('loads the example policy', () => {
    const p = loadPolicy(join(repo, 'configs/examples/age-check.toml'));
    expect(p.query.claims?.map(c => c.id)).toEqual(['adult', 'country', 'city']);
    expect(p.query.claims?.[0]?.values).toEqual([true]);
    expect(p.query.claimSets).toEqual([['adult', 'country'], ['adult', 'city']]);
    expect(p.presentation).toEqual({count: 1, header: {mode: 'nonce'}});
  });

  it('defaults to mandatory-only disclosure, one presentation, empty header', () => {
    expect(parsePolicy({})).toEqual({query: {}, presentation: {count: 1, header: {mode: 'empty'}}});
  });

  it('reads a fixed presentation header', () => {
    const p = parsePolicy({presentation: {header: 'fixed', header_value: '00ff'}});
    expect(p.presentation.header).toEqual({mode: 'fixed', value: Uint8Array.of(0, 255)});
  });

  it('rejects malformed claims', () => {
    expect(() => parsePolicy({query: {claims: []}})).toThrow(/non-empty/);
    expect(() => parsePolicy({query: {claims: [claim('a b', 'x')]}})).toThrow(/\[A-Za-z0-9_-\]/);
    expect(() => parsePolicy({query: {claims: [claim('a', 'x'), claim('a', 'y')]}})).toThrow(/twice/);
    expect(() => parsePolicy({query: {claims: [{id: 'a', path: []}]}})).toThrow(/non-empty array/);
    expect(() => parsePolicy({query: {claims: [{id: 'a', path: ['x', null]}]}})).toThrow(/strings or non-negative/);
    expect(() => parsePolicy({query: {claims: [{id: 'a', path: ['x', -1]}]}})).toThrow(/strings or non-negative/);
    expect(() => parsePolicy({query: {claims: [claim('a', 'x', {values: []})]}})).toThrow(/values/);
    expect(() => parsePolicy({query: {claims: [claim('a', 'x', {values: [[1]]})]}})).toThrow(/values/);
    expect(() => parsePolicy({query: {claims: [claim('a', 'x', {colour: 1})]}})).toThrow(/unknown key/);
  });

  it('rejects malformed claim sets', () => {
    expect(() => parsePolicy({query: {claim_sets: [['a']]}})).toThrow(/requires query.claims/);
    const claims = [claim('a', 'x')];
    expect(() => parsePolicy({query: {claims, claim_sets: []}})).toThrow(/non-empty/);
    expect(() => parsePolicy({query: {claims, claim_sets: [[]]}})).toThrow(/non-empty array of claim ids/);
    expect(() => parsePolicy({query: {claims, claim_sets: [['b']]}})).toThrow(/unknown claim "b"/);
  });

  it('rejects malformed presentation settings', () => {
    expect(() => parsePolicy({presentation: {count: 0}})).toThrow(/positive integer/);
    expect(() => parsePolicy({presentation: {count: 1.5}})).toThrow(/positive integer/);
    expect(() => parsePolicy({presentation: {header: 'fixed'}})).toThrow(/header_value/);
    expect(() => parsePolicy({presentation: {header: 'fixed', header_value: 'xyz'}})).toThrow(/hex/);
    expect(() => parsePolicy({presentation: {header: 'random', header_value: '00'}})).toThrow(/only used/);
    expect(() => parsePolicy({presentation: {header: 'sometimes'}})).toThrow(/"empty", "random"/);
  });
});
