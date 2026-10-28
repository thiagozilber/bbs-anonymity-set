#!/usr/bin/env node
// Prover CLI for the anonymity-set measurement.

import {mkdirSync} from 'node:fs';
import {dirname} from 'node:path';
import {parseArgs} from 'node:util';
import {
  documentLoaderFor,
  readJson,
  readJsonl,
  writeJsonl,
  type AnsweredPresentation,
  type CredentialRecord,
  type PresentationRecord,
  type PublicKeyFile
} from '@bbs-anonymity-set/common';
import {checkCredential} from './check.ts';
import {loadPolicy} from './policy.ts';
import {nonAnswers, present, summarize} from './present.ts';

const USAGE = `usage:
  prover check --public-key <id.pub.json> --credentials <jsonl>
      Verifies each credential's bbs-2023 base proof against the Issuer's
      public key. Exits non-zero if any credential fails.
  prover present --policy <toml> --public-key <id.pub.json> --credentials <jsonl> --out <jsonl> [--no-verify]
      Answers the policy's query from each credential with bbs-2023
      disclosure proofs. Provers that cannot answer get non-answer records
      and are listed; that is not an error.`;

async function check(argv: string[]): Promise<void> {
  const {values} = parseArgs({
    args: argv,
    options: {'public-key': {type: 'string'}, credentials: {type: 'string'}},
    strict: true
  });
  const key = readJson<PublicKeyFile>(required(values['public-key'], '--public-key'));
  const records = readJsonl<CredentialRecord>(required(values.credentials, '--credentials'));
  const loader = await documentLoaderFor([key]);
  let failed = 0;
  for (const record of records) {
    const result = await checkCredential(key, record, loader);
    if (!result.ok) {
      failed++;
      console.error(`  invalid  ${record.prover_id}: ${result.reason}`);
    }
  }
  console.error(
    `checked ${records.length} credentials against key ${JSON.stringify(key.key_id)}: ` +
      `${records.length - failed} valid, ${failed} invalid`
  );
  if (failed > 0) {
    throw new Error(`${failed} of ${records.length} credentials failed verification`);
  }
}

async function presentAll(argv: string[]): Promise<void> {
  const {values} = parseArgs({
    args: argv,
    options: {
      policy: {type: 'string'},
      'public-key': {type: 'string'},
      credentials: {type: 'string'},
      out: {type: 'string'},
      'no-verify': {type: 'boolean', default: false}
    },
    strict: true
  });
  const policy = loadPolicy(required(values.policy, '--policy'));
  const key = readJson<PublicKeyFile>(required(values['public-key'], '--public-key'));
  const credentials = readJsonl<CredentialRecord>(required(values.credentials, '--credentials'));
  const out = required(values.out, '--out');
  const verify = !values['no-verify'];
  const loader = await documentLoaderFor([key]);

  const records: PresentationRecord[] = [];
  const answered: AnsweredPresentation[] = [];
  const unanswered: Array<{prover_id: string; reason: string}> = [];
  for (const credential of credentials) {
    if (credential.key_id !== key.key_id) {
      throw new Error(`prover ${credential.prover_id}: credential is under key ${JSON.stringify(credential.key_id)}, not ${JSON.stringify(key.key_id)}`);
    }
    const outcome = await present(credential, policy, loader, verify);
    if (outcome.ok) {
      records.push(...outcome.records);
      answered.push(...outcome.records);
    } else {
      records.push(...nonAnswers(credential, policy, outcome.reason));
      unanswered.push({prover_id: credential.prover_id, reason: outcome.reason});
    }
  }
  mkdirSync(dirname(out), {recursive: true});
  writeJsonl(out, records);

  const s = summarize(credentials.length, answered, unanswered);
  console.error(
    `wrote ${s.presentations} presentations from ${s.credentials - s.unanswered.length} of ${s.credentials} ` +
      `credentials${verify ? ' (all verified)' : ''} and ${records.length - s.presentations} non-answers to ${out}`
  );
  if (s.unanswered.length > 0) {
    console.error(`  no presentation (${s.unanswered.length}):`);
    for (const u of s.unanswered) {
      console.error(`    ${u.prover_id}: ${u.reason}`);
    }
  }
  const sorted = <K>(m: Map<K, number>) =>
    [...m].sort((a, b) => (a[0] === null ? -1 : b[0] === null ? 1 : Number(a[0]) - Number(b[0])));
  console.error('  claim set presented:');
  for (const [set, n] of sorted(s.perClaimSet)) {
    console.error(`    ${String(n).padStart(8)}  ${set === null ? 'all claims (no claim_sets)' : `claim_sets[${set}]`}`);
  }
  console.error('  undisclosed messages (U):');
  for (const [u, n] of sorted(s.perU)) {
    console.error(`    ${String(n).padStart(8)}  U = ${u}`);
  }
  console.error('  disclosed messages:');
  for (const [d, n] of sorted(s.perDisclosed)) {
    console.error(`    ${String(n).padStart(8)}  ${d}`);
  }
}

function required(value: string | undefined, flag: string): string {
  if (value === undefined || value === '') {
    throw new Error(`${flag} is required\n${USAGE}`);
  }
  return value;
}

const [command, ...rest] = process.argv.slice(2);
const commands: Record<string, (argv: string[]) => Promise<void>> = {check, present: presentAll};
const run = command === undefined ? undefined : commands[command];
if (run === undefined) {
  console.error(USAGE);
  process.exit(2);
}
try {
  await run(rest);
} catch (e) {
  console.error(`error: ${(e as Error).message}`);
  process.exit(1);
}
