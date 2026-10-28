#!/usr/bin/env node
// Verifier observer CLI for the anonymity-set measurement.

import {mkdirSync} from 'node:fs';
import {dirname} from 'node:path';
import {parseArgs} from 'node:util';
import {
  documentLoaderFor,
  readJson,
  readJsonl,
  writeJsonl,
  type ObservationRecord,
  type PresentationRecord,
  type PublicKeyFile
} from '@bbs-anonymity-set/common';
import {observe, summarize} from './observe.ts';

const USAGE = `usage:
  verifier observe --public-key <id.pub.json> [--public-key ...] --presentations <jsonl> --out <jsonl> [--verifier-id <id>]
      Verifies each presentation against the trusted Issuer keys and records
      every channel the Verifier sees. Non-answers are passed through.
      Presentations that fail verification are listed and left out, and the
      exit status is non-zero.`;

async function observeAll(argv: string[]): Promise<void> {
  const {values} = parseArgs({
    args: argv,
    options: {
      'public-key': {type: 'string', multiple: true},
      presentations: {type: 'string'},
      out: {type: 'string'},
      'verifier-id': {type: 'string', default: 'v0'}
    },
    strict: true
  });
  const keyPaths = values['public-key'] ?? [];
  if (keyPaths.length === 0) {
    throw new Error(`--public-key is required\n${USAGE}`);
  }
  const verifierId = values['verifier-id'];
  if (!/^[A-Za-z0-9_-]+$/.test(verifierId)) {
    throw new Error('--verifier-id must use [A-Za-z0-9_-]');
  }
  const keys = keyPaths.map(p => readJson<PublicKeyFile>(p));
  const inputs = readJsonl<PresentationRecord>(required(values.presentations, '--presentations'));
  const out = required(values.out, '--out');
  const loader = await documentLoaderFor(keys);

  const records: ObservationRecord[] = [];
  const invalid: Array<{prover_id: string; presentation_index: number; reason: string}> = [];
  for (const input of inputs) {
    const outcome = await observe(input, verifierId, loader);
    if (outcome.ok) {
      records.push(outcome.record);
    } else {
      invalid.push({prover_id: input.prover_id, presentation_index: input.presentation_index, reason: outcome.reason});
    }
  }
  mkdirSync(dirname(out), {recursive: true});
  writeJsonl(out, records);

  const s = summarize(records);
  console.error(
    `verifier ${verifierId}: wrote ${s.records} observations to ${out} ` +
      `(${s.answered} presentations, ${s.nonAnswers} non-answers)`
  );
  console.error(`  distinct headers: ${s.headers}`);
  console.error(`  distinct (U, total statements, disclosed indexes, header): ${s.coreTuples}`);
  console.error('  undisclosed messages (U):');
  for (const [u, n] of [...s.perU].sort((a, b) => a[0] - b[0])) {
    console.error(`    ${String(n).padStart(8)}  U = ${u}`);
  }
  if (invalid.length > 0) {
    for (const i of invalid) {
      console.error(`  invalid  ${i.prover_id}#${i.presentation_index}: ${i.reason}`);
    }
    throw new Error(`${invalid.length} of ${inputs.length} presentations failed verification and were left out`);
  }
}

function required(value: string | undefined, flag: string): string {
  if (value === undefined || value === '') {
    throw new Error(`${flag} is required\n${USAGE}`);
  }
  return value;
}

const [command, ...rest] = process.argv.slice(2);
if (command !== 'observe') {
  console.error(USAGE);
  process.exit(2);
}
try {
  await observeAll(rest);
} catch (e) {
  console.error(`error: ${(e as Error).message}`);
  process.exit(1);
}
