#!/usr/bin/env node
// Issuer CLI for the anonymity-set measurement.

import {existsSync, mkdirSync} from 'node:fs';
import {dirname, join} from 'node:path';
import {parseArgs} from 'node:util';
import {
  fromHex,
  generateIssuerKey,
  publicPart,
  readJson,
  readJsonl,
  writeJson,
  writeJsonPrivate,
  writeJsonl,
  type IssuerKeyFile,
  type PopulationRecord
} from '@bbs-anonymity-set/common';
import {loadConfig} from './config.ts';
import {Issuer, summarize} from './issuer.ts';

const USAGE = `usage:
  issuer keygen --key-id <id> --out-dir <dir> [--seed <hex, >= 32 octets>] [--controller <url>] [--force]
      Writes <id>.key.json (secret, mode 0600) and <id>.pub.json.
  issuer issue --config <toml> --key <id.key.json> --population <jsonl> --out <jsonl> [--no-verify]
      Issues one bbs-2023 credential per population record.`;

async function keygen(argv: string[]): Promise<void> {
  const {values} = parseArgs({
    args: argv,
    options: {
      'key-id': {type: 'string'},
      'out-dir': {type: 'string'},
      seed: {type: 'string'},
      controller: {type: 'string'},
      force: {type: 'boolean', default: false}
    },
    strict: true
  });
  const keyId = required(values['key-id'], '--key-id');
  const outDir = required(values['out-dir'], '--out-dir');
  const key = await generateIssuerKey({
    keyId,
    ...(values.seed === undefined ? {} : {keyMaterial: fromHex(values.seed.trim(), '--seed')}),
    ...(values.controller === undefined ? {} : {controller: values.controller})
  });
  mkdirSync(outDir, {recursive: true});
  const secretPath = join(outDir, `${keyId}.key.json`);
  const publicPath = join(outDir, `${keyId}.pub.json`);
  for (const path of [secretPath, publicPath]) {
    if (existsSync(path) && !values.force) {
      throw new Error(`${path} exists; pass --force to overwrite`);
    }
  }
  writeJsonPrivate(secretPath, key);
  writeJson(publicPath, publicPart(key));
  console.error(`wrote ${secretPath} and ${publicPath}`);
}

async function issue(argv: string[]): Promise<void> {
  const {values} = parseArgs({
    args: argv,
    options: {
      config: {type: 'string'},
      key: {type: 'string'},
      population: {type: 'string'},
      out: {type: 'string'},
      'no-verify': {type: 'boolean', default: false}
    },
    strict: true
  });
  const config = loadConfig(required(values.config, '--config'));
  const key = readJson<IssuerKeyFile>(required(values.key, '--key'));
  const records = readJsonl<PopulationRecord>(required(values.population, '--population'));
  const out = required(values.out, '--out');
  const verify = !values['no-verify'];

  const issuer = await Issuer.create(config, key);
  const issued = await issuer.issueAll(records, verify);
  mkdirSync(dirname(out), {recursive: true});
  writeJsonl(out, issued.map(i => i.record));

  const s = summarize(issued);
  console.error(
    `issued ${s.credentials} credentials to ${out}${verify ? ' (all base proofs verified)' : ''}`
  );
  console.error(`  BBS header values (proofHash || mandatoryHash): ${s.perHeader.size}`);
  for (const [header, n] of [...s.perHeader].sort()) {
    console.error(`    ${String(n).padStart(8)}  ${header.slice(0, 16)}… ${header.slice(64, 80)}…`);
  }
  console.error('  message counts (L):');
  for (const [l, n] of [...s.perMessageCount].sort((a, b) => a[0] - b[0])) {
    console.error(`    ${String(n).padStart(8)}  L = ${l}`);
  }
  console.error('  total statement counts:');
  for (const [t, n] of [...s.perTotalStatements].sort((a, b) => a[0] - b[0])) {
    console.error(`    ${String(n).padStart(8)}  ${t}`);
  }
}

function required(value: string | undefined, flag: string): string {
  if (value === undefined || value === '') {
    throw new Error(`${flag} is required\n${USAGE}`);
  }
  return value;
}

const [command, ...rest] = process.argv.slice(2);
const commands: Record<string, (argv: string[]) => Promise<void>> = {keygen, issue};
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
