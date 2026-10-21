#!/usr/bin/env node
// Prover CLI for the anonymity-set measurement.

import {parseArgs} from 'node:util';
import {
  documentLoaderFor,
  readJson,
  readJsonl,
  type CredentialRecord,
  type PublicKeyFile
} from '@bbs-anonymity-set/common';
import {checkCredential} from './check.ts';

const USAGE = `usage:
  prover check --public-key <id.pub.json> --credentials <jsonl>
      Verifies each credential's bbs-2023 base proof against the Issuer's
      public key. Exits non-zero if any credential fails.`;

async function check(argv: string[]): Promise<void> {
  const {values} = parseArgs({
    args: argv,
    options: {'public-key': {type: 'string'}, credentials: {type: 'string'}},
    strict: true
  });
  const keyPath = values['public-key'];
  const credentialsPath = values.credentials;
  if (!keyPath || !credentialsPath) {
    throw new Error(`--public-key and --credentials are required\n${USAGE}`);
  }
  const key = readJson<PublicKeyFile>(keyPath);
  const records = readJsonl<CredentialRecord>(credentialsPath);
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

const [command, ...rest] = process.argv.slice(2);
if (command !== 'check') {
  console.error(USAGE);
  process.exit(2);
}
try {
  await check(rest);
} catch (e) {
  console.error(`error: ${(e as Error).message}`);
  process.exit(1);
}
