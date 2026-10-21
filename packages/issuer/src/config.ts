// Issuer deployment policy, read from a TOML file.
//
// Everything a sweep varies on the Issuer side lives here, so each point in a
// sweep is one config file.

import {readFileSync} from 'node:fs';
import {isPidTerm, PID_TERMS} from '@bbs-anonymity-set/common';
import {parse} from 'smol-toml';

export interface FieldConfig {
  name: string;
  optional: boolean;
}

export interface IssuerConfig {
  schema: {
    /**
     * What to do when a Prover lacks an optional attribute. Only "omit" exists
     * under bbs-2023: the statement is left out, so L shrinks by one.
     */
    absentOptional: 'omit';
    /**
     * Attributes a credential may carry. Under bbs-2023 the order here does
     * not set message indexes; the canonical N-Quad order does.
     */
    fields: FieldConfig[];
  };
  proof: {
    /**
     * JSON Pointers into the credential for statements that are always
     * disclosed. Their N-Quads are hashed into the BBS header instead of
     * being BBS messages.
     */
    mandatoryPointers: string[];
  };
}

export function loadConfig(path: string): IssuerConfig {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    throw new Error(`reading ${path}: ${(e as Error).message}`);
  }
  try {
    return parseConfig(parse(text));
  } catch (e) {
    throw new Error(`${path}: ${(e as Error).message}`);
  }
}

/** Validates a parsed TOML document. Unknown keys are errors. */
export function parseConfig(raw: unknown): IssuerConfig {
  const top = table(raw, 'config', ['schema', 'proof']);
  const schema = table(top['schema'], 'schema', ['absent_optional', 'fields']);
  const proof = table(top['proof'], 'proof', ['mandatory_pointers']);

  const absent = schema['absent_optional'];
  if (absent === 'pad') {
    throw new Error(
      'schema.absent_optional = "pad" is not implemented under bbs-2023 yet (see CLAUDE.md, open items)'
    );
  }
  if (absent !== 'omit') {
    throw new Error('schema.absent_optional must be "omit"');
  }

  if (!Array.isArray(schema['fields']) || schema['fields'].length === 0) {
    throw new Error('schema.fields must be a non-empty array of tables');
  }
  const seen = new Set<string>();
  const fields = schema['fields'].map((f, i): FieldConfig => {
    const t = table(f, `schema.fields[${i}]`, ['name', 'optional']);
    const name = t['name'];
    if (typeof name !== 'string') {
      throw new Error(`schema.fields[${i}].name must be a string`);
    }
    if (!isPidTerm(name)) {
      throw new Error(
        `schema field ${JSON.stringify(name)} is not a term of the PID context (${Object.keys(PID_TERMS).join(', ')})`
      );
    }
    if (seen.has(name)) {
      throw new Error(`schema field ${JSON.stringify(name)} is listed twice`);
    }
    seen.add(name);
    const optional = t['optional'] ?? false;
    if (typeof optional !== 'boolean') {
      throw new Error(`schema.fields[${i}].optional must be a boolean`);
    }
    return {name, optional};
  });

  const pointers = proof['mandatory_pointers'];
  if (!Array.isArray(pointers) || !pointers.every(p => typeof p === 'string')) {
    throw new Error('proof.mandatory_pointers must be an array of strings');
  }
  for (const p of pointers) {
    validatePointer(p, fields);
  }

  return {
    schema: {absentOptional: 'omit', fields},
    proof: {mandatoryPointers: pointers}
  };
}

/**
 * A mandatory pointer must exist in every credential, so one into the subject
 * must name a required field.
 */
function validatePointer(pointer: string, fields: FieldConfig[]): void {
  if (!pointer.startsWith('/')) {
    throw new Error(`mandatory pointer ${JSON.stringify(pointer)} must start with "/"`);
  }
  const parts = pointer.split('/').slice(1);
  if (parts[0] === 'credentialSubject' && parts.length > 1) {
    const field = fields.find(f => f.name === parts[1]);
    if (field === undefined) {
      throw new Error(`mandatory pointer ${pointer} names no schema field`);
    }
    if (field.optional) {
      throw new Error(`mandatory pointer ${pointer} names an optional field, which some credentials lack`);
    }
  }
}

function table(value: unknown, where: string, keys: string[]): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${where} must be a table`);
  }
  for (const k of Object.keys(value)) {
    if (!keys.includes(k)) {
      throw new Error(`${where}: unknown key ${JSON.stringify(k)}`);
    }
  }
  return value as Record<string, unknown>;
}
