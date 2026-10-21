// The Issuer: maps population records to PID credentials under a deployment
// policy and signs them with bbs-2023 base proofs.

import {
  checkBaseProof,
  documentLoaderFor,
  inspectBaseProof,
  pidCredential,
  publicPart,
  signCredential,
  toHex,
  type BaseProofInspection,
  type CredentialRecord,
  type DocumentLoader,
  type IssuerKeyFile,
  type PopulationRecord,
  type Scalar
} from '@bbs-anonymity-set/common';
import type {IssuerConfig} from './config.ts';

export interface Issued {
  record: CredentialRecord;
  inspection: BaseProofInspection;
}

export class Issuer {
  readonly config: IssuerConfig;
  readonly key: IssuerKeyFile;
  readonly documentLoader: DocumentLoader;

  private constructor(config: IssuerConfig, key: IssuerKeyFile, documentLoader: DocumentLoader) {
    this.config = config;
    this.key = key;
    this.documentLoader = documentLoader;
  }

  static async create(config: IssuerConfig, key: IssuerKeyFile): Promise<Issuer> {
    return new Issuer(config, key, await documentLoaderFor([publicPart(key)]));
  }

  /** The credentialSubject for one Prover, before signing. */
  subjectFor(record: PopulationRecord): Record<string, Scalar> {
    const fields = this.config.schema.fields;
    for (const [name, value] of Object.entries(record.attributes)) {
      if (value !== null && !fields.some(f => f.name === name)) {
        throw new Error(`prover ${record.prover_id}: attribute ${JSON.stringify(name)} is not in the schema`);
      }
    }
    const subject: Record<string, Scalar> = {};
    for (const field of fields) {
      const value = record.attributes[field.name] ?? null;
      if (value === null) {
        if (!field.optional) {
          throw new Error(`prover ${record.prover_id}: required attribute ${JSON.stringify(field.name)} is absent`);
        }
        continue; // absent_optional = "omit"
      }
      if (!['string', 'number', 'boolean'].includes(typeof value)) {
        throw new Error(
          `prover ${record.prover_id}, attribute ${JSON.stringify(field.name)}: values must be JSON scalars`
        );
      }
      subject[field.name] = value;
    }
    return subject;
  }

  /**
   * Issues one credential. The base proof is always inspected, for the
   * summary; with `verify` the draft's Verify is also run on it.
   */
  async issue(record: PopulationRecord, verify: boolean): Promise<Issued> {
    const credential = await signCredential({
      key: this.key,
      credential: pidCredential(this.key.controller, this.subjectFor(record)),
      mandatoryPointers: this.config.proof.mandatoryPointers,
      documentLoader: this.documentLoader
    }).catch((e: Error) => {
      throw new Error(`signing for prover ${record.prover_id}: ${e.message}`);
    });
    let inspection: BaseProofInspection;
    if (verify) {
      const check = await checkBaseProof(credential, publicPart(this.key), this.documentLoader);
      if (!check.ok) {
        throw new Error(`verifying the credential just issued to prover ${record.prover_id}: ${check.reason}`);
      }
      inspection = check.inspection;
    } else {
      inspection = await inspectBaseProof(credential, this.documentLoader);
    }
    return {
      record: {prover_id: record.prover_id, key_id: this.key.key_id, credential},
      inspection
    };
  }

  /** Issues a credential to every record, in order. Prover ids must be unique. */
  async issueAll(records: PopulationRecord[], verify: boolean): Promise<Issued[]> {
    const ids = new Set<string>();
    for (const r of records) {
      if (ids.has(r.prover_id)) {
        throw new Error(`prover id ${JSON.stringify(r.prover_id)} appears more than once in the population`);
      }
      ids.add(r.prover_id);
    }
    const out: Issued[] = [];
    for (const r of records) {
      out.push(await this.issue(r, verify));
    }
    return out;
  }
}

/**
 * Counts for the end-of-run summary. These are sanity checks on the issued
 * population, not the analysis.
 */
export interface IssuanceSummary {
  credentials: number;
  /** Credentials per BBS header (hex). */
  perHeader: Map<string, number>;
  /** Credentials per message count L. */
  perMessageCount: Map<number, number>;
  /** Credentials per total statement count. */
  perTotalStatements: Map<number, number>;
}

export function summarize(issued: Issued[]): IssuanceSummary {
  const s: IssuanceSummary = {
    credentials: issued.length,
    perHeader: new Map(),
    perMessageCount: new Map(),
    perTotalStatements: new Map()
  };
  const bump = <K>(m: Map<K, number>, k: K) => m.set(k, (m.get(k) ?? 0) + 1);
  for (const {inspection: i} of issued) {
    bump(s.perHeader, toHex(i.header));
    bump(s.perMessageCount, i.messageCount);
    bump(s.perTotalStatements, i.totalStatements);
  }
  return s;
}
