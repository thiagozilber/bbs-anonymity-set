// The Prover's check of credentials it has received, before relying on them.
// Presentation generation (deriving proofs under a disclosure policy) comes
// next.

import {
  checkBaseProof,
  type BaseProofCheck,
  type CredentialRecord,
  type DocumentLoader,
  type PublicKeyFile
} from '@bbs-anonymity-set/common';

/**
 * Checks one credential against the Issuer's public key: the record names the
 * key, the proof is under it, and the draft's Verify accepts the base proof's
 * signature over the header and messages recomputed from the credential.
 */
export async function checkCredential(
  key: PublicKeyFile,
  record: CredentialRecord,
  documentLoader: DocumentLoader
): Promise<BaseProofCheck> {
  if (record.key_id !== key.key_id) {
    return {ok: false, reason: `credential is under key ${JSON.stringify(record.key_id)}, not ${JSON.stringify(key.key_id)}`};
  }
  return checkBaseProof(record.credential, key, documentLoader);
}
