import {CREDENTIALS_V2_URL, PID_CONTEXT_URL, PID_CREDENTIAL_TYPE} from './contexts.ts';
import type {Credential, Scalar} from './types.ts';

/**
 * The credential template: a VC Data Model 2.0 credential of type
 * PidCredential whose subject carries the attributes. The subject has no id,
 * so it is a blank node, as is the credential itself.
 */
export function pidCredential(issuer: string, subject: Record<string, Scalar>): Credential {
  return {
    '@context': [CREDENTIALS_V2_URL, PID_CONTEXT_URL],
    type: ['VerifiableCredential', PID_CREDENTIAL_TYPE],
    issuer,
    credentialSubject: {...subject}
  };
}
