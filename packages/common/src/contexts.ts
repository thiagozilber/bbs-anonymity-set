// JSON-LD contexts and the offline document loader.
//
// Nothing is fetched over the network: every context and key document the
// harness needs is served from memory, and any other URL is an error.

import * as credentialsContext from '@digitalbazaar/credentials-context';
import * as multikeyContext from '@digitalbazaar/multikey-context';
import * as securityContext from '@digitalbazaar/security-context';
import type {DocumentLoader} from '@digitalbazaar/vc';
import type {PublicKeyFile} from './types.ts';

export type {DocumentLoader};

export const CREDENTIALS_V2_URL = 'https://www.w3.org/ns/credentials/v2';

/**
 * Our context for PID-style attributes. The `.example` domain is reserved, so
 * the URLs are identifiers only and are never resolved.
 */
export const PID_CONTEXT_URL = 'https://bbs-anonymity-set.example/contexts/pid/v1';
export const PID_VOCAB = 'https://bbs-anonymity-set.example/vocab#';

/**
 * Attribute terms. Names follow the EUDI PID Rulebook (ARF Annex 3.01), except
 * `age_over_18`, which current EU-level PID versions no longer list and which
 * is taken from the German PID's national extension. The PID Rulebook defines
 * only mdoc and SD-JWT VC encodings, so this JSON-LD mapping is ours.
 */
export const PID_TERMS = {
  family_name: {},
  given_name: {},
  birth_date: {type: 'xsd:date'},
  age_over_18: {},
  nationality: {},
  resident_country: {},
  resident_city: {},
  issuing_country: {}
} as const satisfies Record<string, {type?: string}>;

export type PidTerm = keyof typeof PID_TERMS;

export function isPidTerm(name: string): name is PidTerm {
  return Object.hasOwn(PID_TERMS, name);
}

export const PID_CREDENTIAL_TYPE = 'PidCredential';

export const PID_CONTEXT = {
  '@context': {
    '@protected': true,
    xsd: 'http://www.w3.org/2001/XMLSchema#',
    [PID_CREDENTIAL_TYPE]: PID_VOCAB + PID_CREDENTIAL_TYPE,
    ...Object.fromEntries(
      Object.entries(PID_TERMS).map(([name, def]) => [
        name,
        'type' in def ? {'@id': PID_VOCAB + name, '@type': def.type} : PID_VOCAB + name
      ])
    )
  }
};

const STATIC_DOCUMENTS = new Map<string, unknown>([
  ...credentialsContext.contexts,
  ...securityContext.contexts,
  [multikeyContext.CONTEXT_URL, multikeyContext.CONTEXT],
  [PID_CONTEXT_URL, PID_CONTEXT]
]);

/** The Multikey verification method document for an Issuer key. */
export function verificationMethodDocument(key: PublicKeyFile, publicKeyMultibase: string): object {
  return {
    '@context': multikeyContext.CONTEXT_URL,
    id: key.verification_method,
    type: 'Multikey',
    controller: key.controller,
    publicKeyMultibase
  };
}

/** An Issuer's controller document, authorizing its keys for `assertionMethod`. */
export function controllerDocument(controller: string, methods: object[]): object {
  return {
    '@context': [securityContext.SECURITY_CONTEXT_V2_URL, multikeyContext.CONTEXT_URL],
    id: controller,
    assertionMethod: methods
  };
}

/**
 * A document loader that serves the static contexts plus the verification
 * method and controller documents of the given keys. Keys with the same
 * controller are listed in one controller document. Each key comes with its
 * `publicKeyMultibase`, which `multikeyOf` in bbs2023.ts computes.
 */
export function createDocumentLoader(
  keys: Array<{key: PublicKeyFile; publicKeyMultibase: string}> = []
): DocumentLoader {
  const documents = new Map(STATIC_DOCUMENTS);
  const methodsByController = new Map<string, object[]>();
  for (const {key, publicKeyMultibase} of keys) {
    const method = verificationMethodDocument(key, publicKeyMultibase);
    documents.set(key.verification_method, method);
    const methods = methodsByController.get(key.controller) ?? [];
    methods.push(method);
    methodsByController.set(key.controller, methods);
  }
  for (const [controller, methods] of methodsByController) {
    documents.set(controller, controllerDocument(controller, methods));
  }
  return async (url: string) => {
    const document = documents.get(url);
    if (document === undefined) {
      throw new Error(`offline document loader has no document for ${url}`);
    }
    return {contextUrl: null, documentUrl: url, document};
  };
}
