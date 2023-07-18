import * as utils from '../helpers/utils';
import * as cred from './credential';
import { getLogger } from '../services/common';
import { CredentialEntity } from './types'

const authnData: Map<string, CredentialRequestOptions> = new Map();

export function initAuthentication(allowCredentials: PublicKeyCredentialDescriptor[]): CredentialRequestOptions {
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);
  const options: CredentialRequestOptions = {
    publicKey: {
      challenge: challenge,
      allowCredentials: allowCredentials,
      userVerification: 'preferred',
    }
  };
  authnData.set(utils.bufferToBase64URLString(challenge), options);
  return options;
}

export async function finishAuthentication(credential: PublicKeyCredential): Promise<CredentialEntity> {
  const { authenticatorData, signature, clientDataJSON, userHandle } = credential.response as AuthenticatorAssertionResponse;

  const decodedClientData = utils.bufferToUTF8String(clientDataJSON);
  const clientDataObj = JSON.parse(decodedClientData);
  console.log('clientData=%o', clientDataObj);
  getLogger().log('clientDataObj=' + decodedClientData);

  const { challenge, origin } = clientDataObj;
  const options = authnData.get(challenge);

  if (!options) {
    throw new Error('no credential related to the challenge');
  }

  if (!userHandle) {
    throw new Error('no user id');
  }

  const userId = utils.bufferToUTF8String(userHandle);
  console.log('userhandle=%s', userId);

  const storedCredentials = cred.getCredentials();
  const filteredCredentials = storedCredentials.filter(
    (candidateCredential) => candidateCredential.userId === userId && candidateCredential.id === credential.id
  );

  if (!filteredCredentials.length) {
    throw new Error('no stored credential matched by id=' + credential.id + ' and userId=' + userId);
  }
  const registeredCredential = filteredCredentials[0];

  if (options.publicKey) {
    if (!origin.endsWith(registeredCredential.rpId)) {
      throw new Error('rpId mismatch origin');
    }
  }

  // prepare algorithm
  const algorithm = registeredCredential.publicKeyAlgorithm;
  const getImportAlgorithm = (algorithm: number): RsaHashedImportParams | EcKeyImportParams | AlgorithmIdentifier => {
    if (algorithm === -7) { // for iOS
      return { name: 'ECDSA', namedCurve: 'P-256' };
    } else if (algorithm === -257) { // for Windows
      return { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } };
    } else {
      return 'ECDSA';
    }
  }
  const getVerifyAlgorithm = (algorithm: number): RsaPssParams | EcdsaParams | AlgorithmIdentifier => {
    if (algorithm === -7) { // for iOS
      return { name: 'ECDSA', hash: { name: 'SHA-256' } };
    } else if (algorithm === -257) { // for Windows
      return { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } };
    } else {
      return 'ECDSA';
    }
  }

  // prepare signature base
  const hashedClientData = await crypto.subtle.digest('SHA-256', clientDataJSON);
  const signatureBase = utils.concat([new Uint8Array(authenticatorData), new Uint8Array(hashedClientData)]);

  // prepare public key
  // const publicKeyDer = utils.base64URLStringToBuffer(registeredCredential.publicKey);
  // const publicKey = await crypto.subtle.importKey(
  //   'spki',
  //   publicKeyDer,
  //   getImportAlgorithm(algorithm),
  //   true,
  //   ['verify']
  // );
  const publicKeyJwk = registeredCredential.publicKeyJwk;
  getLogger().log('publicKeyJwk=' + JSON.stringify(publicKeyJwk));
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    publicKeyJwk,
    getImportAlgorithm(algorithm),
    false,
    ['verify']
  );

  // verify signature
  const valid = await crypto.subtle.verify(
    getVerifyAlgorithm(algorithm),
    publicKey,
    signature,
    signatureBase
  );

  if (!valid) {
    throw new Error('Invalid signature');
  }

  return registeredCredential;
}