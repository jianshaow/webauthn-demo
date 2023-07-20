import * as utils from '../helpers/utils';
import * as helper from '../helpers/authData';
import * as cred from './credential';
import { getLogger } from '../services/common';
import { CredentialEntity } from '../types/entities';

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
  getLogger().log('credential.id=' + credential.id);
  getLogger().log('credential.type=' + credential.type);

  const { authenticatorData, signature, clientDataJSON, userHandle } = credential.response as AuthenticatorAssertionResponse;

  if (!userHandle) {
    throw new Error('no user id');
  }

  const { registeredCredential } = handleClientData(clientDataJSON, userHandle, credential.id);

  handleAuthData(new Uint8Array(authenticatorData));

  const hashedClientData = await crypto.subtle.digest('SHA-256', clientDataJSON);
  const signatureBase = utils.concat([new Uint8Array(authenticatorData), new Uint8Array(hashedClientData)]);

  const publicKey = await importPublicKey(registeredCredential);

  const valid = await verifySignature(registeredCredential.publicKeyAlgorithm, publicKey, signature, signatureBase);

  if (!valid) {
    throw new Error('Invalid signature');
  }

  return registeredCredential;
}

function handleClientData(clientDataJSON: ArrayBuffer, userHandle: ArrayBuffer, credentialId: string): { clientDataObj: any, registeredCredential: CredentialEntity } {
  const decodedClientData = utils.bufferToUTF8String(clientDataJSON);
  const clientDataObj = JSON.parse(decodedClientData);
  console.info('clientData=%o', clientDataObj);
  getLogger().log('clientDataObj=' + decodedClientData);

  const { challenge, origin } = clientDataObj;
  const options = authnData.get(challenge);
  authnData.delete(challenge);

  if (!options) {
    throw new Error('no credential related to the challenge');
  }

  const userId = utils.bufferToUTF8String(userHandle);
  getLogger().log('userhandle=' + userId);

  const storedCredentials = cred.getCredentials();
  const filteredCredentials = storedCredentials.filter(
    (candidateCredential) => candidateCredential.userId === userId && candidateCredential.id === credentialId
  );

  if (!filteredCredentials.length) {
    throw new Error('no stored credential matched by id=' + credentialId + ' and userId=' + userId);
  }
  const registeredCredential = filteredCredentials[0];

  if (options.publicKey) {
    if (!origin.endsWith(registeredCredential.rpId)) {
      throw new Error('rpId mismatch origin');
    }
  }

  return { clientDataObj, registeredCredential };
}

function handleAuthData(authData: Uint8Array) {
  const parsedAuthData = helper.parseAuthenticatorData(authData);
  console.info('parsedAuthData=%o', parsedAuthData);

  const { counter, flags } = parsedAuthData;
  getLogger().log('authData.counter=' + counter);
  getLogger().log('authData.flags=' + JSON.stringify(flags));
}

async function importPublicKey(registeredCredential: CredentialEntity): Promise<CryptoKey> {
  const getAlgorithm = (algorithm: number): RsaHashedImportParams | EcKeyImportParams | AlgorithmIdentifier => {
    if (algorithm === -7) { // for iOS
      return { name: 'ECDSA', namedCurve: 'P-256' };
    } else if (algorithm === -257) { // for Windows
      return { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } };
    } else {
      return 'ECDSA';
    }
  };

  const { publicKeyJwk, publicKeyAlgorithm } = registeredCredential;
  getLogger().log('publicKeyJwk=' + JSON.stringify(publicKeyJwk));

  const publicKey = await crypto.subtle.importKey(
    'jwk',
    publicKeyJwk,
    getAlgorithm(publicKeyAlgorithm),
    true,
    ['verify']
  );

  return publicKey;
}

async function verifySignature(algorithm: number, publicKey: CryptoKey, signature: ArrayBuffer, signatureBase: Uint8Array): Promise<boolean> {
  const getAlgorithm = (algorithm: number): RsaPssParams | EcdsaParams | AlgorithmIdentifier => {
    if (algorithm === -7) { // for iOS
      return { name: 'ECDSA', hash: { name: 'SHA-256' } };
    } else if (algorithm === -257) { // for Windows
      return { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } };
    } else {
      return 'ECDSA';
    }
  };

  const valid = await crypto.subtle.verify(
    getAlgorithm(algorithm),
    publicKey,
    signature,
    signatureBase
  );
  return valid;
}
