import * as cbor from 'cbor-x';
import * as utils from '../helpers/utils';
import * as helper from '../helpers/authData';
import * as cred from '../services/credential';
import * as types from '../types/authData';
import { getLogger } from '../services/common';
import { CredentialEntity } from '../types/entities';

const registerData: Map<string, CredentialCreationOptions> = new Map();

export function initRegistration(rpId: string, userId: string, username: string, excludeCredentials: PublicKeyCredentialDescriptor[]): CredentialCreationOptions {
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);
  const options: CredentialCreationOptions = {
    publicKey: {
      rp: {
        id: rpId,
        name: 'AA Server',
      },
      user: {
        id: new TextEncoder().encode(userId),
        name: username,
        displayName: username,
      },
      challenge: challenge,
      excludeCredentials: excludeCredentials,
      pubKeyCredParams: [
        { type: 'public-key', alg: -257 }, { type: 'public-key', alg: -7 }
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'preferred',
      },
      attestation: 'direct',
    },
  };
  registerData.set(utils.bufferToBase64URLString(challenge), options);
  return options;
}

export function finishRegistration(credential: PublicKeyCredential, rpId: string, userId: string, username: string, displayName: string): CredentialEntity {
  getLogger().log('credential.id=' + credential.id);
  getLogger().log('credential.type=' + credential.type);
  getLogger().log('credential.authenticatorAttachment=' + credential.authenticatorAttachment);

  const attestationResponse = credential.response as AuthenticatorAttestationResponse;
  const transports = attestationResponse.getTransports() as AuthenticatorTransport[];
  const publicKeyAlgorithm = attestationResponse.getPublicKeyAlgorithm();

  getLogger().log('attestation.publicKeyAlgorithm=' + publicKeyAlgorithm);
  getLogger().log('attestation.transports=' + transports);

  const pubclicKey = attestationResponse.getPublicKey();

  if (!pubclicKey) {
    throw new Error('no public key');
  }
  const publicKeyDer = utils.bufferToBase64URLString(pubclicKey);

  const { clientDataJSON, attestationObject } = attestationResponse;

  handleClientData(clientDataJSON, rpId, userId);

  const attestationObj = cbor.decode(new Uint8Array(attestationObject));
  console.info('attestation=%o', attestationObj);

  const { fmt, attStmt, authData } = attestationObj;

  handleAttStmt(fmt, attStmt);

  const { publicKeyJwk, coseKeyAlg } = handleAuthData(authData);

  const credentialToBeStored: CredentialEntity = {
    id: credential.id,
    type: credential.type as PublicKeyCredentialType,
    userId: userId,
    username: username,
    displayName: displayName,
    rpId: rpId,
    transports: transports,
    publicKeyDer: publicKeyDer,
    publicKeyJwk: publicKeyJwk,
    publicKeyAlgorithm: coseKeyAlg as number,
  };

  cred.saveCredential(credentialToBeStored);

  return credentialToBeStored;
}

function handleAuthData(authData: Uint8Array): { publicKeyJwk: any, coseKeyAlg: number } {
  const parsedAuthData = helper.parseAuthenticatorData(authData);
  console.info('parsedAuthData=%o', parsedAuthData);

  const { aaguid, counter, flags, credentialPublicKey } = parsedAuthData;
  getLogger().log('authData.aaguid=' + aaguid);
  getLogger().log('authData.counter=' + counter);
  getLogger().log('authData.flags=' + JSON.stringify(flags));

  if (!credentialPublicKey) {
    throw new Error('no public key');
  }

  const publicKeyCose = helper.decodeFirst<types.COSEPublicKey>(credentialPublicKey);
  console.info('publicKeyCose=%o', publicKeyCose);
  const coseKty = publicKeyCose.get(types.COSEKEYS.kty);
  const coseKeyAlg = publicKeyCose.get(types.COSEKEYS.alg);

  if (!coseKty || !coseKeyAlg) {
    throw new Error('no COSE kty or COSE keyAlg');
  }

  let publicKeyJwk;
  if (coseKty === types.COSEKTY.EC2) {
    const ecPublicKeyCose = publicKeyCose as types.COSEPublicKeyEC2;
    const coseCrv = ecPublicKeyCose.get(types.COSEKEYS.crv);
    const coseX = ecPublicKeyCose.get(types.COSEKEYS.x);
    const coseY = ecPublicKeyCose.get(types.COSEKEYS.y);

    if (!coseCrv || !coseX || !coseY) {
      throw new Error('no ec key info');
    }
    publicKeyJwk = {
      kty: 'EC',
      crv: helper.toCrvString(coseCrv),
      x: utils.bufferToBase64URLString(coseX),
      y: utils.bufferToBase64URLString(coseY)
    };
  } else if (coseKty === types.COSEKTY.RSA) {
    const rsaPublicKeyCose = publicKeyCose as types.COSEPublicKeyRSA;
    const coseN = rsaPublicKeyCose.get(types.COSEKEYS.n);
    const coseE = rsaPublicKeyCose.get(types.COSEKEYS.e);
    if (!coseN || !coseE) {
      throw new Error('no ec key info');
    }
    publicKeyJwk = {
      kty: 'RSA',
      alg: 'RS256',
      n: utils.bufferToBase64URLString(coseN),
      e: utils.bufferToBase64URLString(coseE)
    };
  }
  return { publicKeyJwk, coseKeyAlg };
}

function handleClientData(clientDataJSON: ArrayBuffer, rpId: string, userId: string): any {
  const decodedClientData = utils.bufferToUTF8String(clientDataJSON);
  const clientDataObj = JSON.parse(decodedClientData);
  getLogger().log('clientDataObj=' + decodedClientData);

  const { challenge } = clientDataObj;
  const options = registerData.get(challenge);
  registerData.delete(challenge);
  if (!options) {
    throw new Error('no credential related to the challenge');
  }
  if (options.publicKey) {
    const publickey = options.publicKey;
    if (publickey.rp.id !== rpId) {
      throw new Error('rpId mismatch');
    }
    if (utils.bufferToUTF8String(publickey.user.id as ArrayBuffer) !== userId) {
      throw new Error('userId mismatch');
    }
  }

  return clientDataObj;
}

function handleAttStmt(fmt: string, attStmt: any) {
  getLogger().log('attestationObject.fmt=' + fmt);
  if (fmt === 'tpm') {
    getLogger().log('attStmt.ver=' + attStmt.ver);
    getLogger().log('attStmt.alg=' + attStmt.alg);
  }
  else if (fmt === 'apple') {
    getLogger().log('attStmt=' + JSON.stringify(attStmt));
  }
}

