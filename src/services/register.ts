// import * as cbor from 'cbor-x';
import {
  convertAAGUIDToString,
  decodeAttestationObject,
  convertCertBufferToPEM,
  getCertificateInfo,
  AttestationFormat,
  AttestationStatement,
} from '@simplewebauthn/server/helpers';
import * as utils from '../helpers/utils';
import * as helper from '../helpers/authData';
import * as cred from '../services/credential';
import * as types from '../types/authData';
import { getLogger } from '../services/common';
import { CredentialEntity } from '../types/entities';

const registerData: Map<string, PublicKeyCredentialCreationOptions> = new Map();

export function initRegistration(
  rpId: string,
  userId: string,
  username: string,
  displayName: string,
  residentKey: ResidentKeyRequirement,
  userVerification: UserVerificationRequirement,
  authenticatorAttachment: AuthenticatorAttachment,
  attestation: AttestationConveyancePreference,
  excludeCredentials: PublicKeyCredentialDescriptor[]
): PublicKeyCredentialCreationOptions {
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);
  const options: PublicKeyCredentialCreationOptions = {
    rp: {
      id: rpId,
      name: 'AA Server',
    },
    user: {
      id: new TextEncoder().encode(userId),
      name: username,
      displayName: displayName,
    },
    challenge: challenge,
    excludeCredentials: excludeCredentials,
    pubKeyCredParams: [
      { type: 'public-key', alg: -257 }, { type: 'public-key', alg: -7 }
    ],
    authenticatorSelection: {
      authenticatorAttachment: authenticatorAttachment,
      residentKey: residentKey,
      userVerification: userVerification,
    },
    attestation: attestation,
  };
  registerData.set(utils.bufferToBase64URLString(challenge), options);
  return options;
}

export function finishRegistration(
  credential: PublicKeyCredential,
  rpId: string,
  userId: string,
  username: string,
  displayName: string
): CredentialEntity {
  getLogger().log('credential.id=' + credential.id);
  getLogger().log('credential.type=' + credential.type);
  getLogger().log('credential.authenticatorAttachment=' + credential.authenticatorAttachment);

  const attestationResponse = credential.response as AuthenticatorAttestationResponse;
  const publicKeyAlgorithm = attestationResponse.getPublicKeyAlgorithm();
  getLogger().log('attestation.publicKeyAlgorithm=' + publicKeyAlgorithm);

  let transports: AuthenticatorTransport[] = [];
  if (attestationResponse.getTransports) {
    transports = attestationResponse.getTransports() as AuthenticatorTransport[];
    getLogger().log('attestation.transports=' + transports);
  }

  const pubclicKey = attestationResponse.getPublicKey();

  if (!pubclicKey) {
    throw new Error('no public key');
  }
  const publicKeyDer = utils.bufferToBase64URLString(pubclicKey);

  const { clientDataJSON, attestationObject } = attestationResponse;
  getLogger().log('clientDataJSONBase64=' + utils.bufferToBase64URLString(clientDataJSON));
  getLogger().log('attestationObjectBase64=' + utils.bufferToBase64URLString(attestationObject));

  handleClientData(clientDataJSON, rpId, userId);

  // const decodedAttestationObject = cbor.decode(new Uint8Array(attestationObject));
  const decodedAttestationObject = decodeAttestationObject(new Uint8Array(attestationObject));
  console.info('attestationObject=%o', decodedAttestationObject);

  // const { fmt, attStmt, authData } = decodedAttestationObject;

  handleAttStmt(decodedAttestationObject.get('fmt'), decodedAttestationObject.get('attStmt'));

  const { publicKeyJwk, coseKeyAlg } = handleAuthData(decodedAttestationObject.get('authData'));

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
  if (aaguid) {
    getLogger().log('authData.aaguid=' + convertAAGUIDToString(aaguid));
  }
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

  if (options.rp.id !== rpId) {
    throw new Error('rpId mismatch');
  }
  if (utils.bufferToUTF8String(options.user.id as ArrayBuffer) !== userId) {
    throw new Error('userId mismatch');
  }

  return clientDataObj;
}

function handleAttStmt(fmt: AttestationFormat, attStmt: AttestationStatement) {
  getLogger().log('attestationObject.fmt=' + fmt);
  getLogger().log('attStmt.size=' + attStmt.size);
  if (fmt === 'tpm') {
    getLogger().log('attStmt.ver=' + attStmt.get('ver'));
  }
  else if (fmt === 'apple') {
    // TODO
  }
  getLogger().log('attStmt.alg=' + attStmt.get('alg'));
  // getLogger().log('attStmt.sigBase64=' + utils.bufferToBase64URLString(attStmt.get('sig')?.buffer as ArrayBuffer));
  const certs = attStmt.get('x5c');
  if (certs) {
    getLogger().log('attStmt.x5c.size=' + certs.length);
    certs.forEach(item => {
      const { parsedCertificate, ...certInfo } = getCertificateInfo(item);
      getLogger().log('certInfo=' + JSON.stringify(certInfo));
      getLogger().log(convertCertBufferToPEM(item));
    });
  }
}
