import {
  cose,
  isoCBOR,
  convertAAGUIDToString,
  decodeAttestationObject,
  convertCertBufferToPEM,
  getCertificateInfo,
  parseAuthenticatorData,
  AttestationFormat,
  AttestationStatement,
} from '@simplewebauthn/server/helpers';
import * as utils from '../helpers/utils';
import * as cred from '../services/credential';
import { getLogger } from '../services/common';
import { CredentialEntity } from '../types/entities';

const registerData: Map<string, PublicKeyCredentialCreationOptions> = new Map();

export function initRegistration(
  rpId: string,
  userId: string,
  username: string,
  displayName: string,
  requireResidentKey: boolean,
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
      requireResidentKey: requireResidentKey,
      residentKey: residentKey,
      userVerification: userVerification,
    },
    attestation: attestation,
    extensions: {
      devicePubKey: {
        attestation: "direct",
        attestationFormats: [],
      }
    } as AuthenticationExtensionsClientInputs,
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
  if (attestationResponse.getPublicKeyAlgorithm) {
    const publicKeyAlgorithm = attestationResponse.getPublicKeyAlgorithm();
    getLogger().log('attestation.publicKeyAlgorithm=' + publicKeyAlgorithm);
  }

  let transports: AuthenticatorTransport[] = [];
  if (attestationResponse.getTransports) {
    transports = attestationResponse.getTransports() as AuthenticatorTransport[];
    getLogger().log('attestation.transports=' + transports);
  }

  let publicKeyDer = '';
  if (attestationResponse.getPublicKey) {
    const pubclicKey = attestationResponse.getPublicKey();
    if (!pubclicKey) {
      throw new Error('no public key');
    }
    publicKeyDer = utils.bufferToBase64URLString(pubclicKey);
  }

  const { clientDataJSON, attestationObject } = attestationResponse;
  getLogger().log('clientDataJSONBase64=' + utils.bufferToBase64URLString(clientDataJSON));
  getLogger().log('attestationObjectBase64=' + utils.bufferToBase64URLString(attestationObject));

  handleClientData(clientDataJSON, rpId, userId);

  const decodedAttestationObject = decodeAttestationObject(new Uint8Array(attestationObject));
  console.info('attestationObject=%o', decodedAttestationObject);

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
    publicKeyAlgorithm: coseKeyAlg,
  };

  cred.saveCredential(credentialToBeStored);
  {
    const { publicKeyDer, publicKeyJwk, ...printableCredentialEntity } = credentialToBeStored;
    getLogger().log('savedCredentialEntity=' + JSON.stringify(printableCredentialEntity));
  }

  return credentialToBeStored;
}

function handleAuthData(authData: Uint8Array): { publicKeyJwk: any, coseKeyAlg: number } {
  const parsedAuthData = parseAuthenticatorData(authData);
  console.info('parsedAuthData=%o', parsedAuthData);

  const { aaguid, counter, flags, extensionsData, credentialPublicKey } = parsedAuthData;
  if (aaguid) {
    getLogger().log('authData.aaguid=' + convertAAGUIDToString(aaguid));
  }
  getLogger().log('authData.counter=' + counter);
  getLogger().log('authData.flags=' + JSON.stringify(flags));
  if (extensionsData) {
    handleAuthDataExtensions(extensionsData);
  }

  if (!credentialPublicKey) {
    throw new Error('no public key');
  }

  const publicKeyCose = isoCBOR.decodeFirst<cose.COSEPublicKey>(credentialPublicKey);
  console.info('publicKeyCose=%o', publicKeyCose);
  const coseKty = publicKeyCose.get(cose.COSEKEYS.kty);
  const coseKeyAlg = publicKeyCose.get(cose.COSEKEYS.alg);

  if (!coseKty || !coseKeyAlg) {
    throw new Error('no COSE kty or COSE keyAlg');
  }

  let publicKeyJwk;
  if (coseKty === cose.COSEKTY.EC2) {
    const ecPublicKeyCose = publicKeyCose as cose.COSEPublicKeyEC2;
    const coseCrv = ecPublicKeyCose.get(cose.COSEKEYS.crv);
    const coseX = ecPublicKeyCose.get(cose.COSEKEYS.x);
    const coseY = ecPublicKeyCose.get(cose.COSEKEYS.y);

    if (!coseCrv || !coseX || !coseY) {
      throw new Error('no ec key info');
    }
    publicKeyJwk = {
      kty: 'EC',
      crv: utils.toCrvString(coseCrv),
      x: utils.bufferToBase64URLString(coseX),
      y: utils.bufferToBase64URLString(coseY)
    };
  } else if (coseKty === cose.COSEKTY.RSA) {
    const rsaPublicKeyCose = publicKeyCose as cose.COSEPublicKeyRSA;
    const coseN = rsaPublicKeyCose.get(cose.COSEKEYS.n);
    const coseE = rsaPublicKeyCose.get(cose.COSEKEYS.e);
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

function handleAuthDataExtensions(extensionsData: any) {
  getLogger().log('authData.extensionsData=' + JSON.stringify(extensionsData));
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

  if (fmt !== 'none') {
    getLogger().log('attStmt.alg=' + attStmt.get('alg'));

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
}
