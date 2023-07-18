import * as utils from '../helpers/utils';
import * as authData from '../helpers/authData';
import * as cred from '../services/credential'

const registerData: Map<string, CredentialCreationOptions> = new Map();

export function initRegistration(rpId: string, userId: string, username: string): CredentialCreationOptions {
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

export function finishRegistration(credential: PublicKeyCredential, rpId: string, userId: string, username: string, displayName: string) {
  const attestationResponse = credential.response as AuthenticatorAttestationResponse;
  const transports = attestationResponse.getTransports() as AuthenticatorTransport[];
  const pubclicKeyDer = attestationResponse.getPublicKey();

  if (!pubclicKeyDer) {
    throw new Error('no public key');
  }

  const { clientDataJSON, attestationObject } = attestationResponse;
  const decodedClientData = utils.bufferToUTF8String(clientDataJSON);
  const clientDataObj = JSON.parse(decodedClientData);

  const { challenge } = clientDataObj;
  const options = registerData.get(challenge);
  if (!options) {
    throw new Error('no credential related to the challenge');
  }
  if (options.publicKey) {
    const publickey = options.publicKey
    if (publickey.rp.id !== rpId) {
      throw new Error('rpId mismatch');
    }
    if (utils.bufferToUTF8String(publickey.user.id as ArrayBuffer) !== userId) {
      throw new Error('userId mismatch');
    }
  }

  const parsedAuthData = authData.parseAuthenticatorData(new Uint8Array(attestationResponse.getAuthenticatorData()));

  let publicKeyJwk;
  if (parsedAuthData.credentialPublicKey) {
    const publicKeyCose = authData.decodeFirst<authData.COSEPublicKey>(parsedAuthData.credentialPublicKey);
    console.log('publicKeyCose=%o', publicKeyCose);
    const coseKty = publicKeyCose.get(authData.COSEKEYS.kty);
    const coseKeyAlg = publicKeyCose.get(authData.COSEKEYS.alg);

    if (coseKty === authData.COSEKTY.EC2) {
      const ecPublicKeyCose = publicKeyCose as authData.COSEPublicKeyEC2;
      const coseCrv = ecPublicKeyCose.get(authData.COSEKEYS.crv);
      const coseX = ecPublicKeyCose.get(authData.COSEKEYS.x);
      const coseY = ecPublicKeyCose.get(authData.COSEKEYS.y);

      if (!coseCrv || !coseX || !coseY) {
        throw new Error('no ec key info');
      }
      publicKeyJwk = {
        kty: 'EC',
        crv: authData.toCrvString(coseCrv),
        x: utils.bufferToBase64URLString(coseX.buffer),
        y: utils.bufferToBase64URLString(coseY.buffer)
      }
    } else if (coseKty === authData.COSEKTY.RSA) {
      const rsaPublicKeyCose = publicKeyCose as authData.COSEPublicKeyRSA;
      const coseN = rsaPublicKeyCose.get(authData.COSEKEYS.n);
      const coseE = rsaPublicKeyCose.get(authData.COSEKEYS.e);
      if (!coseN || !coseE) {
        throw new Error('no ec key info');
      }
      publicKeyJwk = {
        kty: 'RSA',
        crv: '',
        n: utils.bufferToBase64URLString(coseN.buffer),
        e: utils.bufferToBase64URLString(coseE.buffer)
      }
    }
  }

  const credentialToBeStored = {
    id: credential.id,
    type: credential.type as PublicKeyCredentialType,
    userId: userId,
    username: username,
    displayName: displayName,
    rpId: rpId,
    transports: transports,
    publicKey: utils.bufferToBase64URLString(pubclicKeyDer),
    publicKeyJwk: publicKeyJwk,
    publicKeyAlgorithm: attestationResponse.getPublicKeyAlgorithm()
  };

  registerData.delete(challenge);
  cred.saveCredential(credentialToBeStored);

  return credentialToBeStored;
}
