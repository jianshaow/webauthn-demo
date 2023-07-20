export interface CredentialEntity {
    id: string;
    type: PublicKeyCredentialType;
    userId: string;
    username: string;
    displayName: string;
    rpId: string;
    transports: AuthenticatorTransport[];
    publicKeyDer: string;
    publicKeyJwk: any;
    publicKeyAlgorithm: number;
  }
  