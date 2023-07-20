export interface CredentialEntity {
    id: string;
    type: PublicKeyCredentialType;
    userId: string;
    username: string;
    displayName: string;
    rpId: string;
    transports: AuthenticatorTransport[];
    publicKey: string;
    publicKeyJwk: any;
    publicKeyAlgorithm: number;
  }
  