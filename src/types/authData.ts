export type ParsedAuthenticatorData = {
    rpIdHash: Uint8Array;
    flagsBuf: Uint8Array;
    flags: {
        up: boolean;
        uv: boolean;
        be: boolean;
        bs: boolean;
        at: boolean;
        ed: boolean;
        flagsInt: number;
    };
    counter: number;
    counterBuf: Uint8Array;
    aaguid?: Uint8Array;
    credentialID?: Uint8Array;
    credentialPublicKey?: Uint8Array;
    extensionsData?: AuthenticationExtensionsAuthenticatorOutputs;
    extensionsDataBuffer?: Uint8Array;
};

export type AuthenticationExtensionsAuthenticatorOutputs = {
    devicePubKey?: DevicePublicKeyAuthenticatorOutput;
    uvm?: UVMAuthenticatorOutput;
};

export type DevicePublicKeyAuthenticatorOutput = {
    dpk?: Uint8Array;
    sig?: string;
    nonce?: Uint8Array;
    scope?: Uint8Array;
    aaguid?: Uint8Array;
};

export type UVMAuthenticatorOutput = {
    uvm?: Uint8Array[];
};

export type COSEPublicKey = {
    get(key: COSEKEYS.kty): COSEKTY | undefined;
    get(key: COSEKEYS.alg): COSEALG | undefined;
    set(key: COSEKEYS.kty, value: COSEKTY): void;
    set(key: COSEKEYS.alg, value: COSEALG): void;
};

export type COSEPublicKeyEC2 = COSEPublicKey & {
    get(key: COSEKEYS.crv): number | undefined;
    get(key: COSEKEYS.x): Uint8Array | undefined;
    get(key: COSEKEYS.y): Uint8Array | undefined;
    set(key: COSEKEYS.crv, value: number): void;
    set(key: COSEKEYS.x, value: Uint8Array): void;
    set(key: COSEKEYS.y, value: Uint8Array): void;
};

export type COSEPublicKeyRSA = COSEPublicKey & {
    get(key: COSEKEYS.n): Uint8Array | undefined;
    get(key: COSEKEYS.e): Uint8Array | undefined;
    set(key: COSEKEYS.n, value: Uint8Array): void;
    set(key: COSEKEYS.e, value: Uint8Array): void;
};

export enum COSEKEYS {
    kty = 1,
    alg = 3,
    crv = -1,
    x = -2,
    y = -3,
    n = -1,
    e = -2,
}

export enum COSEKTY {
    OKP = 1,
    EC2 = 2,
    RSA = 3,
}

export enum COSEALG {
    ES256 = -7,
    EdDSA = -8,
    ES384 = -35,
    ES512 = -36,
    PS256 = -37,
    PS384 = -38,
    PS512 = -39,
    ES256K = -47,
    RS256 = -257,
    RS384 = -258,
    RS512 = -259,
    RS1 = -65535,
}

export enum COSECRV {
    P256 = 1,
    P384 = 2,
    P521 = 3,
    ED25519 = 6,
  }