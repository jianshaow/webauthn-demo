import * as cbor from 'cbor-x';

const encoder = new cbor.Encoder({ mapsAsObjects: false, tagUint8Array: false });

function encode(input: any): Uint8Array {
    return encoder.encode(input);
}

function toDataView(array: Uint8Array): DataView {
    return new DataView(array.buffer, array.byteOffset, array.length);
}

export function decodeFirst<Type>(input: Uint8Array): Type {
    const decoded = encoder.decodeMultiple(input) as undefined | Type[];

    if (decoded === undefined) {
        throw new Error('CBOR input data was empty');
    }

    const [first] = decoded;

    return first;
}

function convertMapToObjectDeep(input: Map<string, unknown>): { [key: string]: unknown } {
    const mapped: { [key: string]: unknown } = {};

    for (const [key, value] of input) {
        if (value instanceof Map) {
            mapped[key] = convertMapToObjectDeep(value);
        } else {
            mapped[key] = value;
        }
    }

    return mapped;
}

function decodeAuthenticatorExtensions(
    extensionData: Uint8Array,
): AuthenticationExtensionsAuthenticatorOutputs | undefined {
    let toCBOR: Map<string, unknown>;
    try {
        toCBOR = decodeFirst(extensionData);
    } catch (err) {
        const _err = err as Error;
        throw new Error(`Error decoding authenticator extensions: ${_err.message}`);
    }

    return convertMapToObjectDeep(toCBOR);
}

export function parseAuthenticatorData(authData: Uint8Array): ParsedAuthenticatorData {
    if (authData.byteLength < 37) {
        throw new Error(
            `Authenticator data was ${authData.byteLength} bytes, expected at least 37 bytes`,
        );
    }

    let pointer = 0;
    const dataView = toDataView(authData);

    const rpIdHash = authData.slice(pointer, (pointer += 32));

    const flagsBuf = authData.slice(pointer, (pointer += 1));
    const flagsInt = flagsBuf[0];

    const flags = {
        up: !!(flagsInt & (1 << 0)),
        uv: !!(flagsInt & (1 << 2)),
        be: !!(flagsInt & (1 << 3)),
        bs: !!(flagsInt & (1 << 4)),
        at: !!(flagsInt & (1 << 6)),
        ed: !!(flagsInt & (1 << 7)),
        flagsInt,
    };

    const counterBuf = authData.slice(pointer, pointer + 4);
    const counter = dataView.getUint32(pointer, false);
    pointer += 4;

    let aaguid: Uint8Array | undefined = undefined;
    let credentialID: Uint8Array | undefined = undefined;
    let credentialPublicKey: Uint8Array | undefined = undefined;

    if (flags.at) {
        aaguid = authData.slice(pointer, (pointer += 16));

        const credIDLen = dataView.getUint16(pointer);
        pointer += 2;

        credentialID = authData.slice(pointer, (pointer += credIDLen));

        const firstDecoded = decodeFirst<COSEPublicKey>(authData.slice(pointer));
        const firstEncoded = Uint8Array.from(encode(firstDecoded));

        credentialPublicKey = firstEncoded;
        pointer += firstEncoded.byteLength;
    }

    let extensionsData: AuthenticationExtensionsAuthenticatorOutputs | undefined = undefined;
    let extensionsDataBuffer: Uint8Array | undefined = undefined;

    if (flags.ed) {
        const firstDecoded = decodeFirst(authData.slice(pointer));
        extensionsDataBuffer = Uint8Array.from(encode(firstDecoded));
        extensionsData = decodeAuthenticatorExtensions(extensionsDataBuffer);
        pointer += extensionsDataBuffer.byteLength;
    }

    if (authData.byteLength > pointer) {
        throw new Error('Leftover bytes detected while parsing authenticator data');
    }

    return {
        rpIdHash,
        flagsBuf,
        flags,
        counter,
        counterBuf,
        aaguid,
        credentialID,
        credentialPublicKey,
        extensionsData,
        extensionsDataBuffer,
    };
}

export function toCrvString(coseCrv: number){
    if (coseCrv === COSECRV.P256) {
        return 'P-256';
      } else if (coseCrv === COSECRV.P384) {
        return 'P-384';
      } else if (coseCrv === COSECRV.P521) {
        return 'P-521';
      } else {
        throw new Error(`Unexpected COSE crv value $(coseCrv)`);
      }
}

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
