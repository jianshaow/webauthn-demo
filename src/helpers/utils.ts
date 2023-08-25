import { ECDSASigValue } from '@peculiar/asn1-ecc';
import { AsnParser } from '@peculiar/asn1-schema';
import { cose } from '@simplewebauthn/server/helpers';

export function bufferToUTF8String(value: ArrayBuffer): string {
  return new TextDecoder('utf-8').decode(value);
}

export function stringToBuffer(value: string): ArrayBuffer {
  return new TextEncoder().encode(value);
}

export function bufferToBase64URLString(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let str = '';

  for (const charCode of bytes) {
    str += String.fromCharCode(charCode);
  }

  const base64String = btoa(str);

  return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export function base64URLStringToBuffer(base64URLString: string): ArrayBuffer {
  const base64 = base64URLString.replace(/-/g, '+').replace(/_/g, '/');

  const padLength = (4 - (base64.length % 4)) % 4;
  const padded = base64.padEnd(base64.length + padLength, '=');

  const binary = atob(padded);

  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return buffer;
}

export function concat(arrays: Uint8Array[]): Uint8Array {
  let pointer = 0;
  const totalLength = arrays.reduce((prev, curr) => prev + curr.length, 0);

  const toReturn = new Uint8Array(totalLength);

  arrays.forEach(arr => {
    toReturn.set(arr, pointer);
    pointer += arr.length;
  });

  return toReturn;
}

export function generateUUID(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  array[6] = (array[6] & 0x0f) | 0x40;
  array[8] = (array[8] & 0x3f) | 0x80;
  const hex = Array.from(array, byte => byte.toString(16).padStart(2, '0'));
  const uuid = `${hex.slice(0, 4).join('')}-${hex.slice(4, 6).join('')}-${hex.slice(6, 8).join('')}-${hex.slice(8, 10).join('')}-${hex.slice(10).join('')}`;
  return uuid;
}

export function unwrapEC2Signature(signature: Uint8Array): Uint8Array {
  const parsedSignature = AsnParser.parse(signature, ECDSASigValue);
  let rBytes = new Uint8Array(parsedSignature.r);
  let sBytes = new Uint8Array(parsedSignature.s);
  if (shouldRemoveLeadingZero(rBytes)) {
    rBytes = rBytes.slice(1);
  }
  if (shouldRemoveLeadingZero(sBytes)) {
    sBytes = sBytes.slice(1);
  }
  const finalSignature = concat([rBytes, sBytes]);
  return finalSignature;
}

export function toCrvString(coseCrv: number) {
  if (coseCrv === cose.COSECRV.P256) {
    return 'P-256';
  } else if (coseCrv === cose.COSECRV.P384) {
    return 'P-384';
  } else if (coseCrv === cose.COSECRV.P521) {
    return 'P-521';
  } else {
    throw new Error(`Unexpected COSE crv value $(coseCrv)`);
  }
}

export function splitDomain(domain: string): string[] {
  const parts = domain.split('.');
  const result: string[] = [];

  for (let i = 0; i < parts.length - 1; i++) {
    const subDomain = parts.slice(i).join('.');
    result.push(subDomain);
  }

  return result;
}

function shouldRemoveLeadingZero(bytes: Uint8Array): boolean {
  return bytes[0] === 0x0 && (bytes[1] & (1 << 7)) !== 0;
}
