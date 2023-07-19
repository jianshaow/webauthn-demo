import { CredentialEntity } from "./types";

export function saveCredential(credential: CredentialEntity): CredentialEntity[] {
  const credentialsJson = localStorage.getItem('credentials');
  let credentials = [];
  if (credentialsJson) {
    credentials = JSON.parse(credentialsJson);
  }
  credentials.push(credential);
  localStorage.setItem('credentials', JSON.stringify(credentials));
  return credentials;
}

export function getCredentials(): CredentialEntity[] {
  const credentialsJson = localStorage.getItem('credentials');
  let credentials = [];
  if (credentialsJson) {
    credentials = JSON.parse(credentialsJson);
  }
  return credentials;
}

export function getCredential(credentialId: string): CredentialEntity {
  const credentialsJson = localStorage.getItem('credentials');
  let credentials = [];
  if (credentialsJson) {
    credentials = JSON.parse(credentialsJson);
  }
  const newCredentials = getCredentials().filter((credential) => credential.id == credentialId);
  if (!newCredentials.length) {
    throw new Error(`no credential with id $(credentialId)`);
  }
  return newCredentials[0];
}

export function deleteCredential(credentialId: string): CredentialEntity[] {
  const newCredentials = getCredentials().filter((credential) => credential.id !== credentialId);
  localStorage.setItem('credentials', JSON.stringify(newCredentials));
  return newCredentials;
}
