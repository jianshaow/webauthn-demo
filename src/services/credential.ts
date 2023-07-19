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

export function deleteCredential(credentialId: string): CredentialEntity[] {
  const newCredentials = getCredentials().filter((credential) => credential.id !== credentialId);
  localStorage.setItem('credentials', JSON.stringify(newCredentials));
  return newCredentials;
}
