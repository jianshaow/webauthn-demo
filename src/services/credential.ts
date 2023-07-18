import { CredentialEntity } from "./types";

export function saveCredential(credential: CredentialEntity) {
  const credentialsJson = localStorage.getItem('credentials');
  let credentials = [];
  if (credentialsJson) {
    credentials = JSON.parse(credentialsJson);
  }
  credentials.push(credential);
  localStorage.setItem('credentials', JSON.stringify(credentials));
}

export function getCredentials(): CredentialEntity[] {
  const credentialsJson = localStorage.getItem('credentials');
  let credentials = [];
  if (credentialsJson) {
    credentials = JSON.parse(credentialsJson);
  }
  return credentials;
}
