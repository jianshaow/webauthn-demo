import React, { Component, ChangeEvent, FormEvent, MouseEvent } from 'react';
import './Home.css'
import * as cbor from 'cbor-x'

interface HomeState {
  log: string;
  loggedIn: boolean;
  userId: string;
  username: string;
  allowCredentials: PublicKeyCredentialDescriptor[];
  storedCredentials: Credential[];
  displayName: string;
  rpId: string;
}

interface Credential {
  id: string;
  userId: string;
  username: string;
  displayName: string;
  publicKey: string;
  publicKeyAlgorithm: number;
}

class Home extends Component<{}, HomeState> {
  constructor(props: {}) {
    super(props);

    const credentialsJson = localStorage.getItem('credentials');
    var credentials = [];
    if (credentialsJson) {
      credentials = JSON.parse(credentialsJson);
    }

    this.state = {
      log: '',
      loggedIn: false,
      userId: '14562550-a677-4832-9add-77527ae332db',
      username: 'John.Smith@TechGenius.com',
      allowCredentials: [],
      storedCredentials: credentials,
      rpId: window.location.host.split(':')[0],
      displayName: 'John Smith',
    };
  }

  appendToLog(message: string) {
    const now = new Date();
    const hours = now.getHours().toString().padStart(2, '0');
    const minutes = now.getMinutes().toString().padStart(2, '0');
    const seconds = now.getSeconds().toString().padStart(2, '0');
    const milliseconds = now.getMilliseconds().toString().padStart(3, '0');
    const timestamp = `${hours}:${minutes}:${seconds}.${milliseconds}`;
    const logEntry = `[${timestamp}] ${message}`;
    this.setState(prevState => ({ log: prevState.log + logEntry + '\n' }));
  };

  bufferToUTF8String(value: ArrayBuffer): string {
    return new TextDecoder('utf-8').decode(value);
  }

  stringToBuffer(value: string): ArrayBuffer {
    return new TextEncoder().encode(value);
  }

  bufferToBase64URLString(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let str = '';

    for (const charCode of bytes) {
      str += String.fromCharCode(charCode);
    }

    const base64String = btoa(str);

    return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  base64URLStringToBuffer(base64URLString: string): ArrayBuffer {
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

  concat(arrays: Uint8Array[]): Uint8Array {
    let pointer = 0;
    const totalLength = arrays.reduce((prev, curr) => prev + curr.length, 0);

    const toReturn = new Uint8Array(totalLength);

    arrays.forEach(arr => {
      toReturn.set(arr, pointer);
      pointer += arr.length;
    });

    return toReturn;
  }

  generateUUID(): string {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    array[6] = (array[6] & 0x0f) | 0x40;
    array[8] = (array[8] & 0x3f) | 0x80;
    const hex = Array.from(array, byte => byte.toString(16).padStart(2, '0'));
    const uuid = `${hex.slice(0, 4).join('')}-${hex.slice(4, 6).join('')}-${hex.slice(6, 8).join('')}-${hex.slice(8, 10).join('')}-${hex.slice(10).join('')}`;
    return uuid;
  }

  isSelected = (credentialId: string) => {
    const { allowCredentials } = this.state;
    return allowCredentials.some((selectedCredential) => this.bufferToBase64URLString(selectedCredential.id as ArrayBuffer) === credentialId);
  };

  deleteCredential = (e: MouseEvent<HTMLButtonElement>) => {
    const { storedCredentials } = this.state;
    const newCredentials = storedCredentials.filter((credential) => credential.id !== (e.target as HTMLButtonElement).id);
    this.setState({ storedCredentials: newCredentials });
    localStorage.setItem('credentials', JSON.stringify(newCredentials));
  }

  regenUserId = (e: MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    this.setState({ userId: this.generateUUID() });
  };

  handleUsernameChange = (e: ChangeEvent<HTMLInputElement>) => {
    this.setState({ username: e.target.value });
  };

  handleRpId = (e: ChangeEvent<HTMLInputElement>) => {
    this.setState({ rpId: e.target.value });
  };

  handleAllowCredentialsChange = (e: ChangeEvent<HTMLInputElement>) => {
    const { allowCredentials } = this.state;
    if (e.target.checked) {
      const allowCredential: PublicKeyCredentialDescriptor = {
        type: 'public-key',
        id: this.base64URLStringToBuffer(e.target.value),
        transports: ['internal']
      }
      allowCredentials.push(allowCredential);
      this.setState({ allowCredentials: allowCredentials })
    } else {
      const newCredentials = allowCredentials.filter((selectedCredential) => this.bufferToUTF8String(selectedCredential.id as ArrayBuffer) !== e.target.value);
      this.setState({ allowCredentials: newCredentials });
    }
  };

  handleRegister = async (e: FormEvent) => {
    e.preventDefault();
    const { username, displayName, userId, rpId, storedCredentials } = this.state;

    try {
      this.appendToLog('Start register...')
      this.appendToLog('username=' + username)
      this.appendToLog('userId=' + userId);

      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);
      const createCredentialOptions: CredentialCreationOptions = {
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

      const credential = await navigator.credentials.create(createCredentialOptions) as PublicKeyCredential;
      this.appendToLog('credential.id=' + credential.id);
      this.appendToLog('credential.type=' + credential.type);
      this.appendToLog('credential.authenticatorAttachment=' + credential.authenticatorAttachment);

      const attestationResponse = credential.response as AuthenticatorAttestationResponse;
      this.appendToLog('attestation.publicKeyAlgorithm=' + attestationResponse.getPublicKeyAlgorithm());
      this.appendToLog('attestation.transports=' + attestationResponse.getTransports());

      const pubclicKeyDer = attestationResponse.getPublicKey();
      if (!pubclicKeyDer) {
        throw new Error('no public key');
      }

      const { clientDataJSON, attestationObject } = attestationResponse;

      // verify challenge
      const decodedClientData = this.bufferToUTF8String(clientDataJSON);
      const clientDataObj = JSON.parse(decodedClientData);
      console.log('clientData=%o', clientDataObj);
      this.appendToLog('actualChallenge=' + clientDataObj.challenge);
      this.appendToLog('expectedChallenge=' + this.bufferToBase64URLString(challenge.buffer));

      const attestationObj = cbor.decode(new Uint8Array(attestationObject));
      console.log('attestation=%o', attestationObj);
      this.appendToLog('attestationObject.fmt=' + attestationObj.fmt);

      // save credential in state and local storage
      storedCredentials.push({
        id: credential.id,
        userId: userId,
        username: username,
        displayName: displayName,
        publicKey: this.bufferToBase64URLString(pubclicKeyDer),
        publicKeyAlgorithm: attestationResponse.getPublicKeyAlgorithm()
      });
      localStorage.setItem('credentials', JSON.stringify(storedCredentials));

      this.appendToLog('Register success');
    } catch (error) {
      console.error(error);
      alert('Register fail');
      this.appendToLog('Error=' + error);
    }

    this.setState({ username: 'John.Smith@TechGenius.com', storedCredentials: storedCredentials });
  };

  handleLogin = async (e: FormEvent) => {
    e.preventDefault();
    const { username, storedCredentials, allowCredentials } = this.state;

    try {
      this.appendToLog('Start login...')
      this.appendToLog('username=' + username)
      this.appendToLog('storedCredentials.length=' + storedCredentials.length)

      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);
      const getCredentialOptions: CredentialRequestOptions = {
        publicKey: {
          challenge: challenge,
          allowCredentials: allowCredentials,
          userVerification: 'preferred',
        },
      };

      const assertion = await navigator.credentials.get(getCredentialOptions) as PublicKeyCredential;
      this.appendToLog('assertion.id=' + assertion.id);
      this.appendToLog('assertion.type=' + assertion.type);

      const { authenticatorData, signature, clientDataJSON, userHandle } = assertion.response as AuthenticatorAssertionResponse;

      if (!userHandle) {
        throw new Error('no user id')
      }

      // verify challenge
      const decodedClientData = this.bufferToUTF8String(clientDataJSON);
      const clientDataObj = JSON.parse(decodedClientData);
      console.log('clientData=%o', clientDataObj);
      this.appendToLog('actualChallenge=' + clientDataObj.challenge);
      this.appendToLog('expectedChallenge=' + this.bufferToBase64URLString(challenge.buffer));

      const hashedClientData = await crypto.subtle.digest('SHA-256', clientDataJSON);
      const signatureBase = this.concat([new Uint8Array(authenticatorData), new Uint8Array(hashedClientData)]);

      // retrieve public key from attestation that returned from registering before
      if (!storedCredentials.length) {
        throw new Error('No credential stored, register first');
      }

      const userId = this.bufferToUTF8String(userHandle);
      this.appendToLog('userId=' + userId);
      const filteredCredentials = storedCredentials.filter((credential) => credential.userId === userId);
      if (!filteredCredentials.length) {
        throw new Error('no this user stored')
      }
      const credential = filteredCredentials[0];

      const publicKeyDer = this.base64URLStringToBuffer(credential.publicKey);
      const algorithm = credential.publicKeyAlgorithm;
      this.appendToLog('publicKeyAlgorithm=' + algorithm);

      const getImportAlgorithm = (algorithm: number): RsaHashedImportParams | EcKeyImportParams | AlgorithmIdentifier => {
        if (algorithm === -7) { // for iOS
          return { name: 'ECDSA', namedCurve: 'P-256' };
        } else if (algorithm === -257) { // for Windows
          return { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } };
        } else {
          return 'ECDSA';
        }
      }

      const getVerifyAlgorithm = (algorithm: number): RsaPssParams | EcdsaParams | AlgorithmIdentifier => {
        if (algorithm === -7) { // for iOS
          return { name: 'ECDSA', hash: { name: 'SHA-256' } };
        } else if (algorithm === -257) { // for Windows
          return { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } };
        } else {
          return 'ECDSA';
        }
      }

      if (!publicKeyDer) {
        throw new Error('No public key');
      }

      // prepare public key
      const publicKey = await crypto.subtle.importKey(
        'spki',
        publicKeyDer,
        getImportAlgorithm(algorithm),
        true,
        ['verify']
      );

      // verify signature
      const result = await crypto.subtle.verify(
        getVerifyAlgorithm(algorithm),
        publicKey,
        signature,
        signatureBase
      );

      if (!result) {
        throw new Error('Invalid signature');
      }

      this.setState({ loggedIn: true });
      this.appendToLog('Login success');
    } catch (error) {
      console.error(error);
      alert('Login fail');
      this.appendToLog('Error=' + error);
    }

    this.setState({ username: 'John.Smith@TechGenius.com' });
  };

  render() {
    const { loggedIn, userId, username, storedCredentials, displayName, rpId, log } = this.state;
    return (
      <div className="container">
        <div className="center">
          {loggedIn ? (
            <div>
              <h1>Wellcome, {username}！</h1>
              <button onClick={() => this.setState({ loggedIn: false })}>Logout</button>
            </div>
          ) : (
            <div>
              <h1>Login</h1>
              <form onSubmit={this.handleLogin}>
                <label>storedCredentials:</label>
                <div className='table-container'>
                  <table>
                    <thead>
                      <tr>
                        <th>allowCredentials</th>
                        <th>credentials</th>
                        <th>action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {storedCredentials.map((credential) => (
                        <tr key={credential.id}>
                          <td>
                            <input type="checkbox" value={credential.id} checked={this.isSelected(credential.id)} onChange={this.handleAllowCredentialsChange} />
                          </td>
                          <td>
                            {credential.username}
                          </td>
                          <td>
                            <button id={credential.id} onClick={this.deleteCredential}>delete</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div>
                  <label> Username: </label>
                  <input type="text" value={username} onChange={this.handleUsernameChange} />
                </div>
                <button type="submit" disabled={!storedCredentials.length}>Passkey Login</button>
              </form>
              <div>
                <br />
                <label>No Passkey?</label>
                <form onSubmit={this.handleRegister}>
                  <div>
                    <label> UserId: </label>
                    <input type="text" value={userId} readOnly style={{ width: '260px' }} />
                    <button onClick={this.regenUserId}>Regen</button>
                  </div>
                  <div>
                    <label> DisplayName: </label>
                    <input type="text" value={displayName} readOnly style={{ width: '260px' }} />
                  </div>
                  <div>
                    <label>RPId: </label>
                    <input type="text" value={rpId} onChange={this.handleRpId} />
                  </div>
                  <div>
                    <button type="submit">Register Passkey</button>
                  </div>
                </form>
              </div>
            </div>
          )}
        </div>
        <div className="divider" />
        <div className="center">
          <LogViewer log={log} />
        </div>
      </div>
    );
  }
}

interface LogViewerState {
  log: string;
}

class LogViewer extends Component<LogViewerState> {
  logRef = React.createRef<HTMLTextAreaElement>();

  componentDidUpdate() {
    const { current } = this.logRef;
    if (current) {
      current.scrollTop = current.scrollHeight;
    }
  }

  render() {
    const { log } = this.props;

    return (
      <textarea ref={this.logRef} value={log} readOnly rows={10} style={{ width: '80%', height: '200px' }} />
    );
  }
}

export default Home;
