import React, { Component, ChangeEvent, FormEvent } from 'react';
import './Home.css'
import * as cbor from 'cbor-x'

interface HomeState {
  log: string;
  loggedIn: boolean;
  userId: string;
  username: string;
  credential: PublicKeyCredential | null;
  registerEnabled: boolean;
  loginEnabled: boolean;
}

class Home extends Component<{}, HomeState> {
  constructor(props: {}) {
    super(props);
    this.state = {
      log: '',
      loggedIn: false,
      userId: '14562550-a677-4832-9add-77527ae332db',
      username: 'admin',
      credential: null,
      registerEnabled: false,
      loginEnabled: false,
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

  bufferToBase64URLString(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let str = '';

    for (const charCode of bytes) {
      str += String.fromCharCode(charCode);
    }

    const base64String = btoa(str);

    return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
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

  handleUsernameChange = (e: ChangeEvent<HTMLInputElement>) => {
    this.setState({ username: e.target.value });
  };

  handleRegister = async (e: FormEvent) => {
    e.preventDefault();
    const { username, userId } = this.state;

    try {
      this.appendToLog('Start register...')
      this.appendToLog('username=' + username)
      this.appendToLog('userId=' + userId);
      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);
      const createCredentialOptions: CredentialCreationOptions = {
        publicKey: {
          rp: {
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
          // attestation: 'direct',
          attestation: 'none',
        },
      };

      const credential = await navigator.credentials.create(createCredentialOptions) as PublicKeyCredential;
      this.appendToLog('credential.authenticatorAttachment=' + credential.authenticatorAttachment);
      this.appendToLog('credential.id=' + credential.id);
      this.appendToLog('credential.type=' + credential.type);

      const attestationResponse = credential.response as AuthenticatorAttestationResponse;
      this.appendToLog('attestation.publicKeyAlgorithm=' + attestationResponse.getPublicKeyAlgorithm());
      this.appendToLog('attestation.transports=' + attestationResponse.getTransports());

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

      // save credential in state
      this.setState({ registerEnabled: false, loginEnabled: true, credential: credential });
      this.appendToLog('Register success');
    } catch (error) {
      console.error(error);
      alert('Register fail');
      this.appendToLog('Error=' + error);
    }

    this.setState({ username: 'admin' });
  };

  handleLogin = async (e: FormEvent) => {
    e.preventDefault();
    const { username, credential } = this.state;

    try {
      this.appendToLog('Start login...')
      this.appendToLog('username=' + username)
      this.appendToLog('credential.id=' + credential?.id)
      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);
      const getCredentialOptions: CredentialRequestOptions = {
        publicKey: {
          challenge: challenge,
          allowCredentials: [
            {
              type: 'public-key',
              id: credential?.rawId as BufferSource,
              transports: ['internal', 'ble', 'nfc', 'usb', 'hybrid']
            },
          ],
          userVerification: 'preferred',
        },
      };

      const assertion = await navigator.credentials.get(getCredentialOptions) as PublicKeyCredential;
      this.appendToLog('assertion.id=' + assertion.id);
      this.appendToLog('assertion.type=' + assertion.type);

      const { authenticatorData, signature, clientDataJSON, userHandle } = assertion.response as AuthenticatorAssertionResponse;
      if (userHandle) {
        this.appendToLog('userHandle=' + this.bufferToUTF8String(userHandle));
      }

      // verify challenge
      const decodedClientData = this.bufferToUTF8String(clientDataJSON);
      const clientDataObj = JSON.parse(decodedClientData);
      this.appendToLog('actualChallenge=' + clientDataObj.challenge);
      this.appendToLog('expectedChallenge=' + this.bufferToBase64URLString(challenge.buffer))

      const hashedClientData = await crypto.subtle.digest('SHA-256', clientDataJSON)
      const signatureBase = this.concat([new Uint8Array(authenticatorData), new Uint8Array(hashedClientData)]);

      // retrieve public key from attestation that returned from registering before
      if (!credential) {
        throw new Error('No credential, register first')
      }

      const attestationResponse = credential.response as AuthenticatorAttestationResponse;
      const publicKeyDer = attestationResponse.getPublicKey();

      if (!publicKeyDer) {
        throw new Error('No public key');
      }

      // prepare public key
      const publicKey = await crypto.subtle.importKey(
        "spki",
        publicKeyDer,
        {
          name: "RSASSA-PKCS1-v1_5",
          hash: { name: "SHA-256" },
        },
        true,
        ["verify"]
      );

      // verify signature
      const result = await crypto.subtle.verify(
        {
          name: 'RSASSA-PKCS1-v1_5',
          hash: { name: 'SHA-256' },
        },
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

    this.setState({ username: 'admin' });
  };

  render() {
    const { loggedIn, username, registerEnabled, loginEnabled, log } = this.state;

    return (
      <div className="container">
        <div className="center">
          {loggedIn ? (
            <div>
              <h1>Wellcome, {username}！</h1>
              <button onClick={() => this.setState({ loggedIn: false })}>退出登录</button>
            </div>
          ) : (
            <div>
              <h1>Login</h1>
              <form onSubmit={this.handleLogin}>
                <label>
                  Username:
                  <input type="text" value={username} onChange={this.handleUsernameChange} />
                </label>
                <br />
                {registerEnabled ? (
                  <button type="submit">Register FIDO2 Passkey</button>
                ) : (
                  <button type="submit" disabled={!loginEnabled}>
                    FIDO2 Passkey Login
                  </button>
                )}
              </form>
              {registerEnabled ? null : (
                <p>
                  No FIDO2 Passkey？<button onClick={this.handleRegister}>Register FIDO2 Passkey</button>
                </p>
              )}
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
