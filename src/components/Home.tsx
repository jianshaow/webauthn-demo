import { Component, ChangeEvent, FormEvent } from 'react';
import './Home.css'
import * as cbor from 'cbor-x'

interface HomeState {
  log: string;
  loggedIn: boolean;
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
    const { username } = this.state;

    try {
      this.appendToLog('Start register...')
      this.appendToLog('username=' + username)
      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);
      const createCredentialOptions: CredentialCreationOptions = {
        publicKey: {
          rp: {
            name: 'AA Server',
          },
          user: {
            id: new Uint8Array([79, 252, 83, 72, 214, 7, 89, 26]),
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
      this.appendToLog('credentialId=' + credential.id);

      const { clientDataJSON, attestationObject } = credential.response as AuthenticatorAttestationResponse;

      // verify challenge
      const decoder = new TextDecoder('utf-8');
      const decodedClientData = decoder.decode(clientDataJSON);
      const clientDataObj = JSON.parse(decodedClientData);
      console.log('clientData=%o', clientDataObj);
      this.appendToLog('actualChallenge=' + clientDataObj.challenge);
      this.appendToLog('expectedChallenge=' + this.bufferToBase64URLString(challenge.buffer))

      const attestationObj = cbor.decode(new Uint8Array(attestationObject));
      console.log('attestation=%o', attestationObj)

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
      this.appendToLog('credentialId=' + credential?.id)
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
      const { authenticatorData, signature, clientDataJSON } = assertion.response as AuthenticatorAssertionResponse;

      // verify challenge
      const decoder = new TextDecoder('utf-8');
      const decodedClientData = decoder.decode(clientDataJSON);
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
        throw new Error('No public key')
      }

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
              <h1>Wellcome, { username }！</h1>
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
  render() {
    const { log } = this.props;

    return (
      <textarea value={log} readOnly rows={10} style={{ width: '80%', height: '200px' }} />
    );
  }
}

export default Home;
