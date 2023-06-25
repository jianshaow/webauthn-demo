import { Component, ChangeEvent, FormEvent } from 'react';
import './Home.css'
import * as cbor from 'cbor-x'

interface HomeState {
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
      loggedIn: false,
      username: 'admin',
      credential: null,
      registerEnabled: false,
      loginEnabled: false,
    };
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
    const { username } = this.state;
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);

    try {
      const createCredentialOptions: CredentialCreationOptions = {
        publicKey: {
          rp: {
            name: 'Admin Console',
          },
          user: {
            id: new Uint8Array([79, 252, 83, 72, 214, 7, 89, 26]),
            name: username,
            displayName: username,
          },
          challenge: challenge,
          pubKeyCredParams: [
            { type: 'public-key', alg: -257 },
          ],
          authenticatorSelection: {
            authenticatorAttachment: 'platform',
            userVerification: 'preferred',
          },
          attestation: 'direct',
        },
      };

      const credential = await navigator.credentials.create(createCredentialOptions) as PublicKeyCredential;
      console.log('credentialId=%s', credential.id);

      const { clientDataJSON, attestationObject } = credential.response as AuthenticatorAttestationResponse;

      // verify challenge
      const decoder = new TextDecoder('utf-8');
      const decodedClientData = decoder.decode(clientDataJSON);
      const clientDataObj = JSON.parse(decodedClientData);
      console.log('clientData=%o', clientDataObj);
      console.log('actualChallenge=%s', clientDataObj.challenge);
      console.log('expectedChallenge=%s', this.bufferToBase64URLString(challenge.buffer))

      const attestationObj = cbor.decode(new Uint8Array(attestationObject));
      console.log('attestation=%o', attestationObj)

      // save credential in state
      this.setState({ registerEnabled: false, loginEnabled: true, credential: credential });
      alert('Register success');
    } catch (error) {
      console.error(error);
      alert('Register fail');
    }

    this.setState({ username: '' });
  };

  handleLogin = async (e: FormEvent) => {
    e.preventDefault();
    const { username, credential } = this.state;
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);

    console.log('credentialId=%s', credential?.id)

    try {
      const getCredentialOptions: CredentialRequestOptions = {
        publicKey: {
          challenge: challenge,
          allowCredentials: [
            {
              type: 'public-key',
              id: credential?.rawId as BufferSource,
              transports: ['internal']
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
      console.log('actualChallenge=%s', clientDataObj.challenge);
      console.log('expectedChallenge=%s', this.bufferToBase64URLString(challenge.buffer))

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
      alert('Login success');
    } catch (error) {
      console.error(error);
      alert('Login fail');
    }

    this.setState({ username: '' });
  };

  render() {
    const { loggedIn, username, registerEnabled, loginEnabled } = this.state;

    return (
      <div className="container">
        <div className="center">
          {loggedIn ? (
            <div>
              <h1>Wellcome！</h1>
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
      </div>
    );
  }
}

export default Home;
