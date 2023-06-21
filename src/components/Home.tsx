import React, { Component, ChangeEvent, FormEvent } from 'react';
import * as cbor from 'cbor-web'

interface HomeState {
  loggedIn: boolean;
  username: string;
  credential: PublicKeyCredential|null;
  registerEnabled: boolean;
  loginEnabled: boolean;
}

class Home extends Component<{}, HomeState> {
  constructor(props: {}) {
    super(props);
    this.state = {
      loggedIn: false,
      username: '',
      credential: null,
      registerEnabled: false,
      loginEnabled: false,
    };
  }

  handleUsernameChange = (e: ChangeEvent<HTMLInputElement>) => {
    this.setState({ username: e.target.value });
  };

  handleRegister = async (e: FormEvent) => {
    e.preventDefault();
    const { username } = this.state;
    const challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);

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
      console.log('credentialId=%s', credential.id)

      const response = credential.response as AuthenticatorAttestationResponse;

      const utf8Decoder = new TextDecoder('utf-8');
      const decodedClientData = utf8Decoder.decode(response.clientDataJSON);
      const clientDataObj = JSON.parse(decodedClientData);
      console.log('clientData=%o', clientDataObj)

      const decodedAttestationObj = cbor.decode(response.attestationObject);
      console.log('attestation=%o', decodedAttestationObj)

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
    window.crypto.getRandomValues(challenge);

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

      if (credential != null) {
        const response = credential.response as AuthenticatorAttestationResponse;
        const publicKey = response.getPublicKey();
        console.log('publicKey=%s', publicKey)
      }

      const assertion = await navigator.credentials.get(getCredentialOptions) as PublicKeyCredential;
      
      const response = assertion.response as AuthenticatorAssertionResponse;
      console.log('signature=%s', response.signature)

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
      <div>
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
    );
  }
}

export default Home;
