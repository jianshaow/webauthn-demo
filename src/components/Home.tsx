import React, { Component, ChangeEvent, FormEvent, MouseEvent } from 'react';
import * as cbor from 'cbor-x';
import * as utils from '../helpers/utils';
import * as authData from '../helpers/authData';
import './Home.css';

interface HomeState {
  log: string;
  loggedIn: boolean;
  userId: string;
  username: string;
  allowCredentials: PublicKeyCredentialDescriptor[];
  storedCredentials: Credential[];
  displayName: string;
  rpId: string;
  showImport: boolean;
  importCredential: string;
}

interface Credential {
  id: string;
  type: PublicKeyCredentialType;
  userId: string;
  username: string;
  displayName: string;
  rpId: string;
  transports: AuthenticatorTransport[];
  publicKey: string;
  publicKeyAlgorithm: number;
}

class Home extends Component<{}, HomeState> {
  constructor(props: {}) {
    super(props);

    const credentialsJson = localStorage.getItem('credentials');
    let credentials = [];
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
      showImport: false,
      importCredential: ''
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
  }

  handleImportClick = (e: MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    this.setState({ showImport: true });
  };

  handleImportClose = (e: MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    const { storedCredentials, importCredential } = this.state;
    if (!importCredential.length) {
      this.setState({ showImport: false });
      return;
    }
    storedCredentials.push(JSON.parse(importCredential));
    localStorage.setItem('credentials', JSON.stringify(storedCredentials));
    this.setState({ showImport: false, storedCredentials: storedCredentials, importCredential: '' });
  };

  handleImportCredentialChange = (e: ChangeEvent<HTMLInputElement>) => {
    this.setState({ importCredential: e.target.value });
  };

  isCredentialSelected = (credentialId: string) => {
    const { allowCredentials } = this.state;
    return allowCredentials.some(
      (selectedCredential) => utils.bufferToBase64URLString(selectedCredential.id as ArrayBuffer) === credentialId
    );
  };

  deleteCredential = (e: MouseEvent<HTMLButtonElement>) => {
    const { storedCredentials } = this.state;
    const newCredentials = storedCredentials.filter((credential) => credential.id !== (e.target as HTMLButtonElement).id);
    this.setState({ storedCredentials: newCredentials });
    localStorage.setItem('credentials', JSON.stringify(newCredentials));
  };

  regenUserId = (e: MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    this.setState({ userId: utils.generateUUID() });
  };

  handleUsernameChange = (e: ChangeEvent<HTMLInputElement>) => {
    this.setState({ username: e.target.value });
  };

  handleDisplayNameChange = (e: ChangeEvent<HTMLInputElement>) => {
    this.setState({ displayName: e.target.value });
  };

  handleRpIdChange = (e: ChangeEvent<HTMLInputElement>) => {
    this.setState({ rpId: e.target.value });
  };

  handleAllowCredentialsChange = (e: ChangeEvent<HTMLInputElement>) => {
    const { allowCredentials, storedCredentials } = this.state;
    if (e.target.checked) {
      const credential = storedCredentials.filter((candidateCredential) => candidateCredential.id === e.target.value)[0];
      const allowCredential: PublicKeyCredentialDescriptor = {
        type: credential.type,
        id: utils.base64URLStringToBuffer(e.target.value),
        transports: credential.transports
      }
      allowCredentials.push(allowCredential);
      this.setState({ allowCredentials: allowCredentials });
    } else {
      const newCredentials = allowCredentials.filter(
        (selectedCredential) => utils.bufferToBase64URLString(selectedCredential.id as ArrayBuffer) !== e.target.value
      );
      this.setState({ allowCredentials: newCredentials });
    }
  };


  handleRegister = async (e: FormEvent) => {
    e.preventDefault();
    const { username, displayName, userId, rpId, storedCredentials } = this.state;

    try {
      this.appendToLog('Start register...');
      this.appendToLog('username=' + username);
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

      const parsedAuthData = authData.parseAuthenticatorData(new Uint8Array(attestationResponse.getAuthenticatorData()));
      console.log('authData=%o', parsedAuthData);

      if (parsedAuthData.credentialPublicKey) {
        const publicKeyDose = authData.decodeFirst<authData.COSEPublicKey>(parsedAuthData.credentialPublicKey);
        console.log('publicKeyDose=%o', publicKeyDose);
      }

      const pubclicKeyDer = attestationResponse.getPublicKey();
      if (!pubclicKeyDer) {
        throw new Error('no public key');
      }

      const { clientDataJSON, attestationObject } = attestationResponse;

      // verify challenge
      const decodedClientData = utils.bufferToUTF8String(clientDataJSON);
      const clientDataObj = JSON.parse(decodedClientData);
      console.log('clientData=%o', clientDataObj);
      this.appendToLog('actualChallenge=' + clientDataObj.challenge);
      this.appendToLog('expectedChallenge=' + utils.bufferToBase64URLString(challenge.buffer));

      const attestationObj = cbor.decode(new Uint8Array(attestationObject));
      console.log('attestation=%o', attestationObj);
      this.appendToLog('attestationObject.fmt=' + attestationObj.fmt);

      // save credential in state and local storage
      const transports = attestationResponse.getTransports() as AuthenticatorTransport[];
      const credentialToBeStored = {
        id: credential.id,
        type: credential.type as PublicKeyCredentialType,
        userId: userId,
        username: username,
        displayName: displayName,
        rpId: rpId,
        transports: transports,
        publicKey: utils.bufferToBase64URLString(pubclicKeyDer),
        publicKeyAlgorithm: attestationResponse.getPublicKeyAlgorithm()
      };
      storedCredentials.push(credentialToBeStored);
      localStorage.setItem('credentials', JSON.stringify(storedCredentials));
      this.appendToLog('credentialStored=' + JSON.stringify(credentialToBeStored));

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
      this.appendToLog('Start login...');
      this.appendToLog('username=' + username);
      this.appendToLog('storedCredentials.length=' + storedCredentials.length);

      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);
      const getCredentialOptions: CredentialRequestOptions = {
        publicKey: {
          challenge: challenge,
          allowCredentials: allowCredentials,
          userVerification: 'preferred',
        },
      };

      const credential = await navigator.credentials.get(getCredentialOptions) as PublicKeyCredential;
      this.appendToLog('credential.id=' + credential.id);
      this.appendToLog('credential.type=' + credential.type);

      const { authenticatorData, signature, clientDataJSON, userHandle } = credential.response as AuthenticatorAssertionResponse;

      // verify challenge
      const decodedClientData = utils.bufferToUTF8String(clientDataJSON);
      const clientDataObj = JSON.parse(decodedClientData);
      console.log('clientData=%o', clientDataObj);
      this.appendToLog('actualChallenge=' + clientDataObj.challenge);
      this.appendToLog('expectedChallenge=' + utils.bufferToBase64URLString(challenge.buffer));

      if (!userHandle) {
        throw new Error('no user id');
      }

      if (!storedCredentials.length) {
        throw new Error('No credential stored, register first');
      }

      const userId = utils.bufferToUTF8String(userHandle);
      this.appendToLog('userId=' + userId);

      // search credential from storage by userId and credentialId
      const filteredCredentials = storedCredentials.filter(
        (candidateCredential) => candidateCredential.userId === userId && candidateCredential.id === credential.id
      );

      if (!filteredCredentials.length) {
        throw new Error('no stored credential matched by id=' + credential.id + ' and userId=' + userId);
      }
      const registeredCredential = filteredCredentials[0];

      // retrieve public key from attestation that returned from registering before
      const publicKeyDer = utils.base64URLStringToBuffer(registeredCredential.publicKey);
      const algorithm = registeredCredential.publicKeyAlgorithm;
      this.appendToLog('publicKeyAlgorithm=' + algorithm);

      // prepare signature base
      const hashedClientData = await crypto.subtle.digest('SHA-256', clientDataJSON);
      const signatureBase = utils.concat([new Uint8Array(authenticatorData), new Uint8Array(hashedClientData)]);

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
    const { loggedIn, userId, username, storedCredentials, displayName, rpId, log, showImport } = this.state;
    const example = '{"id":"","userId":"","username":"","displayName":"","rpId":"","publicKey":"","publicKeyAlgorithm":-7}';
    return (
      <div className="container">
        <div className="center">
          {loggedIn ? (
            <div>
              <h1>Wellcome, {username}!</h1>
              <button onClick={() => this.setState({ loggedIn: false })}>Logout</button>
            </div>
          ) : (
            <div>
              <h1>Login</h1>
              <form onSubmit={this.handleLogin}>
                <label>Stored Credentials:</label>
                <br />
                <button onClick={this.handleImportClick}>Add Credential</button>
                {showImport && (
                  <div>
                    <input
                      type="text"
                      placeholder={example}
                      onChange={this.handleImportCredentialChange}
                      style={{ width: '60%' }} />
                    <button onClick={this.handleImportClose}>OK</button>
                  </div>
                )}
                <div className='table-container'>
                  <table>
                    <thead>
                      <tr>
                        <th>allowCredentials</th>
                        <th>username</th>
                        <th>action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {storedCredentials.map((credential) => (
                        <tr key={credential.id}>
                          <td>
                            <input type="checkbox"
                              value={credential.id}
                              checked={this.isCredentialSelected(credential.id)}
                              onChange={this.handleAllowCredentialsChange}
                            />
                          </td>
                          <td>{credential.username}</td>
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
                  <input type="text"
                    value={username}
                    onChange={this.handleUsernameChange}
                    style={{ width: '160px' }}
                    autoComplete='username webauthn'
                  />
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
                    <input type="text"
                      value={displayName}
                      onChange={this.handleDisplayNameChange}
                      style={{ width: '160px' }}
                    />
                  </div>
                  <div>
                    <label>RPId: </label>
                    <input type="text" value={rpId} onChange={this.handleRpIdChange} />
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
      <textarea ref={this.logRef} value={log} readOnly rows={10} />
    );
  }
}

export default Home;
