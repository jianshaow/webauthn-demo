import React, { Component, ChangeEvent, FormEvent, MouseEvent } from 'react';
import * as utils from '../helpers/utils';
import * as reg from '../services/register';
import * as authn from '../services/authenticate';
import { CredentialEntity } from '../services/types';
import { setLogger } from '../services/common';
import { getCredentials } from '../services/credential';
import './Home.css';

interface HomeState {
  log: string;
  loggedIn: boolean;
  userId: string;
  username: string;
  allowCredentials: PublicKeyCredentialDescriptor[];
  storedCredentials: CredentialEntity[];
  displayName: string;
  rpId: string;
  showImport: boolean;
  importCredential: string;
}

const defaultState = {
  log: '',
  loggedIn: false,
  userId: '14562550-a677-4832-9add-77527ae332db',
  username: 'John.Smith@TechGenius.com',
  allowCredentials: [],
  rpId: window.location.host.split(':')[0],
  displayName: 'John Smith',
  showImport: false,
  importCredential: ''
}

class Home extends Component<{}, HomeState> {

  constructor(props: {}) {
    super(props);
    this.state = { ...defaultState, storedCredentials: getCredentials() };
    setLogger(this);
  }

  resetState() {
    this.setState({ ...defaultState, storedCredentials: getCredentials() });
  }

  log(message: string) {
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
      this.log('Start register...');
      this.log('username=' + username);
      this.log('userId=' + userId);

      // initialize register to get creation options
      const createCredentialOptions = reg.initRegistration(rpId, userId, username);

      const credential = await navigator.credentials.create(createCredentialOptions) as PublicKeyCredential;
      this.log('credential.id=' + credential.id);
      this.log('credential.type=' + credential.type);
      this.log('credential.authenticatorAttachment=' + credential.authenticatorAttachment);

      // finish register to save credential
      const credentialToBeStored = reg.finishRegistration(credential, rpId, userId, username, displayName);
      storedCredentials.push(credentialToBeStored);
      this.log('credentialStored=' + JSON.stringify(credentialToBeStored));

      this.log('Register success');
    } catch (error) {
      console.error(error);
      alert('Register fail');
      this.log('Error=' + error);
    }

    this.setState({ storedCredentials: storedCredentials });
  };

  handleLogin = async (e: FormEvent) => {
    e.preventDefault();
    const { username, storedCredentials, allowCredentials } = this.state;

    try {
      this.log('Start login...');
      this.log('username=' + username);
      this.log('storedCredentials.length=' + storedCredentials.length);

      // initialize authentication for get options
      const getCredentialOptions = authn.initAuthentication(allowCredentials);

      const credential = await navigator.credentials.get(getCredentialOptions) as PublicKeyCredential;
      this.log('credential.id=' + credential.id);
      this.log('credential.type=' + credential.type);

      // finish authentication for a credential
      const registeredCredential = await authn.finishAuthentication(credential);

      this.setState({ loggedIn: true });
      this.log('Login success');
      this.setState({
        username: registeredCredential.username,
        displayName: registeredCredential.displayName,
        userId: registeredCredential.userId
      });
    } catch (error) {
      console.error(error);
      alert('Login fail');
      this.log('Error=' + error);
    }
  };

  render() {
    const { loggedIn, userId, username, storedCredentials, displayName, rpId, log, showImport } = this.state;
    const example = '{"id":"","userId":"","username":"","displayName":"","rpId":"","publicKey":"","publicKeyAlgorithm":-7}';
    return (
      <div className="container">
        <div className="center">
          {loggedIn ? (
            <div>
              <h1>Wellcome, {displayName}!</h1>
              <button onClick={() => this.resetState()}>Logout</button>
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
