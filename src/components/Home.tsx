import React, { Component, ChangeEvent, FormEvent, MouseEvent } from 'react';
import * as utils from '../helpers/utils';
import * as reg from '../services/register';
import * as authn from '../services/authenticate';
import { CredentialEntity } from '../types/entities';
import { setLogger } from '../services/common';
import { getCredentials, deleteCredential, saveCredential, getCredential } from '../services/credential';
import './Home.css';

interface HomeState {
  log: string;
  loggedIn: boolean;
  userId: string;
  username: string;
  excludeCredentials: PublicKeyCredentialDescriptor[];
  allowCredentials: PublicKeyCredentialDescriptor[];
  storedCredentials: CredentialEntity[];
  displayName: string;
  rpId: string;
  showImport: boolean;
  showCopiedMessage: boolean;
  importCredential: string;
}

const defaultState = {
  log: '',
  loggedIn: false,
  userId: '14562550-a677-4832-9add-77527ae332db',
  username: 'John.Smith@TechGenius.com',
  excludeCredentials: [],
  allowCredentials: [],
  rpId: window.location.host.split(':')[0],
  displayName: 'John Smith',
  showImport: false,
  showCopiedMessage: false,
  importCredential: ''
}

class Home extends Component<{}, HomeState> {

  constructor(props: {}) {
    super(props);
    this.state = { ...defaultState, storedCredentials: getCredentials() };
    setLogger(this);
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

  handleImportClose = (e: MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    const { importCredential } = this.state;
    if (!importCredential.length) {
      this.setState({ showImport: false });
      return;
    }
    const newCredentials = saveCredential(JSON.parse(importCredential));
    this.setState({ showImport: false, storedCredentials: newCredentials, importCredential: '' });
  };

  isAllowCredentialSelected = (credentialId: string) => {
    const { allowCredentials } = this.state;
    return allowCredentials.some(
      (selectedCredential) => utils.bufferToBase64URLString(selectedCredential.id as ArrayBuffer) === credentialId
    );
  };

  isExcludeCredentialSelected = (credentialId: string) => {
    const { excludeCredentials } = this.state;
    return excludeCredentials.some(
      (selectedCredential) => utils.bufferToBase64URLString(selectedCredential.id as ArrayBuffer) === credentialId
    );
  };

  deleteCredential = (e: MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    const credentialId = (e.target as HTMLButtonElement).id.split('.')[1];
    const newCredentials = deleteCredential(credentialId);
    this.setState({ storedCredentials: newCredentials });
  };

  copyCredential = (e: MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    const credentialId = (e.target as HTMLButtonElement).id.split('.')[1];
    const credential = getCredential(credentialId);
    navigator.clipboard.writeText(JSON.stringify(credential));
    this.setState({ showCopiedMessage: true });
    setTimeout(() => {
      this.setState({ showCopiedMessage: false });
    }, 2000);
  };

  handleExcludeCredentialsChange = (e: ChangeEvent<HTMLInputElement>) => {
    const { excludeCredentials, storedCredentials } = this.state;
    if (e.target.checked) {
      const credential = storedCredentials.filter((candidateCredential) => candidateCredential.id === e.target.value)[0];
      const excludeCredential: PublicKeyCredentialDescriptor = {
        type: credential.type,
        id: utils.base64URLStringToBuffer(e.target.value),
        transports: credential.transports
      }
      excludeCredentials.push(excludeCredential);
      this.setState({ excludeCredentials: excludeCredentials });
    } else {
      const newCredentials = excludeCredentials.filter(
        (selectedCredential) => utils.bufferToBase64URLString(selectedCredential.id as ArrayBuffer) !== e.target.value
      );
      this.setState({ excludeCredentials: newCredentials });
    }
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
    const { username, displayName, userId, rpId, storedCredentials, excludeCredentials } = this.state;

    try {
      this.log('Start register...');
      this.log('username=' + username);
      this.log('userId=' + userId);

      // initialize register to get creation options
      const createCredentialOptions = reg.initRegistration(rpId, userId, username, excludeCredentials);

      const credential = await navigator.credentials.create(createCredentialOptions) as PublicKeyCredential;

      // finish register to save credential
      const credentialToBeStored = reg.finishRegistration(credential, rpId, userId, username, displayName);
      storedCredentials.push(credentialToBeStored);

      this.log('Register success');
    } catch (error) {
      console.error(error);
      this.log('Error=' + error);
      alert('Register fail: ' + (error as Error).message);
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
      this.log('Error=' + error);
      alert('Login fail: ' + (error as Error).message);
    }
  };

  render() {
    const { loggedIn, userId, username, storedCredentials, importCredential, displayName, rpId, log, showImport, showCopiedMessage } = this.state;
    const example = 'can be copied from stored credential via click copy button';
    return (
      <div className="container">
        <div className="center">
          {loggedIn ? (
            <div>
              <h1>Wellcome, {displayName}!</h1>
              <button onClick={() => {
                this.setState({ ...defaultState, storedCredentials: getCredentials() });
              }}>Logout</button>
            </div>
          ) : (
            <div>
              <h1>Stored Credentials:</h1>
              <br />
              <button onClick={(e: MouseEvent<HTMLButtonElement>) => {
                e.preventDefault();
                this.setState({ showImport: !showImport });
              }}>Add Credential</button>
              {showImport && (
                <div>
                  <input
                    type="text"
                    placeholder={example}
                    value={importCredential}
                    onChange={(e: ChangeEvent<HTMLInputElement>) => {
                      this.setState({ importCredential: e.target.value });
                    }}
                    style={{ width: '60%' }} />
                  <button onClick={(e: MouseEvent<HTMLButtonElement>) => {
                    e.preventDefault();
                    this.setState({ importCredential: '' });
                  }}>Reset</button>
                  <button onClick={async (e: MouseEvent<HTMLButtonElement>) => {
                    e.preventDefault();
                    this.setState({ importCredential: await navigator.clipboard.readText() });
                  }}>Paste</button>
                  <button onClick={this.handleImportClose}>OK</button>
                </div>
              )}
              <div className='table-container'>
                <table>
                  <thead>
                    <tr>
                      <th>Exclude Credentials </th>
                      <th>Allow Credentials</th>
                      <th>Username</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {storedCredentials.map((credential) => (
                      <tr key={credential.id}>
                        <td>
                          <input type="checkbox"
                            value={credential.id}
                            checked={this.isExcludeCredentialSelected(credential.id)}
                            onChange={this.handleExcludeCredentialsChange}
                          />
                        </td>
                        <td>
                          <input type="checkbox"
                            value={credential.id}
                            checked={this.isAllowCredentialSelected(credential.id)}
                            onChange={this.handleAllowCredentialsChange}
                          />
                        </td>
                        <td>{credential.username}</td>
                        <td>
                          <button id={'del.' + credential.id} onClick={this.deleteCredential}>Delete</button>
                          <button id={'cpy.' + credential.id} onClick={this.copyCredential}>Copy</button>
                          {showCopiedMessage && 'Copied'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <h1>Login</h1>
              <form onSubmit={this.handleLogin}>
                <div>
                  <label> Username: </label>
                  <input type="text"
                    value={username}
                    onChange={(e: ChangeEvent<HTMLInputElement>) => {
                      this.setState({ username: e.target.value });
                    }}
                    style={{ width: '180px' }}
                    autoComplete='username webauthn'
                  />
                  <button onClick={(e: MouseEvent<HTMLButtonElement>) => {
                    e.preventDefault();
                    this.setState({ username: defaultState.username });
                  }}>Reset</button>
                  <button onClick={async (e: MouseEvent<HTMLButtonElement>) => {
                    e.preventDefault();
                    this.setState({ username: await navigator.clipboard.readText() });
                  }}>Paste</button>
                </div>
                <button type="submit" disabled={!storedCredentials.length}>Passkey Login</button>
              </form>
              <div>
                <br />
                <h1>Register</h1>
                <form onSubmit={this.handleRegister}>
                  <div>
                    <label> UserId: </label>
                    <input type="text" value={userId} readOnly style={{ width: '260px' }} />
                    <button onClick={(e: MouseEvent<HTMLButtonElement>) => {
                      e.preventDefault();
                      this.setState({ userId: defaultState.userId });
                    }}>Reset</button>
                    <button onClick={async (e: MouseEvent<HTMLButtonElement>) => {
                      e.preventDefault();
                      this.setState({ userId: await navigator.clipboard.readText() });
                    }}>Paste</button>
                    <button onClick={(e: MouseEvent<HTMLButtonElement>) => {
                      e.preventDefault();
                      this.setState({ userId: utils.generateUUID() });
                    }}>Regen</button>
                  </div>
                  <div>
                    <label> DisplayName: </label>
                    <input type="text"
                      value={displayName}
                      onChange={(e: ChangeEvent<HTMLInputElement>) => {
                        this.setState({ displayName: e.target.value });
                      }}
                      style={{ width: '160px' }}
                    />
                    <button onClick={(e: MouseEvent<HTMLButtonElement>) => {
                      e.preventDefault();
                      this.setState({ displayName: defaultState.displayName });
                    }}>Reset</button>
                    <button onClick={async (e: MouseEvent<HTMLButtonElement>) => {
                      e.preventDefault();
                      this.setState({ displayName: await navigator.clipboard.readText() });
                    }}>Paste</button>
                  </div>
                  <div>
                    <label>RPId: </label>
                    <input type="text" value={rpId} onChange={(e: ChangeEvent<HTMLInputElement>) => {
                      this.setState({ rpId: e.target.value });
                    }} />
                    <button onClick={(e: MouseEvent<HTMLButtonElement>) => {
                      e.preventDefault();
                      this.setState({ rpId: defaultState.rpId });
                    }}>Reset</button>
                    <button onClick={async (e: MouseEvent<HTMLButtonElement>) => {
                      e.preventDefault();
                      this.setState({ rpId: await navigator.clipboard.readText() });
                    }}>Paste</button>
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
          <div>
            <button onClick={(e: MouseEvent<HTMLButtonElement>) => {
              e.preventDefault();
              this.setState({ log: '' });
            }}>Clear</button>
            <button onClick={async (e: MouseEvent<HTMLButtonElement>) => {
              e.preventDefault();
              navigator.clipboard.writeText(log);
            }}>Copy</button>
          </div>
        </div>
      </div>
    );
  }
}

interface LogViewerProps {
  log: string;
}

class LogViewer extends Component<LogViewerProps> {
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
