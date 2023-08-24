import React, { Component, ChangeEvent, FormEvent, MouseEvent, SyntheticEvent } from 'react';
import * as utils from '../helpers/utils';
import * as reg from '../services/register';
import * as authn from '../services/authenticate';
import { CredentialEntity } from '../types/entities';
import { setLogger } from '../services/common';
import { getCredentials, deleteCredential, saveCredential, getCredential } from '../services/credential';
import './Home.css';

interface HomeState {
  logs: string;
  loggedIn: boolean;
  userId: string;
  username: string;
  displayName: string;
  authnUserVerification: string;
  excludeCredentials: PublicKeyCredentialDescriptor[];
  allowCredentials: PublicKeyCredentialDescriptor[];
  storedCredentials: CredentialEntity[];
  rpId: string;
  requireResidentKey: boolean;
  residentKey: string;
  attestation: string;
  regUserVerification: string;
  authenticatorAttachment: string;
  showImport: boolean;
  showCopiedMessage: boolean;
  copiedCredentialId: string;
  importCredential: string;
}

const defaultUser = {
  userId: '14562550-a677-4832-9add-77527ae332db',
  username: 'John.Smith@TechGenius.com',
  displayName: 'John Smith'
}

const defaultState = {
  loggedIn: false,
  userId: '',
  username: '',
  displayName: '',
  authnUserVerification: 'preferred',
  excludeCredentials: [],
  allowCredentials: [],
  rpId: window.location.hostname,
  attestation: 'direct',
  requireResidentKey: false,
  residentKey: 'preferred',
  regUserVerification: 'preferred',
  authenticatorAttachment: 'platform',
  showImport: false,
  showCopiedMessage: false,
  copiedCredentialId: '',
  importCredential: '',
}

class Home extends Component<{}, HomeState> {

  autofillAbortController: AbortController | undefined = undefined;
  autofillPending = false;

  constructor(props: {}) {
    super(props);
    const storedCredentials = getCredentials();
    if (storedCredentials.length) {
      this.state = { ...defaultState, storedCredentials: getCredentials(), logs: '' };
    } else {
      this.state = { ...defaultState, ...defaultUser, storedCredentials: getCredentials(), logs: '' };
    }
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
    this.setState(prevState => ({ logs: prevState.logs + logEntry + '\n' }));
  }

  isAllowCredentialSelected(credentialId: string) {
    const { allowCredentials } = this.state;
    return allowCredentials.some(
      (selectedCredential) => utils.bufferToBase64URLString(selectedCredential.id as ArrayBuffer) === credentialId
    );
  };

  isExcludeCredentialSelected(credentialId: string) {
    const { excludeCredentials } = this.state;
    return excludeCredentials.some(
      (selectedCredential) => utils.bufferToBase64URLString(selectedCredential.id as ArrayBuffer) === credentialId
    );
  };

  handleImportClose = (e: MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    const { importCredential } = this.state;
    if (!importCredential.length) {
      this.setState({ showImport: false });
      return;
    }
    const newCredentials = saveCredential(JSON.parse(importCredential));
    this.setState({ ...defaultState, storedCredentials: newCredentials });
  };

  deleteCredential = (e: MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    const credentialId = (e.target as HTMLButtonElement).id.split('.')[1];
    const newCredentials = deleteCredential(credentialId);
    if (newCredentials.length) {
      this.setState({ ...defaultState, storedCredentials: newCredentials });
    } else {
      this.setState({ ...defaultState, ...defaultUser, storedCredentials: newCredentials });
    }
  };

  copyCredential = (e: MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    const credentialId = (e.target as HTMLButtonElement).id.split('.')[1];
    const credential = getCredential(credentialId);
    navigator.clipboard.writeText(JSON.stringify(credential));
    this.setState({ showCopiedMessage: true, copiedCredentialId: credentialId });
    setTimeout(() => {
      this.setState({ showCopiedMessage: false, copiedCredentialId: '' });
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
    const { username, displayName, userId, rpId, requireResidentKey, residentKey, regUserVerification, authenticatorAttachment, attestation, storedCredentials, excludeCredentials } = this.state;

    try {
      this.log('Start register...');
      this.log('username=' + username);
      this.log('userId=' + userId);

      if (this.autofillPending && this.autofillAbortController) {
        this.autofillAbortController.abort('explicit.register');
      }

      // initialize register to get creation options
      const publicKey = reg.initRegistration(
        rpId,
        userId,
        username,
        displayName,
        requireResidentKey,
        residentKey as ResidentKeyRequirement,
        regUserVerification as UserVerificationRequirement,
        authenticatorAttachment as AuthenticatorAttachment,
        attestation as AttestationConveyancePreference,
        excludeCredentials
      );
      const createCredentialOptions: CredentialCreationOptions = { publicKey: publicKey }

      const credential = await navigator.credentials.create(createCredentialOptions) as PublicKeyCredential;

      // finish register to save credential
      const credentialToBeStored = reg.finishRegistration(credential, rpId, userId, username, displayName);
      storedCredentials.push(credentialToBeStored);

      this.setState({ ...defaultState, storedCredentials: storedCredentials });
      this.log('Register success');
    } catch (error) {
      console.error(error);
      this.log('Error=' + error);
      alert('Register fail: ' + (error as Error).message);
    }
  };

  handleLogin = async (e: FormEvent) => {
    e.preventDefault();
    const { username, storedCredentials, allowCredentials, authnUserVerification } = this.state;

    try {
      this.log('Start login...');
      this.log('username=' + username);
      this.log('storedCredentials.length=' + storedCredentials.length);

      if (this.autofillPending && this.autofillAbortController) {
        this.autofillAbortController.abort('explicit.login');
      }

      // initialize authentication for get options
      const publicKey = authn.initAuthentication(allowCredentials, authnUserVerification as UserVerificationRequirement);
      const getCredentialOptions: CredentialRequestOptions = { publicKey: publicKey };

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

  handleAutofill = async (e: MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    const { allowCredentials, authnUserVerification } = this.state;

    try {
      if (this.autofillPending) {
        this.log('There is a autofill request on pending');
        return;
      }
      this.log('Start autofill login...');

      // initialize authentication for get options
      const publicKey = authn.initAuthentication(allowCredentials, authnUserVerification as UserVerificationRequirement);
      this.autofillAbortController = new AbortController();
      const getCredentialOptions: CredentialRequestOptions = {
        publicKey: publicKey,
        mediation: 'conditional' as CredentialMediationRequirement,
        signal: this.autofillAbortController.signal
      };

      this.autofillPending = true;
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
      if (error === 'explicit.login' ||
        error === 'explicit.register' ||
        (error as DOMException).name === 'AbortError') {
        this.log('Autofill login canceled by ' + error);
      } else {
        alert('Login fail: ' + (error as Error).message);
      }
    }
    this.autofillPending = false;
  }

  renderLoggedIn() {
    const { displayName } = this.state;
    return (
      <div>
        <h1>Wellcome, {displayName}!</h1>
        <button onClick={() => {
          this.setState({ ...defaultState, storedCredentials: getCredentials() });
        }}>Logout</button>
      </div>
    );
  }

  renderStoredCredentials() {
    const { storedCredentials, importCredential, showImport, showCopiedMessage, copiedCredentialId } = this.state;
    const hints = 'can be copied from stored credential via click copy button';
    return (
      <div>
        <h1>Stored Credentials:</h1>
        <div>
          <button onClick={(e: MouseEvent<HTMLButtonElement>) => {
            e.preventDefault();
            this.setState({ showImport: !showImport });
          }}>Add Credential</button>
        </div>
        {showImport && (
          <div>
            <input
              type="text"
              placeholder={hints}
              value={importCredential}
              onChange={(e: ChangeEvent<HTMLInputElement>) => {
                this.setState({ importCredential: e.target.value });
              }}
              style={{ width: '60%' }}
            />
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
                    {showCopiedMessage && copiedCredentialId === credential.id && 'Copied'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  }

  renderLogin() {
    const { username, authnUserVerification, storedCredentials } = this.state;
    return (
      <div>
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
          <div>
            <label> UserVerification: </label>
            <select value={authnUserVerification} onChange={(e: ChangeEvent<HTMLSelectElement>) => {
              this.setState({ authnUserVerification: e.target.value })
            }}>
              <option key='discouraged' value='discouraged'>discouraged</option>
              <option key='preferred' value='preferred'>preferred</option>
              <option key='required' value='required'>required</option>
            </select>
          </div>
          <div>
            <button type="submit" disabled={!storedCredentials.length}>Passkey Login</button>
            <button disabled={!storedCredentials.length} onClick={this.handleAutofill}>Passkey Autofill</button>
          </div>
        </form>
      </div>
    );
  }

  renderRegister() {
    const { userId, displayName, rpId, requireResidentKey, residentKey, regUserVerification, authenticatorAttachment, attestation } = this.state;
    return (
      <div>
        <h1>Register</h1>
        <form onSubmit={this.handleRegister}>
          <div>
            <button onClick={(e: MouseEvent<HTMLButtonElement>) => {
              e.preventDefault();
              this.setState({ ...defaultUser });
            }}>Fill in Default User</button>
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
            <label> RequireResidentKey: </label>
            <input type="checkbox"
              checked={requireResidentKey}
              onChange={(e: ChangeEvent<HTMLInputElement>) => {
                this.setState({ requireResidentKey: e.target.checked });
              }}
            />
          </div>
          <div>
            <label> ResidentKey: </label>
            <select value={residentKey} onChange={(e: ChangeEvent<HTMLSelectElement>) => {
              this.setState({ residentKey: e.target.value })
            }}>
              <option key='discouraged' value='discouraged'>discouraged</option>
              <option key='preferred' value='preferred'>preferred</option>
              <option key='required' value='required'>required</option>
            </select>
          </div>
          <div>
            <label> UserVerification: </label>
            <select value={regUserVerification} onChange={(e: ChangeEvent<HTMLSelectElement>) => {
              this.setState({ regUserVerification: e.target.value })
            }}>
              <option key='discouraged' value='discouraged'>discouraged</option>
              <option key='preferred' value='preferred'>preferred</option>
              <option key='required' value='required'>required</option>
            </select>
          </div>
          <div>
            <label> AuthenticatorAttachment: </label>
            <select value={authenticatorAttachment} onChange={(e: ChangeEvent<HTMLSelectElement>) => {
              this.setState({ authenticatorAttachment: e.target.value })
            }}>
              <option key='platform' value='platform'>platform</option>
              <option key='cross-platform' value='cross-platform'>cross-platform</option>
            </select>
          </div>
          <div>
            <label> Attestation: </label>
            <select value={attestation} onChange={(e: ChangeEvent<HTMLSelectElement>) => {
              this.setState({ attestation: e.target.value })
            }}>
              <option key='direct' value='direct'>direct</option>
              <option key='enterprise' value='enterprise'>enterprise</option>
              <option key='indirect' value='indirect'>indirect</option>
              <option key='none' value='none'>none</option>
            </select>
          </div>
          <div>
            <button type="submit">Register Passkey</button>
          </div>
        </form>
      </div>
    );
  }

  renderLogViewer() {
    const { logs } = this.state;
    return (
      <div className="center">
        <LogViewer log={logs} />
        <div>
          <button onClick={(e: MouseEvent<HTMLButtonElement>) => {
            e.preventDefault();
            this.setState({ logs: '' });
          }}>Clear</button>
          <button onClick={async (e: MouseEvent<HTMLButtonElement>) => {
            e.preventDefault();
            navigator.clipboard.writeText(logs);
          }}>Copy</button>
        </div>
      </div>
    );
  }

  render() {
    const { loggedIn } = this.state;
    return (
      <div className="container">
        <div className="center">
          {loggedIn ?
            this.renderLoggedIn()
            : (
              <div>
                {this.renderStoredCredentials()}
                {this.renderLogin()}
                {this.renderRegister()}
              </div>
            )
          }
        </div>
        <div className="divider" />
        {this.renderLogViewer()}
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
