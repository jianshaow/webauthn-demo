import { Component } from 'react';
import { Link } from 'react-router-dom';
import { UAParser } from 'ua-parser-js';
import './Common.css';
import './Info.css';

interface InfoState {
  position: string;
  online: boolean;
  browser: string;
  os: string;
  device: string;
  engine: string;
  cpu: string | undefined;
}

class Info extends Component<{}, InfoState> {
  constructor(props: {}) {
    super(props);
    const { isOnline } = this.getNetworkInfo();
    const { device, browser, os, engine, cpu } = this.getBrowserInfo();
    this.state = {
      position: '(-/-)',
      online: isOnline,
      browser: browser.name + '/' + browser.version,
      os: os.name + '/' + os.version,
      device: device.type + '/' + device.vendor + '/' + device.model,
      engine: engine.name + '/' + engine.version,
      cpu: cpu.architecture
    };
  }

  getPositionInfo() {
    if ('geolocation' in navigator) {
      const component = this;
      navigator.geolocation.getCurrentPosition(
        function (position) {
          const latitude = position.coords.latitude;
          const longitude = position.coords.longitude;
          component.setState({ position: '(' + longitude + ', ' + latitude + ')' });
        },
        function (error) {
          let msg = '';
          switch (error.code) {
            case error.PERMISSION_DENIED:
              msg = 'Permission denied';
              break;
            case error.POSITION_UNAVAILABLE:
              msg = 'Position unavailable';
              break;
            case error.TIMEOUT:
              msg = 'Timeout';
              break;
            default:
              msg = 'unknown error';
          }
          alert('Get posistion fail: ' + msg);
        });
    } else {
      console.error("Get position not suport");
    }
  }

  getNetworkInfo() {
    const isOnline = navigator.onLine;
    return { isOnline };
  }

  getBrowserInfo() {
    const parser = new UAParser();
    const result = parser.getResult();
    console.info(result);
    return result;
  }

  render() {
    const { position, online, browser, os, device, engine, cpu } = this.state;

    return (
      <div className='container'>
        <div className='header'>
          <Link to="/">Return Home</Link>
        </div>
        <div className="center">
          <h1>Device Information</h1>
          <nav className='navbar'>
            <ul>
              <li>Location: {position}
                <button onClick={() => {
                  this.getPositionInfo();
                }}>Get Location</button></li>
              <li>Online: {online ? <div className="green-dot"></div> : <div className="red-dot"></div>}</li>
              <li>Browser: {browser}</li>
              <li>OS: {os}</li>
              <li>Device: {device}</li>
              <li>Engine: {engine}</li>
              <li>CPU: {cpu}</li>
            </ul>
          </nav>
        </div>
      </div>
    );
  }
}

export default Info;