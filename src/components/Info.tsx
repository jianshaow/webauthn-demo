import { Component } from 'react';
import { Link } from 'react-router-dom';
import { UAParser } from 'ua-parser-js';
import './Common.css';
import './Info.css';

interface InfoState {
  longitude: number;
  latitude: number;
}

class Info extends Component<{}, InfoState> {
  constructor(props: {}) {
    super(props);
    this.state = { longitude: 0, latitude: 0 };
  }

  setPosition(position: GeolocationPosition) {
    const latitude = position.coords.latitude;
    const longitude = position.coords.longitude;
    this.setState({ longitude: longitude, latitude: latitude });
  };

  getLocationInfo() {
    let longitude = 0;
    let latitude = 0;
    if ("geolocation" in navigator) {
      navigator.geolocation.getCurrentPosition(this.setPosition, function (error) {
        switch (error.code) {
          case error.PERMISSION_DENIED:
            console.error("Permission denied");
            break;
          case error.POSITION_UNAVAILABLE:
            console.error("Position unavailable");
            break;
          case error.TIMEOUT:
            console.error("Timeout");
            break;
        }
      });
    } else {
      console.error("Get position not suport");
    }
    return { longitude, latitude };
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
    const { longitude, latitude } = this.state;

    this.getLocationInfo();
    const { isOnline } = this.getNetworkInfo();
    const { device, browser, os, engine, cpu } = this.getBrowserInfo();
    return (
      <div className='container'>
        <div className='header'>
          <Link to="/">Return Home</Link>
        </div>
        <div className="center">
          <h1>Device Information</h1>
          <nav className='navbar'>
            <ul>
              <li>Location: ({longitude}, {latitude})</li>
              <li>Online: {isOnline ? <div className="green-dot"></div> : <div className="red-dot"></div>}</li>
              <li>Browser: {browser.name}/{browser.version}</li>
              <li>OS: {os.name}/{os.version}</li>
              <li>Device: {device.type}/{device.model}/{device.vendor}</li>
              <li>Engine: {engine.name}/{engine.version}</li>
              <li>CPU: {cpu.architecture}</li>
            </ul>
          </nav>
        </div>
      </div>
    );
  }
}

export default Info;