import { Component } from 'react';
import { Link } from 'react-router-dom';
import './Common.css';
import './Info.css';

class Info extends Component<{}> {
  constructor(props: {}) {
    super(props);
  }

  getLocationInfo() {
    let longitude = 0;
    let latitude = 0;
    if ("geolocation" in navigator) {
      navigator.geolocation.getCurrentPosition(function (position) {
        latitude = position.coords.latitude;
        longitude = position.coords.longitude;
        console.log(`longitude: ${longitude}, latitude: ${latitude}`);
      }, function (error) {
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

  render() {
    const { longitude, latitude } = this.getLocationInfo();
    const { isOnline } = this.getNetworkInfo();
    return (
      <div className='container'>
        <Link to="/">Return Home</Link>
        <div className="center">
          <h1>Device Information</h1>
          <nav className='navbar'>
            <ul>
              <li>Location: ({longitude}, {latitude})</li>
              <li>Online: {isOnline ? <div className="green-dot"></div> : <div className="red-dot"></div>}</li>
            </ul>
          </nav>
        </div>
      </div>
    );
  }
}

export default Info;