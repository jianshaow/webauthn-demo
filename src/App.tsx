import './App.css';
import { BrowserRouter as Router, Link, Routes, Route } from "react-router-dom";
import Home from './components/Home';

function App() {
  return (
    <Router>
      <ul>
        <li>
          <Link to="/home">Home</Link>
        </li>
      </ul>
      <Routes>
        <Route path="/home" element={<Home />}></Route>
      </Routes>
    </Router>
  );
}

export default App;
