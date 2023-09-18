import './App.css';
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Home from './components/Home';
import Info from './components/Info';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/info" element={<Info />} />
      </Routes>
    </Router>
  );
}

export default App;
