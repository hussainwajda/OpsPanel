import React from 'react'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import Auth from './pages/Auth'
import Signup from './pages/Signup'

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/signup" element={<Signup />} />
        {/* Default route shows Auth (login) page; login form is intentionally non-functional */}
        <Route path="*" element={<Auth />} />
      </Routes>
    </Router>
  )
}

export default App