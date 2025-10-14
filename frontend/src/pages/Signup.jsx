import React from 'react'
import SignupForm from '../components/SignupForm'

const Signup = () => {
  return (
    <div style={{ maxWidth: 480, margin: '2rem auto', padding: 20 }}>
      <h2>Create an account</h2>
      <SignupForm />
    </div>
  )
}

export default Signup
