import React from 'react'

const LoginForm = () => {
  return (
    <form style={{ display: 'grid', gap: 12 }}>
      <label>
        <div>Email</div>
        <input name="email" type="email" />
      </label>

      <label>
        <div>Password</div>
        <input name="password" type="password" />
      </label>

      {/* Intentionally non-functional: no submit handler */}
      <button type="button">Log in (non-working)</button>
    </form>
  )
}

export default LoginForm
