import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { signup } from '../utils/authService'

const SignupForm = () => {
  const navigate = useNavigate()
  const [form, setForm] = useState({ username: '', email: '', password: '', confirmPassword: '' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const onChange = (e) => {
    setForm(prev => ({ ...prev, [e.target.name]: e.target.value }))
    setError('')
  }

  const validate = () => {
    if (!form.username.trim()) return 'Username is required'
    if (!form.email.trim()) return 'Email is required'
    const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRe.test(form.email)) return 'Email is invalid'
    if (form.password.length < 6) return 'Password must be at least 6 characters'
    if (form.password !== form.confirmPassword) return 'Passwords do not match'
    return null
  }

  const onSubmit = async (e) => {
    e.preventDefault()
    const v = validate()
    if (v) {
      setError(v)
      return
    }

    setLoading(true)
    setError('')
    try {
      const res = await signup({
        username: form.username.trim(),
        email: form.email.trim(),
        password: form.password,
      })

      if (res && res.success) {
        if (res.token) localStorage.setItem('auth_token', res.token)
        navigate('/', { replace: true })
      } else {
        setError(res.message || 'Signup failed')
      }
    } catch (err) {
      setError(err?.message || 'Network error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={onSubmit} style={{ display: 'grid', gap: 12 }}>
      {error && <div style={{ color: 'crimson' }}>{error}</div>}

      <label>
        <div>Username</div>
        <input name="username" value={form.username} onChange={onChange} required />
      </label>

      <label>
        <div>Email</div>
        <input name="email" type="email" value={form.email} onChange={onChange} required />
      </label>

      <label>
        <div>Password</div>
        <input name="password" type="password" value={form.password} onChange={onChange} required />
      </label>

      <label>
        <div>Confirm Password</div>
        <input name="confirmPassword" type="password" value={form.confirmPassword} onChange={onChange} required />
      </label>

      <button type="submit" disabled={loading}>{loading ? 'Signing up...' : 'Sign up'}</button>
    </form>
  )
}

export default SignupForm
