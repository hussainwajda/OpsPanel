// Simple auth service used by SignupForm. Modify baseUrl to match backend.
const baseUrl = '' // e.g. 'http://localhost:8000' if your backend runs elsewhere

export async function signup({ username, email, password }) {
  const endpoint = baseUrl + '/api/signup'
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, email, password }),
  })

  if (!res.ok) {
    let msg = 'Signup failed'
    try {
      const j = await res.json()
      msg = j.message || msg
    } catch {}
    return { success: false, message: msg }
  }

  const data = await res.json()
  // Expected backend response: { success: true, token: '...', user: {...} }
  return { success: true, token: data.token, user: data.user, message: data.message }
}
