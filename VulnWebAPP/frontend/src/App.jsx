import { useEffect, useState } from 'react'

const defaultUsers = []

export default function App() {
  const [users, setUsers] = useState(defaultUsers)
  const [selectedUserId, setSelectedUserId] = useState('1')
  const [profile, setProfile] = useState(null)
  const [username, setUsername] = useState('Art')
  const [password, setPassword] = useState('admin123')
  const [loginResult, setLoginResult] = useState(null)
  const [status, setStatus] = useState('Loading...')

  useEffect(() => {
    fetch('/api/users')
      .then((response) => response.json())
      .then((data) => {
        setUsers(data)
        setStatus('API connected')
      })
      .catch(() => setStatus('Backend unavailable'))
  }, [])

  async function loadProfile() {
    const response = await fetch('/api/profile', {
      headers: {
        'X-User-ID': selectedUserId
      }
    })
    const data = await response.json()
    setProfile(data)
  }

  async function login(event) {
    event.preventDefault()
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ username, password })
    })
    setLoginResult(await response.json())
  }

  return (
    <main className="shell">
      <section className="hero">
        <p className="eyebrow">Go + React training sandbox</p>
        <h1>Vulnerable full stack app for local security practice</h1>
        <p className="lede">
          Use this UI to observe weak authentication, insecure object lookup, and trust in caller-controlled headers.
        </p>
        <div className="statusRow">
          <span className="statusDot" />
          <span>{status}</span>
        </div>
      </section>

      <section className="grid">
        <article className="card">
          <h2>Login</h2>
          <form onSubmit={login} className="form">
            <label>
              Username
              <input value={username} onChange={(event) => setUsername(event.target.value)} />
            </label>
            <label>
              Password
              <input type="text" value={password} onChange={(event) => setPassword(event.target.value)} />
            </label>
            <button type="submit">Submit</button>
          </form>
          {loginResult ? <pre>{JSON.stringify(loginResult, null, 2)}</pre> : null}
        </article>

        <article className="card">
          <h2>Users</h2>
          <ul className="userList">
            {users.map((user) => (
              <li key={user.id}>
                <button type="button" onClick={() => setSelectedUserId(String(user.id))}>
                  #{user.id} {user.name} - {user.role}
                </button>
              </li>
            ))}
          </ul>
        </article>

        <article className="card wide">
          <h2>Profile viewer</h2>
          <div className="inlineRow">
            <input value={selectedUserId} onChange={(event) => setSelectedUserId(event.target.value)} />
            <button type="button" onClick={loadProfile}>Load profile</button>
          </div>
          {profile ? <pre>{JSON.stringify(profile, null, 2)}</pre> : <p>No profile loaded yet.</p>}
        </article>
      </section>
    </main>
  )
}
