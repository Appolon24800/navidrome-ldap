import { beforeEach, describe, expect, it, vi } from 'vitest'
import authProvider from './authProvider'
import config from './config'

vi.mock('./config', () => ({ default: { firstTime: false } }))
vi.mock('./utils', () => ({ baseUrl: (path) => `/music${path}` }))
vi.mock('jwt-decode', () => ({ jwtDecode: () => ({ uid: 'existing-user' }) }))

describe('web authentication', () => {
  beforeEach(() => {
    config.firstTime = false
    localStorage.clear()
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        status: 200,
        json: async () => ({
          token: 'navidrome-session',
          id: 'existing-user',
          username: 'alice',
          name: 'Alice',
          isAdmin: false,
          subsonicSalt: 'salt',
          subsonicToken: 'legacy-token',
        }),
      }),
    )
    // Node's Request requires an absolute URL, while the browser accepts baseUrl.
    vi.stubGlobal(
      'Request',
      class {
        constructor(url, options) {
          this.url = url
          Object.assign(this, options)
        }
      },
    )
  })

  afterEach(() => vi.unstubAllGlobals())

  it('exchanges the HttpOnly OIDC handoff for a normal Navidrome session', async () => {
    await authProvider.login({ oidc: true })
    const request = fetch.mock.calls[0][0]
    expect(request.url).toBe('/music/auth/oidc/session')
    expect(request.method).toBe('POST')
    expect(request.credentials).toBe('same-origin')
    expect(request.body).toBe('{}')
    expect(localStorage.getItem('token')).toBe('navidrome-session')
    expect(localStorage.getItem('userId')).toBe('existing-user')
    expect(localStorage.getItem('is-authenticated')).toBe('true')
  })

  it('keeps password login on its existing endpoint', async () => {
    await authProvider.login({ username: 'alice', password: 'password' })
    const request = fetch.mock.calls[0][0]
    expect(request.url).toBe('/music/auth/login')
    expect(JSON.parse(request.body)).toEqual({
      username: 'alice',
      password: 'password',
    })
  })

  it('does not authenticate when the OIDC handoff is rejected', async () => {
    fetch.mockResolvedValue({ status: 401, statusText: 'Unauthorized' })
    await expect(authProvider.login({ oidc: true })).rejects.toThrow()
    expect(localStorage.getItem('is-authenticated')).toBeNull()
    expect(localStorage.getItem('token')).toBeNull()
  })
})
