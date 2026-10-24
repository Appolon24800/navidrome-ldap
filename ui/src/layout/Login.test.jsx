import React from 'react'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import Login from './Login'
import config from '../config'

const mocks = vi.hoisted(() => ({
  login: vi.fn(),
  notify: vi.fn(),
  dispatch: vi.fn(),
  redirect: vi.fn(),
  replaceState: vi.fn(),
}))

vi.mock('react-admin', async () => {
  const { createTheme } = await vi.importActual('@material-ui/core/styles')
  return {
    createMuiTheme: createTheme,
    useLogin: () => mocks.login,
    useNotify: () => mocks.notify,
    useTranslate: () => (key) => key,
    useVersion: () => 0,
  }
})
vi.mock('react-redux', () => ({ useDispatch: () => mocks.dispatch }))
vi.mock('./Notification', () => ({ default: () => null }))
vi.mock('../themes/useCurrentTheme', () => ({ default: () => ({}) }))
vi.mock('../utils', () => ({ baseUrl: (path) => `/music${path}` }))
vi.mock('../actions', () => ({ clearQueue: () => ({ type: 'CLEAR_QUEUE' }) }))
vi.mock('../consts.js', () => ({ INSIGHTS_DOC_URL: 'https://example.test' }))
vi.mock('../config', () => ({ default: {} }))

describe('OIDC login-page redirect', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.login.mockResolvedValue({})
    Object.assign(config, {
      firstTime: false,
      oidcEnabled: true,
      oidcAutoRedirect: true,
      oidcDisplayName: 'PocketID',
      loginBackgroundURL: '',
      welcomeMessage: '',
    })
    vi.stubGlobal(
      'window',
      new Proxy(window, {
        get(target, key) {
          if (key === 'location') return { replace: mocks.redirect }
          if (key === 'history') {
            return { state: null, replaceState: mocks.replaceState }
          }
          return Reflect.get(target, key, target)
        },
      }),
    )
  })

  afterEach(() => {
    cleanup()
    vi.unstubAllGlobals()
  })

  const showLogin = (search = '') =>
    render(<Login location={{ search, state: null }} />)

  it('redirects without showing the username/password form', () => {
    showLogin()
    expect(mocks.redirect).toHaveBeenCalledExactlyOnceWith(
      '/music/auth/oidc/login',
    )
    expect(
      document.querySelector('input[name="username"]'),
    ).not.toBeInTheDocument()
    expect(
      document.querySelector('input[name="password"]'),
    ).not.toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveTextContent(
      'ra.auth.oidc_redirecting',
    )
  })

  it('completes a callback instead of starting another authorization', async () => {
    showLogin('?oidc=complete')
    await waitFor(() =>
      expect(mocks.login).toHaveBeenCalledWith({ oidc: true }, '/'),
    )
    expect(mocks.redirect).not.toHaveBeenCalled()
    expect(mocks.replaceState).toHaveBeenCalledWith(null, '', '#/login')
  })

  it('offers an explicit retry after provider failure without a redirect loop', () => {
    const { rerender } = showLogin('?oidc=failed')
    rerender(<Login location={{ search: '', state: null }} />)
    expect(mocks.redirect).not.toHaveBeenCalled()
    expect(mocks.login).not.toHaveBeenCalled()
    expect(screen.getByRole('alert')).toHaveTextContent('ra.auth.oidc_error')
    expect(
      screen.getByRole('link', { name: 'ra.auth.oidc_sign_in' }),
    ).toHaveAttribute('href', '/music/auth/oidc/login')
    expect(
      document.querySelector('input[name="username"]'),
    ).not.toBeInTheDocument()
  })

  it('offers a retry when the session exchange fails', async () => {
    mocks.login.mockRejectedValueOnce(new Error('Unauthorized'))
    showLogin('?oidc=complete')
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(mocks.redirect).not.toHaveBeenCalled()
    expect(
      document.querySelector('input[name="username"]'),
    ).not.toBeInTheDocument()
  })

  it('keeps the ordinary login form when automatic redirect is disabled', () => {
    config.oidcAutoRedirect = false
    showLogin()
    expect(mocks.redirect).not.toHaveBeenCalled()
    expect(document.querySelector('input[name="username"]')).toBeInTheDocument()
    expect(
      screen.getByRole('link', { name: 'ra.auth.oidc_sign_in' }),
    ).toBeInTheDocument()
  })

  it('preserves first-administrator setup on a fresh installation', () => {
    config.firstTime = true
    showLogin()
    expect(mocks.redirect).not.toHaveBeenCalled()
    expect(document.querySelector('input[name="username"]')).toBeInTheDocument()
    expect(
      document.querySelector('input[name="confirmPassword"]'),
    ).toBeInTheDocument()
  })
})
