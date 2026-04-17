export type AuthUser = {
  email: string
  role: string
}

export const API_BASE_URL = 'http://localhost:5000'

const TOKEN_KEY = 'auth_token'
const USER_KEY = 'auth_user'

type JwtPayload = {
  exp?: number
  role?: string
  sub?: string
}

function parseJwtPayload(token: string): JwtPayload | null {
  const parts = token.split('.')
  if (parts.length < 2) {
    return null
  }

  try {
    const payload = parts[1]
    const normalized = payload.replace(/-/g, '+').replace(/_/g, '/')
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=')
    const decoded = window.atob(padded)
    return JSON.parse(decoded) as JwtPayload
  } catch {
    return null
  }
}

function getRemainingTokenSeconds(token: string): number {
  const payload = parseJwtPayload(token)
  if (!payload || typeof payload.exp !== 'number') {
    return 86400
  }

  const remaining = payload.exp - Math.floor(Date.now() / 1000)
  return Math.max(0, remaining)
}

function setAuthCookies(role: string, maxAgeSeconds: number): void {
  const safeRole = encodeURIComponent(role)
  document.cookie = `auth_role=${safeRole}; path=/; max-age=${maxAgeSeconds}; samesite=lax`
  document.cookie = `auth_token_present=1; path=/; max-age=${maxAgeSeconds}; samesite=lax`
}

export function getStoredToken(): string | null {
  if (typeof window === 'undefined') {
    return null
  }

  const token = window.localStorage.getItem(TOKEN_KEY)
  if (!token) {
    return null
  }

  const remainingSeconds = getRemainingTokenSeconds(token)
  if (remainingSeconds <= 0) {
    clearAuthStorage()
    return null
  }

  return token
}

export function getStoredUser(): AuthUser | null {
  if (typeof window === 'undefined') {
    return null
  }

  const raw = window.localStorage.getItem(USER_KEY)
  if (!raw) {
    return null
  }

  try {
    return JSON.parse(raw) as AuthUser
  } catch {
    return null
  }
}

export function clearAuthStorage(): void {
  if (typeof window === 'undefined') {
    return
  }

  window.localStorage.removeItem(TOKEN_KEY)
  window.localStorage.removeItem(USER_KEY)
  window.localStorage.removeItem('auth_email')
  window.localStorage.removeItem('auth_role')
  document.cookie = 'auth_role=; path=/; max-age=0; samesite=lax'
  document.cookie = 'auth_token_present=; path=/; max-age=0; samesite=lax'
}

export function hasAuthPresenceCookie(): boolean {
  if (typeof document === 'undefined') {
    return false
  }

  return document.cookie
    .split(';')
    .map((part) => part.trim())
    .some((part) => part === 'auth_token_present=1')
}

export function syncAuthSessionFromStorage(): boolean {
  if (typeof window === 'undefined') {
    return false
  }

  const token = getStoredToken()
  if (!token) {
    clearAuthStorage()
    return false
  }

  const user = getStoredUser()
  const payload = parseJwtPayload(token)
  const role = user?.role || (typeof payload?.role === 'string' ? payload.role : 'user')
  const remainingSeconds = getRemainingTokenSeconds(token)

  if (remainingSeconds <= 0) {
    clearAuthStorage()
    return false
  }

  setAuthCookies(role, remainingSeconds)
  return true
}

export function storeAuthSession(token: string, fallbackEmail?: string): AuthUser {
  const payload = parseJwtPayload(token)
  const role = typeof payload?.role === 'string' ? payload.role : 'user'
  const emailFromToken = typeof payload?.sub === 'string' ? payload.sub : ''
  const email = (emailFromToken || fallbackEmail || '').toLowerCase()

  const user: AuthUser = {
    email,
    role,
  }

  window.localStorage.setItem(TOKEN_KEY, token)
  window.localStorage.setItem(USER_KEY, JSON.stringify(user))
  window.localStorage.setItem('auth_email', email)
  window.localStorage.setItem('auth_role', role)

  const remainingSeconds = getRemainingTokenSeconds(token)
  setAuthCookies(role, remainingSeconds)

  return user
}

export function getAuthHeader(): Record<string, string> {
  const token = getStoredToken()
  if (!token) {
    return {}
  }

  return {
    Authorization: `Bearer ${token}`,
  }
}
