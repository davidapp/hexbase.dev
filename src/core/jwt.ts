import { base64ToBytes } from './encode'

export interface JwtParts {
  header: Record<string, unknown>
  payload: Record<string, unknown>
  signatureB64: string
  raw: { header: string; payload: string; signature: string }
}

export const JWT_CLAIM_NOTES: Record<string, string> = {
  iss: 'Issuer — who created and signed the token',
  sub: 'Subject — whom the token is about (usually a user id)',
  aud: 'Audience — intended recipient(s)',
  exp: 'Expiration time (Unix seconds) — reject after this',
  nbf: 'Not before (Unix seconds) — reject before this',
  iat: 'Issued at (Unix seconds)',
  jti: 'JWT ID — unique identifier, useful for revocation',
  alg: 'Signature algorithm (header)',
  typ: 'Token type (header)',
  kid: 'Key ID — which key signed this (header)',
  scope: 'OAuth scopes granted',
  azp: 'Authorized party (OpenID Connect)',
  nonce: 'Replay-protection value (OpenID Connect)',
}

export function decodeJwt(token: string): JwtParts {
  const parts = token.trim().split('.')
  if (parts.length !== 3) {
    throw new Error(`a JWT has 3 dot-separated sections (header.payload.signature); got ${parts.length}`)
  }
  const [h, p, s] = parts
  const decodeSection = (seg: string, what: string): Record<string, unknown> => {
    let json: string
    try {
      json = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(base64ToBytes(seg))
    } catch {
      throw new Error(`${what} is not valid base64url`)
    }
    try {
      const v = JSON.parse(json)
      if (typeof v !== 'object' || v === null) throw new Error()
      return v as Record<string, unknown>
    } catch {
      throw new Error(`${what} is not a valid JSON object`)
    }
  }
  return {
    header: decodeSection(h, 'header'),
    payload: decodeSection(p, 'payload'),
    signatureB64: s,
    raw: { header: h, payload: p, signature: s },
  }
}

/** Verify an HS256/HS384/HS512 signature with a shared secret. */
export async function verifyJwtHmac(token: string, secret: string): Promise<boolean> {
  const { header, raw } = decodeJwt(token)
  const alg = String(header.alg ?? '')
  const hash = { HS256: 'SHA-256', HS384: 'SHA-384', HS512: 'SHA-512' }[alg]
  if (!hash) {
    throw new Error(`${alg || '(missing alg)'} cannot be checked with a shared secret — only HS256/HS384/HS512 can`)
  }
  const enc = new TextEncoder()
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash }, false, ['verify'])
  return crypto.subtle.verify('HMAC', key, new Uint8Array(base64ToBytes(raw.signature)), enc.encode(`${raw.header}.${raw.payload}`))
}
