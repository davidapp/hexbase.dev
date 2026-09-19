import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { CSP, SECURITY_HEADERS, THEME_SCRIPT_HASH, withSecurityHeaders } from '../src/worker/headers'

describe('security headers', () => {
  it('pins the CSP hash of the one inline script in the head partial', () => {
    const head = readFileSync(join(__dirname, '..', 'site', 'partials', 'head.html'), 'utf8')
    const scripts = [...head.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1])
    expect(scripts).toHaveLength(1)
    // one line, no surrounding whitespace: the hash must not depend on line endings
    expect(scripts[0]).not.toMatch(/[\r\n]/)
    const hash = 'sha256-' + createHash('sha256').update(scripts[0], 'utf8').digest('base64')
    expect(hash).toBe(THEME_SCRIPT_HASH)
    expect(CSP).toContain(`'${THEME_SCRIPT_HASH}'`)
  })

  it('locks the site to its own origin', () => {
    expect(CSP).toContain("default-src 'self'")
    expect(CSP).toContain("frame-ancestors 'none'")
    expect(CSP).toContain("object-src 'none'")
    expect(CSP).not.toContain('unsafe-eval')
    expect(SECURITY_HEADERS['strict-transport-security']).toMatch(/max-age=\d{8}/)
    expect(SECURITY_HEADERS['x-content-type-options']).toBe('nosniff')
  })

  it('adds the headers without disturbing the response', async () => {
    const original = new Response('<html>', { status: 200, headers: { 'content-type': 'text/html', etag: '"abc"' } })
    const res = withSecurityHeaders(original)
    expect(res.status).toBe(200)
    expect(res.headers.get('etag')).toBe('"abc"')
    expect(res.headers.get('content-type')).toBe('text/html')
    expect(res.headers.get('content-security-policy')).toBe(CSP)
    expect(await res.text()).toBe('<html>')
  })
})
