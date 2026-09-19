import { Hono } from 'hono'
import { withSecurityHeaders } from './headers'

const app = new Hono<{ Bindings: Env }>()

// Security headers on every response that passes through the Worker (pages,
// API, redirects); see headers.ts for the policy.
app.use('*', async (c, next) => {
  await next()
  c.res = withSecurityHeaders(c.res)
})

const SHARE_TOOLS: Record<string, string> = {
  json: '/tools/json/',
  xml: '/tools/xml/',
  encode: '/tools/encode/',
  packet: '/tools/packet/',
  hex: '/tools/hex/',
  timestamp: '/tools/timestamp/',
  diff: '/tools/diff/',
  cert: '/tools/cert/',
}
const MAX_SHARE_BYTES = 256 * 1024
const SHARE_TTL_MS = 30 * 24 * 3600 * 1000
const RATE_LIMIT_PER_HOUR = 30
const CODE_RE = /^[1-9A-HJ-NP-Za-km-z]{6,16}$/

function base64ToBytes(b64: string): Uint8Array {
  let s = b64.replace(/\s+/g, '').replaceAll('-', '+').replaceAll('_', '/')
  while (s.length % 4 !== 0) s += '='
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

function randomCode(len = 10): string {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  const bytes = new Uint8Array(len)
  crypto.getRandomValues(bytes)
  let out = ''
  for (let i = 0; i < len; i++) out += alphabet[bytes[i] % alphabet.length]
  return out
}

async function sha256hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

// ---------------------------------------------------------------- API

app.get('/api/health', (c) => c.json({ ok: true, service: 'hexbase', time: new Date().toISOString() }))

interface LinkRow {
  category: string
  category_sort: number
  title: string
  url: string
  description: string
}

app.get('/api/links', async (c) => {
  const cached = await c.env.CACHE.get('links:v1', 'text')
  if (cached) {
    return new Response(cached, {
      headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=300', 'x-hexbase-cache': 'hit' },
    })
  }
  const { results } = await c.env.DB.prepare(
    'SELECT category, category_sort, title, url, description FROM links ORDER BY category_sort, category, sort, title',
  ).all<LinkRow>()

  const categories: { category: string; links: { title: string; url: string; description: string }[] }[] = []
  for (const row of results) {
    let bucket = categories[categories.length - 1]
    if (!bucket || bucket.category !== row.category) {
      bucket = { category: row.category, links: [] }
      categories.push(bucket)
    }
    bucket.links.push({ title: row.title, url: row.url, description: row.description })
  }
  const body = JSON.stringify({ categories })
  c.executionCtx.waitUntil(c.env.CACHE.put('links:v1', body, { expirationTtl: 3600 }))
  return new Response(body, {
    headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=300', 'x-hexbase-cache': 'miss' },
  })
})

app.post('/api/share', async (c) => {
  // Rate limit by salted+hashed client IP (we never store the raw IP).
  const ip = c.req.header('cf-connecting-ip') ?? 'local'
  const hour = Math.floor(Date.now() / 3600_000)
  const rlKey = `rl:${await sha256hex(`${ip}:${hour}:hexbase-share`)}`
  const count = Number((await c.env.CACHE.get(rlKey)) ?? '0')
  if (count >= RATE_LIMIT_PER_HOUR) {
    return c.json({ error: 'rate limit exceeded — try again in an hour' }, 429)
  }

  const body = await c.req.json<{ tool?: string; content?: string; filename?: string }>().catch(() => null)
  if (!body || typeof body.content !== 'string' || !body.tool || !(body.tool in SHARE_TOOLS)) {
    return c.json({ error: 'expected JSON body: { tool, content (base64), filename? }' }, 400)
  }
  let bytes: Uint8Array
  try {
    bytes = base64ToBytes(body.content)
  } catch {
    return c.json({ error: 'content is not valid base64' }, 400)
  }
  if (bytes.length === 0) return c.json({ error: 'content is empty' }, 400)
  if (bytes.length > MAX_SHARE_BYTES) {
    return c.json({ error: `content is ${bytes.length} bytes — the limit is ${MAX_SHARE_BYTES}` }, 413)
  }

  const code = randomCode()
  const now = Date.now()
  const expiresAt = now + SHARE_TTL_MS
  const filename = typeof body.filename === 'string' ? body.filename.slice(0, 120) : null

  await c.env.SHARES.put(`shares/${code}`, bytes)
  await c.env.DB.prepare('INSERT INTO shares (code, tool, filename, size, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(code, body.tool, filename, bytes.length, now, expiresAt)
    .run()
  c.executionCtx.waitUntil(c.env.CACHE.put(rlKey, String(count + 1), { expirationTtl: 3600 }))

  const origin = c.env.SITE_ORIGIN || new URL(c.req.url).origin
  return c.json({ code, url: `${origin}/s/${code}`, expiresAt })
})

app.get('/api/share/:code', async (c) => {
  const code = c.req.param('code')
  if (!CODE_RE.test(code)) return c.json({ error: 'invalid share code' }, 400)
  const row = await c.env.DB.prepare('SELECT tool, filename, size, expires_at FROM shares WHERE code = ?')
    .bind(code)
    .first<{ tool: string; filename: string | null; size: number; expires_at: number }>()
  if (!row || row.expires_at < Date.now()) {
    return c.json({ error: 'share not found or expired' }, 404)
  }
  const obj = await c.env.SHARES.get(`shares/${code}`)
  if (!obj) return c.json({ error: 'share content missing' }, 404)
  return new Response(obj.body, {
    headers: {
      'content-type': 'application/octet-stream',
      'cache-control': 'public, max-age=3600',
      'x-hexbase-tool': row.tool,
      'x-hexbase-filename': row.filename ?? '',
    },
  })
})

// Short link: /s/abc123 → the right tool page, which then loads the content.
app.get('/s/:code', async (c) => {
  const code = c.req.param('code')
  if (!CODE_RE.test(code)) return c.notFound()
  const row = await c.env.DB.prepare('SELECT tool, expires_at FROM shares WHERE code = ?')
    .bind(code)
    .first<{ tool: string; expires_at: number }>()
  if (!row || row.expires_at < Date.now() || !(row.tool in SHARE_TOOLS)) {
    return c.redirect('/?missing-share', 302)
  }
  return c.redirect(`${SHARE_TOOLS[row.tool]}?share=${code}`, 302)
})

/** Aggregate, anonymous page-view counting: path + country, nothing else.
 *  Counts successful HTML documents only — root-level files (sitemap,
 *  robots, sw.js…) pass through the Worker too but are not page views. */
function countPageView(c: { env: Env; req: { raw: Request; path: string; method: string } }, res: Response): void {
  if (c.req.method !== 'GET' || !c.env.METRICS) return
  if (res.status !== 200 || !(res.headers.get('content-type') ?? '').includes('text/html')) return
  try {
    const country = (c.req.raw.cf?.country as string | undefined) ?? 'XX'
    c.env.METRICS.writeDataPoint({
      blobs: [c.req.path, country],
      doubles: [1],
      indexes: [c.req.path.slice(0, 96)],
    })
  } catch {
    // metrics must never break serving
  }
}

app.notFound(async (c) => {
  if (c.req.path.startsWith('/api/')) {
    return c.json({ error: 'not found' }, 404)
  }
  // Everything except the hashed asset directories runs the Worker first (see
  // wrangler.jsonc): serve the built site (including its 404 page) and count
  // the successful HTML pages.
  const res = await c.env.ASSETS.fetch(c.req.raw)
  countPageView(c, res)
  return res
})

app.onError((err, c) => {
  console.log(JSON.stringify({ level: 'error', message: err.message, path: c.req.path }))
  if (c.req.path.startsWith('/api/')) {
    return c.json({ error: 'internal error' }, 500)
  }
  return c.text('internal error', 500)
})

// Nightly cleanup of expired shares: R2 objects first, then their D1 rows.
async function purgeExpiredShares(env: Env): Promise<void> {
  const { results } = await env.DB.prepare('SELECT code FROM shares WHERE expires_at < ? LIMIT 400')
    .bind(Date.now())
    .all<{ code: string }>()
  if (results.length === 0) return
  await env.SHARES.delete(results.map((r) => `shares/${r.code}`))
  const placeholders = results.map(() => '?').join(',')
  await env.DB.prepare(`DELETE FROM shares WHERE code IN (${placeholders})`)
    .bind(...results.map((r) => r.code))
    .run()
  console.log(JSON.stringify({ level: 'info', message: 'purged expired shares', count: results.length }))
}

export default {
  fetch: app.fetch,
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(purgeExpiredShares(env))
  },
} satisfies ExportedHandler<Env>
