#!/usr/bin/env node
/**
 * Daily operations digest → Slack.
 *
 * Pulls the last 24 h of aggregate page views from Workers Analytics Engine,
 * share-link counts from D1, GitHub repo stats, and a health probe, then posts
 * a compact summary to a Slack incoming webhook. Runs from GitHub Actions
 * (.github/workflows/daily-digest.yml) but works anywhere:
 *
 *   CLOUDFLARE_ACCOUNT_ID=… CLOUDFLARE_API_TOKEN=… SLACK_WEBHOOK_URL=… node scripts/daily-digest.mjs
 *
 * Every section degrades independently: a missing token or a failed query
 * prints why and the rest still posts. Set DIGEST_DRY_RUN=1 to print instead
 * of posting. The API token needs "Account Analytics: Read" for the views
 * section and "D1: Read" for the shares section.
 */
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const SITE = 'https://hexbase.dev'
const REPO = 'davidapp/hexbase.dev'
const DATASET = 'hexbase_metrics'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const env = process.env
const account = env.CLOUDFLARE_ACCOUNT_ID
const cfToken = env.CLOUDFLARE_API_TOKEN
const webhook = env.SLACK_WEBHOOK_URL
const dryRun = env.DIGEST_DRY_RUN === '1' || !webhook

// The D1 database id lives in wrangler.jsonc — read it there so it can't drift.
const wranglerConfig = readFileSync(resolve(root, 'wrangler.jsonc'), 'utf8')
const d1Id = wranglerConfig.match(/"database_id":\s*"([^"]+)"/)?.[1]

const fmt = (n) => Math.round(n).toLocaleString('en-US')
const pct = (part, total) => (total > 0 ? `${Math.round((part / total) * 100)}%` : '—')

// ---------------------------------------------------------------- data sources

async function cfApi(path, init) {
  const res = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
    ...init,
    headers: { authorization: `Bearer ${cfToken}`, ...(init?.headers ?? {}) },
  })
  if (res.status === 403 || res.status === 401) {
    throw new Error(`HTTP ${res.status} — the API token lacks permission for ${path.split('/')[3] ?? path}`)
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`)
  return res.json()
}

async function aeQuery(sql) {
  const data = await cfApi(`/accounts/${account}/analytics_engine/sql`, {
    method: 'POST',
    headers: { 'content-type': 'text/plain' },
    body: sql,
  })
  return data.data ?? []
}

async function views() {
  if (!account || !cfToken) return { error: 'CLOUDFLARE_ACCOUNT_ID / CLOUDFLARE_API_TOKEN not set' }
  const day = `timestamp > NOW() - INTERVAL '1' DAY`
  const [total24, total7, byPath, byCountry] = await Promise.all([
    aeQuery(`SELECT SUM(_sample_interval) AS views FROM ${DATASET} WHERE ${day}`),
    aeQuery(`SELECT SUM(_sample_interval) AS views FROM ${DATASET} WHERE timestamp > NOW() - INTERVAL '7' DAY`),
    aeQuery(`SELECT blob1 AS path, SUM(_sample_interval) AS views FROM ${DATASET} WHERE ${day} GROUP BY path ORDER BY views DESC LIMIT 8`),
    aeQuery(`SELECT blob2 AS country, SUM(_sample_interval) AS views FROM ${DATASET} WHERE ${day} GROUP BY country ORDER BY views DESC LIMIT 6`),
  ])
  return {
    day: Number(total24[0]?.views ?? 0),
    week: Number(total7[0]?.views ?? 0),
    paths: byPath.map((r) => ({ path: r.path, views: Number(r.views) })),
    countries: byCountry.map((r) => ({ country: r.country, views: Number(r.views) })),
  }
}

async function shares() {
  if (!account || !cfToken) return { error: 'Cloudflare credentials not set' }
  if (!d1Id) return { error: 'database_id not found in wrangler.jsonc' }
  const now = Date.now()
  const data = await cfApi(`/accounts/${account}/d1/database/${d1Id}/query`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      sql: 'SELECT (SELECT COUNT(*) FROM shares WHERE created_at > ?1) AS created, (SELECT COUNT(*) FROM shares WHERE expires_at > ?2) AS active',
      params: [now - 86400_000, now],
    }),
  })
  const row = data.result?.[0]?.results?.[0] ?? {}
  return { created: Number(row.created ?? 0), active: Number(row.active ?? 0) }
}

async function health() {
  const t0 = Date.now()
  try {
    // A descriptive User-Agent: Node's default ("node") from a datacenter IP
    // trips Cloudflare's bot heuristics, which would report a healthy site as down.
    const res = await fetch(`${SITE}/api/health`, {
      signal: AbortSignal.timeout(10_000),
      headers: { 'user-agent': 'hexbase-digest/1.0 (+https://hexbase.dev/.well-known/security.txt)' },
    })
    const ms = Date.now() - t0
    const body = await res.json().catch(() => ({}))
    const ok = res.ok && body.ok === true
    // A 403 that is not our JSON comes from Cloudflare's bot protection acting on
    // the runner's datacenter IP — report it as a blocked probe, not an outage.
    const blocked = !ok && res.status === 403 && body.ok !== true
    return {
      ok,
      status: res.status,
      ms,
      error: blocked
        ? `blocked by Cloudflare bot protection (${res.headers.get('cf-mitigated') ?? 'runner IP'}) — probe, not outage`
        : undefined,
    }
  } catch (e) {
    return { ok: false, status: 0, ms: Date.now() - t0, error: e instanceof Error ? e.message : String(e) }
  }
}

async function github() {
  const headers = { accept: 'application/vnd.github+json', 'user-agent': 'hexbase-digest' }
  if (env.GITHUB_TOKEN) headers.authorization = `Bearer ${env.GITHUB_TOKEN}`
  const repo = await (await fetch(`https://api.github.com/repos/${REPO}`, { headers })).json()
  const since = new Date(Date.now() - 86400_000)
  // stargazers with timestamps: count the ones from the last 24 h (most recent page last)
  let newStars = 0
  const perPage = 100
  const lastPage = Math.max(1, Math.ceil((repo.stargazers_count ?? 0) / perPage))
  const stars = await (
    await fetch(`https://api.github.com/repos/${REPO}/stargazers?per_page=${perPage}&page=${lastPage}`, {
      headers: { ...headers, accept: 'application/vnd.github.star+json' },
    })
  ).json()
  if (Array.isArray(stars)) newStars = stars.filter((s) => new Date(s.starred_at) > since).length
  const pulls = await (await fetch(`https://api.github.com/repos/${REPO}/pulls?state=open&per_page=50`, { headers })).json()
  const openPRs = Array.isArray(pulls) ? pulls.length : 0
  return {
    stars: repo.stargazers_count ?? 0,
    newStars,
    openIssues: Math.max(0, (repo.open_issues_count ?? 0) - openPRs),
    openPRs,
    forks: repo.forks_count ?? 0,
  }
}

// ---------------------------------------------------------------- report

const settle = (p) => p.then((v) => v).catch((e) => ({ error: e instanceof Error ? e.message : String(e) }))
const [v, s, h, g] = await Promise.all([settle(views()), settle(shares()), settle(health()), settle(github())])

const date = new Date().toISOString().slice(0, 10)
const lines = []

if (v.error) lines.push(`*Views:* unavailable — ${v.error}`)
else {
  lines.push(`*Views (24h):* ${fmt(v.day)}  ·  *7d:* ${fmt(v.week)}`)
  if (v.paths.length) lines.push('*Top pages:* ' + v.paths.map((p) => `\`${p.path}\` ${fmt(p.views)}`).join(' · '))
  if (v.countries.length) lines.push('*Countries:* ' + v.countries.map((c) => `${c.country} ${pct(c.views, v.day)}`).join(' · '))
}
if (s.error) lines.push(`*Shares:* unavailable — ${s.error}`)
else lines.push(`*Shares:* ${fmt(s.created)} created today  ·  ${fmt(s.active)} active`)
lines.push(
  h.ok ? `*Health:* ✅ /api/health ${h.ms} ms` : `*Health:* 🔴 /api/health ${h.status || 'unreachable'}${h.error ? ` (${h.error})` : ''}`,
)
if (g.error) lines.push(`*GitHub:* unavailable — ${g.error}`)
else lines.push(`*GitHub:* ★ ${fmt(g.stars)}${g.newStars ? ` (+${g.newStars})` : ''}  ·  ${g.openIssues} open issues  ·  ${g.openPRs} open PRs  ·  ${g.forks} forks`)

const text = `hexbase.dev daily — ${date}\n` + lines.map((l) => l.replaceAll('*', '')).join('\n')
const payload = {
  text,
  blocks: [
    { type: 'header', text: { type: 'plain_text', text: `📊 hexbase.dev daily — ${date}` } },
    { type: 'section', text: { type: 'mrkdwn', text: lines.join('\n') } },
    {
      type: 'context',
      elements: [{ type: 'mrkdwn', text: `<${SITE}|hexbase.dev> · <https://github.com/${REPO}|GitHub> · views are aggregate path+country counts, no user data` }],
    },
  ],
}

if (dryRun) {
  console.log(webhook ? '(dry run)' : '(SLACK_WEBHOOK_URL not set — printing instead)')
  console.log(text)
} else {
  const res = await fetch(webhook, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) })
  console.log(`slack: HTTP ${res.status}`)
  console.log(text) // aggregate numbers only — safe in a public Actions log, handy for debugging
  if (!res.ok) {
    console.log(await res.text())
    process.exitCode = 1
  }
}
