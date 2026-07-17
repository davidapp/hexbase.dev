#!/usr/bin/env node
/**
 * Submits every sitemap URL to IndexNow (Bing, Seznam, Naver, Yandex share
 * the endpoint). Run after deploy; the key file is served from the site root.
 * Never fails the build: indexing pings are best-effort.
 */
import { readFileSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const KEY = '91ccc9b4471de074c08a6cfd7ff8ab4f'
const HOST = 'hexbase.dev'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const sitemap = readFileSync(resolve(root, 'public', 'sitemap.xml'), 'utf8')
const urls = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1])

if (urls.length === 0) {
  console.log('indexnow: no URLs found in sitemap.xml, skipping')
  process.exit(0)
}

try {
  const res = await fetch('https://api.indexnow.org/indexnow', {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify({ host: HOST, key: KEY, keyLocation: `https://${HOST}/${KEY}.txt`, urlList: urls }),
  })
  console.log(`indexnow: submitted ${urls.length} URLs → HTTP ${res.status}`)
} catch (e) {
  console.log(`indexnow: submission failed (${e instanceof Error ? e.message : e}) — not fatal`)
}
