/**
 * hexbase.dev service worker — offline support for a local-first site.
 *
 * Strategy:
 *  - HTML navigations: network-first, falling back to the cached copy (so
 *    updates land immediately when online, and visited pages work offline).
 *  - Hashed assets, demo files, icons: cache-first (immutable or static).
 *  - /api/ and /s/ are never touched: shares and metrics stay network-only.
 *
 * The cache self-heals: HTML is revalidated on every online visit and asset
 * filenames are content-hashed, so a version bump here is only needed when
 * the strategy itself changes.
 */
const CACHE = 'hexbase-v1'

self.addEventListener('install', () => {
  self.skipWaiting()
})

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const names = await caches.keys()
      await Promise.all(names.filter((n) => n !== CACHE).map((n) => caches.delete(n)))
      await self.clients.claim()
    })(),
  )
})

self.addEventListener('fetch', (event) => {
  const req = event.request
  if (req.method !== 'GET') return
  const url = new URL(req.url)
  if (url.origin !== location.origin) return
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/s/')) return

  if (req.mode === 'navigate') {
    event.respondWith(networkFirst(req))
  } else {
    event.respondWith(cacheFirst(req))
  }
})

async function networkFirst(req) {
  const cache = await caches.open(CACHE)
  try {
    const res = await fetch(req)
    if (res.ok && res.type === 'basic') await cache.put(req, res.clone())
    return res
  } catch {
    const hit = await cache.match(req)
    if (hit) return hit
    // last resort for a never-visited page while offline: the cached home page
    const home = await cache.match('/')
    return home ?? Response.error()
  }
}

async function cacheFirst(req) {
  const cache = await caches.open(CACHE)
  const hit = await cache.match(req)
  if (hit) return hit
  const res = await fetch(req)
  if (res.ok && res.type === 'basic') await cache.put(req, res.clone())
  return res
}
