#!/usr/bin/env node
/**
 * Generates the /formats/ landing pages (one per file format the hex inspector
 * parses) plus the /formats/ hub and a complete sitemap.xml.
 *
 * Content lives in format-content-*.mjs; this file is only the template.
 * Output goes to site/formats/** (gitignored — regenerated on every build).
 */
import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { FORMAT_PAGES_1 } from './format-content-1.mjs'
import { FORMAT_PAGES_2 } from './format-content-2.mjs'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const outRoot = resolve(root, 'site', 'formats')
const SITE = 'https://hexbase.dev'
const PUBLISHED = '2026-07-18'

export const FORMAT_PAGES = [...FORMAT_PAGES_1, ...FORMAT_PAGES_2]

const esc = (s) =>
  String(s).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;')

/** Prose fields may embed <code>/<strong>/<em>/<a> — trust our own content, escape nothing else. */
const prose = (s) => s

/** Strip the little HTML we allow in prose so FAQ answers are plain text in JSON-LD. */
const plain = (s) => String(s).replace(/<[^>]+>/g, '')

function jsonLd(f) {
  const graph = [
    {
      '@type': 'TechArticle',
      headline: f.title,
      description: f.desc,
      url: `${SITE}/formats/${f.slug}/`,
      datePublished: PUBLISHED,
      dateModified: PUBLISHED,
      inLanguage: 'en',
      author: { '@type': 'Organization', name: 'hexbase.dev', url: `${SITE}/` },
      publisher: { '@type': 'Organization', name: 'hexbase.dev', url: `${SITE}/`, email: 'support@hexbase.dev' },
      about: `${f.name} (${f.fullName}) binary file format`,
    },
    {
      '@type': 'BreadcrumbList',
      itemListElement: [
        { '@type': 'ListItem', position: 1, name: 'hexbase.dev', item: `${SITE}/` },
        { '@type': 'ListItem', position: 2, name: 'File formats', item: `${SITE}/formats/` },
        { '@type': 'ListItem', position: 3, name: f.name, item: `${SITE}/formats/${f.slug}/` },
      ],
    },
  ]
  if (f.faq?.length) {
    graph.push({
      '@type': 'FAQPage',
      mainEntity: f.faq.map((qa) => ({
        '@type': 'Question',
        name: plain(qa.q),
        acceptedAnswer: { '@type': 'Answer', text: plain(qa.a) },
      })),
    })
  }
  return JSON.stringify({ '@context': 'https://schema.org', '@graph': graph }, null, 2)
    .split('\n')
    .map((l) => '      ' + l)
    .join('\n')
    .trim()
}

function structureTable(f) {
  if (!f.structure) return ''
  const head = f.structure.head.map((h) => `<th>${esc(h)}</th>`).join('')
  const rows = f.structure.rows
    .map((r) => `<tr>${r.map((c, i) => `<td>${i === 0 ? esc(c) : prose(c)}</td>`).join('')}</tr>`)
    .join('\n            ')
  return `
        <h2>${esc(f.structure.caption)}</h2>
        <table>
          <thead><tr>${head}</tr></thead>
          <tbody>
            ${rows}
          </tbody>
        </table>`
}

function pageHtml(f) {
  const related = (f.related ?? [])
    .map((slug) => {
      const r = FORMAT_PAGES.find((p) => p.slug === slug)
      return r ? `<a href="/formats/${r.slug}/">${esc(r.name)}</a>` : ''
    })
    .filter(Boolean)
    .join(' · ')
  const demoLink = f.demoId
    ? `<a class="btn primary" href="/tools/hex/?demo=${f.demoId}">Open a real ${esc(f.name)} in the hex inspector</a>`
    : `<a class="btn primary" href="/tools/${f.tool ?? 'hex'}/">Open the ${f.tool === 'packet' ? 'packet decoder' : 'hex inspector'}</a>`
  const download = f.demoFile ? ` <a class="btn" href="/demo/${f.demoFile}" download>Download the specimen</a>` : ''

  return `<!doctype html>
<html lang="en">
  <head>
    <!--#include:head-->
    <title>${esc(f.title)} | hexbase.dev</title>
    <meta name="description" content="${esc(f.desc)}" />
    <link rel="canonical" href="${SITE}/formats/${f.slug}/" />
    <meta property="og:title" content="${esc(f.title)}" />
    <meta property="og:description" content="${esc(f.desc)}" />
    <meta property="og:url" content="${SITE}/formats/${f.slug}/" />
    <meta property="og:image" content="${SITE}/og/formats.png" />
    <meta property="og:image:width" content="1200" />
    <meta property="og:image:height" content="630" />
    <meta property="og:image:alt" content="${esc(f.title)}" />
    <script type="application/ld+json">
      ${jsonLd(f)}
    </script>
  </head>
  <body>
    <!--#include:header-->
    <main class="container">
      <div class="page-head">
        <p class="crumbs"><a href="/formats/">file formats</a> / ${esc(f.slug)}</p>
        <h1>The ${esc(f.name)} file format</h1>
        <p class="sub">${prose(f.tagline)}</p>
      </div>

      <div class="card magic-card">
        <div class="pane-title"><span>magic bytes</span><span>${esc(f.fullName)}</span></div>
        <div class="byteline" style="text-align:left">${esc(f.magic.hex)}${f.magic.ascii ? ` <span class="hl">${esc(f.magic.ascii)}</span>` : ''}</div>
        <p class="dim" style="margin:8px 0 0; font-size:0.85rem">${prose(f.magic.note)}</p>
      </div>

      <section class="learn">
${f.intro.map((p) => `        <p>${prose(p)}</p>`).join('\n')}
${structureTable(f)}
${
  f.quirks?.length
    ? `
        <h2>Details that bite</h2>
        <ul>
${f.quirks.map((q) => `          <li>${prose(q)}</li>`).join('\n')}
        </ul>`
    : ''
}
        <div class="btn-row" style="margin-top: 22px">
          ${demoLink}${download}
        </div>
      </section>
${
  f.faq?.length
    ? `
      <section class="learn" id="faq">
        <h2>Frequently asked questions</h2>
${f.faq.map((qa) => `        <h3>${prose(qa.q)}</h3>\n        <p>${prose(qa.a)}</p>`).join('\n')}
      </section>`
    : ''
}
${
  related
    ? `
      <section class="learn">
        <h2>Related formats</h2>
        <p>${related} — or browse <a href="/formats/">all ${FORMAT_PAGES.length} formats</a>.</p>
      </section>`
    : ''
}
    </main>
    <!--#include:footer-->
    <script type="module" src="/js/legal.ts"></script>
  </body>
</html>
`
}

function hubHtml() {
  const groups = new Map()
  for (const f of FORMAT_PAGES) {
    if (!groups.has(f.group)) groups.set(f.group, [])
    groups.get(f.group).push(f)
  }
  const sections = [...groups.entries()]
    .map(
      ([group, items]) => `
      <section class="learn">
        <h2>${esc(group)}</h2>
        <table>
          <thead><tr><th>Format</th><th>Magic</th><th>In one line</th></tr></thead>
          <tbody>
${items
  .map(
    (f) =>
      `            <tr><td><a href="/formats/${f.slug}/">${esc(f.name)}</a></td><td>${esc(f.magic.hex.split(' ').slice(0, 4).join(' '))}</td><td>${prose(f.oneLiner)}</td></tr>`,
  )
  .join('\n')}
          </tbody>
        </table>
      </section>`,
    )
    .join('\n')

  const itemList = FORMAT_PAGES.map((f, i) => ({
    '@type': 'ListItem',
    position: i + 1,
    name: `${f.name} file format`,
    url: `${SITE}/formats/${f.slug}/`,
  }))

  return `<!doctype html>
<html lang="en">
  <head>
    <!--#include:head-->
    <title>Binary file formats, explained byte by byte | hexbase.dev</title>
    <meta name="description" content="Field guides to ${FORMAT_PAGES.length} binary file formats — PNG, JPEG, ZIP, ELF, PE, Mach-O, SQLite, PDF, WASM and more: magic bytes, structure tables, gotchas, and a real specimen of each to open in the hex inspector." />
    <link rel="canonical" href="${SITE}/formats/" />
    <meta property="og:title" content="Binary file formats, explained byte by byte" />
    <meta property="og:description" content="Field guides to ${FORMAT_PAGES.length} binary formats: magic bytes, structure, gotchas, and a real specimen of each." />
    <meta property="og:url" content="${SITE}/formats/" />
    <meta property="og:image" content="${SITE}/og/formats.png" />
    <meta property="og:image:width" content="1200" />
    <meta property="og:image:height" content="630" />
    <meta property="og:image:alt" content="Binary file formats, explained byte by byte" />
    <script type="application/ld+json">
      ${JSON.stringify(
        {
          '@context': 'https://schema.org',
          '@graph': [
            {
              '@type': 'CollectionPage',
              name: 'Binary file formats, explained byte by byte',
              url: `${SITE}/formats/`,
              description: `Field guides to ${FORMAT_PAGES.length} binary file formats: magic bytes, structure, quirks, and real specimens.`,
              isPartOf: { '@type': 'WebSite', '@id': `${SITE}/#website`, url: `${SITE}/`, name: 'hexbase.dev' },
            },
            { '@type': 'ItemList', name: 'File format guides', itemListElement: itemList },
            {
              '@type': 'BreadcrumbList',
              itemListElement: [
                { '@type': 'ListItem', position: 1, name: 'hexbase.dev', item: `${SITE}/` },
                { '@type': 'ListItem', position: 2, name: 'File formats', item: `${SITE}/formats/` },
              ],
            },
          ],
        },
        null,
        2,
      )
        .split('\n')
        .map((l) => '      ' + l)
        .join('\n')
        .trim()}
    </script>
  </head>
  <body>
    <!--#include:header-->
    <main class="container">
      <div class="page-head">
        <h1>File formats, byte by byte</h1>
        <p class="sub">
          Every format below opens with a promise about what follows. Each guide covers the magic bytes, the on-disk
          structure, the details that bite — and links a real specimen you can walk field-by-field in the
          <a href="/tools/hex/">hex inspector</a>.
        </p>
      </div>
${sections}
    </main>
    <!--#include:footer-->
    <script type="module" src="/js/legal.ts"></script>
  </body>
</html>
`
}

function sitemap() {
  const items = [
    { loc: '/', pri: '1.0' },
    { loc: '/tools/hex/', pri: '0.9' },
    { loc: '/tools/packet/', pri: '0.9' },
    { loc: '/tools/json/', pri: '0.9' },
    { loc: '/tools/diff/', pri: '0.9' },
    { loc: '/tools/cert/', pri: '0.9' },
    { loc: '/tools/xml/', pri: '0.8' },
    { loc: '/tools/timestamp/', pri: '0.9' },
    { loc: '/tools/encode/', pri: '0.9' },
    { loc: '/tools/random/', pri: '0.9' },
    { loc: '/formats/', pri: '0.8' },
    ...FORMAT_PAGES.map((f) => ({ loc: `/formats/${f.slug}/`, pri: '0.7' })),
    { loc: '/links/', pri: '0.6' },
    { loc: '/terms/', pri: '0.3' },
    { loc: '/privacy/', pri: '0.3' },
  ]
  const body = items
    .map((i) => `  <url><loc>${SITE}${i.loc}</loc><lastmod>${PUBLISHED}</lastmod><priority>${i.pri}</priority></url>`)
    .join('\n')
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${body}\n</urlset>\n`
}

// ---------------------------------------------------------------- emit

rmSync(outRoot, { recursive: true, force: true })
mkdirSync(outRoot, { recursive: true })
writeFileSync(resolve(outRoot, 'index.html'), hubHtml())
for (const f of FORMAT_PAGES) {
  const dir = resolve(outRoot, f.slug)
  mkdirSync(dir, { recursive: true })
  writeFileSync(resolve(dir, 'index.html'), pageHtml(f))
}
writeFileSync(resolve(root, 'public', 'sitemap.xml'), sitemap())
console.log(`formats: wrote ${FORMAT_PAGES.length} pages + hub + sitemap.xml`)
