import { entropy, extractStrings, formatSize, hex } from '@core/bytes'
import { detectFormat } from '@core/formats/index'
import type { ParseResult } from '@core/region'
import { ALL_DEMOS, DEMO_GROUPS, type DemoFile } from './demos'
import { $, bindShare, el, HexView, initChrome, initTabs, loadShare, RegionTree, renderResultHead, shareParam, showMsg, toast } from './ui'

initChrome()
initTabs($('#right-tabs').parentElement as HTMLElement)

const MAX_BYTES = 64 * 1024 * 1024

const dropzone = $('#drop')
const fileInput = $<HTMLInputElement>('#file')
const msg = $('#hex-msg')
const result = $('#result')
const summary = $('#summary')
const fileinfo = $('#fileinfo')
const stringsPanel = $('#strings')

const hexview = new HexView($('#hexview'))
const tree = new RegionTree($('#tree'), $('#note'))
tree.onSelect = (region) => hexview.highlight(region.offset, region.length)

let current: { bytes: Uint8Array; name: string } | null = null

function analyze(bytes: Uint8Array, name: string): void {
  current = { bytes, name }
  result.classList.remove('hidden')
  msg.className = 'msg hidden'

  const format = detectFormat(bytes)
  let parsed: ParseResult
  if (format) {
    try {
      parsed = format.parse(bytes)
    } catch (e) {
      parsed = { format: format.name, summary: [], regions: [], warnings: [`parser crashed: ${e instanceof Error ? e.message : String(e)}`] }
    }
  } else {
    const printable = bytes.subarray(0, 2048).filter((b) => (b >= 0x20 && b <= 0x7e) || b === 0x0a || b === 0x0d || b === 0x09).length
    const looksText = bytes.length > 0 && printable / Math.min(bytes.length, 2048) > 0.9
    parsed = {
      format: looksText ? 'Plain text (no binary signature)' : 'Unknown format',
      summary: [looksText ? 'No magic bytes matched; content is mostly printable ASCII/UTF-8.' : 'No known magic bytes at offset 0 — unknown, headerless, or encrypted data.'],
      regions: [],
      warnings: [],
    }
  }

  const ent = entropy(bytes.subarray(0, 256 * 1024))
  parsed.summary.push(`${formatSize(bytes.length)} · entropy ${ent.toFixed(2)} bits/byte${ent > 7.8 ? ' (compressed or encrypted-looking)' : ent < 3 ? ' (highly regular)' : ''}`)

  renderResultHead(summary, parsed)
  fileinfo.textContent = `${name} · ${formatSize(bytes.length)}`
  hexview.setData(bytes)
  tree.set(parsed.regions)

  // strings tab
  stringsPanel.textContent = ''
  const found = extractStrings(bytes, 4, 400)
  if (found.length === 0) {
    stringsPanel.append(el('div', 'trow', 'no printable strings ≥ 4 chars'))
  }
  for (const s of found) {
    const row = el('div', 'trow')
    row.append(el('span', 'toff', '0x' + hex(s.offset, 6)), el('span', 'tname', s.text.length > 60 ? s.text.slice(0, 60) + '…' : s.text))
    row.style.cursor = 'pointer'
    row.addEventListener('click', () => hexview.highlight(s.offset, s.text.length))
    stringsPanel.append(row)
  }

  document.title = `${name} — Hex Inspector | hexbase.dev`
}

function handleFile(file: File): void {
  if (file.size > MAX_BYTES) {
    showMsg(msg, 'err', `${file.name} is ${formatSize(file.size)} — the in-browser limit is ${formatSize(MAX_BYTES)}`)
    return
  }
  void file.arrayBuffer().then((buf) => analyze(new Uint8Array(buf), file.name))
}

dropzone.addEventListener('dragover', (e) => {
  e.preventDefault()
  dropzone.classList.add('drag')
})
dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag'))
dropzone.addEventListener('drop', (e) => {
  e.preventDefault()
  dropzone.classList.remove('drag')
  const file = e.dataTransfer?.files[0]
  if (file) handleFile(file)
})
fileInput.addEventListener('change', () => {
  if (fileInput.files?.[0]) handleFile(fileInput.files[0])
})

// ---------------------------------------------------------------- demo gallery
// Real, representative files (see scripts/make-demos.mjs) served from /demo/.

async function openDemo(demo: DemoFile, updateUrl = true): Promise<void> {
  try {
    const res = await fetch(`/demo/${demo.file}`)
    if (!res.ok) throw new Error(`could not load demo (${res.status})`)
    const bytes = new Uint8Array(await res.arrayBuffer())
    analyze(bytes, demo.file)
    if (updateUrl) history.replaceState(null, '', `?demo=${demo.id}`)
  } catch (e) {
    showMsg(msg, 'err', e instanceof Error ? e.message : 'failed to load demo')
  }
}

/** icns has no native <img> support — extract the first embedded PNG entry
 *  from the file itself (they are literally PNGs wearing an OSType tag). */
async function icnsThumb(img: HTMLImageElement, demo: DemoFile): Promise<void> {
  try {
    const res = await fetch(`/demo/${demo.file}`)
    const bytes = new Uint8Array(await res.arrayBuffer())
    let pos = 8
    while (pos + 8 <= bytes.length) {
      const len = ((bytes[pos + 4] << 24) | (bytes[pos + 5] << 16) | (bytes[pos + 6] << 8) | bytes[pos + 7]) >>> 0
      if (len < 8) break
      const d = pos + 8
      if (bytes[d] === 0x89 && bytes[d + 1] === 0x50 && bytes[d + 2] === 0x4e && bytes[d + 3] === 0x47) {
        img.src = URL.createObjectURL(new Blob([bytes.slice(d, pos + len)], { type: 'image/png' }))
        return
      }
      pos += len
    }
  } catch {
    /* keep the placeholder */
  }
}

function demoChip(demo: DemoFile): HTMLElement {
  const chip = el('span', 'demo-chip')

  const open = el('button', 'demo-open')
  if (demo.kind === 'image') {
    const img = el('img', 'demo-thumb') as HTMLImageElement
    img.alt = `${demo.label} preview`
    img.loading = 'lazy'
    if (demo.file.endsWith('.icns')) void icnsThumb(img, demo)
    else img.src = `/demo/${demo.file}`
    open.append(img)
  }
  open.append(document.createTextNode(demo.label))
  open.title = `${demo.desc}\n\nClick to open in the inspector.`
  open.addEventListener('click', () => void openDemo(demo))
  chip.append(open)

  const dl = el('a', 'demo-dl', '↓') as HTMLAnchorElement
  dl.href = `/demo/${demo.file}`
  dl.setAttribute('download', demo.file)
  dl.title = `download ${demo.file}`
  chip.append(dl)
  return chip
}

const demosBox = $('#demos')
for (const { group, items } of DEMO_GROUPS) {
  const row = el('div', 'demo-row')
  row.append(el('span', 'demo-group', group))
  for (const demo of items) {
    row.append(demoChip(demo))
    if (demo.kind === 'audio') {
      const audio = el('audio', 'demo-audio') as HTMLAudioElement
      audio.controls = true
      audio.preload = 'none'
      audio.src = `/demo/${demo.file}`
      audio.title = `${demo.file} — the same bytes the inspector shows you`
      row.append(audio)
    }
  }
  demosBox.append(row)
}

// ---------------------------------------------------------------- share + deep links

bindShare($('#share'), 'hex', () => (current ? { bytes: current.bytes, filename: current.name } : null))

const shareCode = shareParam()
const demoParam = new URLSearchParams(location.search).get('demo')
if (shareCode) {
  loadShare(shareCode)
    .then(({ bytes, filename }) => {
      analyze(bytes, filename ?? 'shared.bin')
      toast('Loaded shared file')
    })
    .catch((e) => showMsg(msg, 'err', e instanceof Error ? e.message : 'failed to load share'))
} else if (demoParam) {
  const demo = ALL_DEMOS.find((d) => d.id === demoParam)
  if (demo) void openDemo(demo, false)
}
