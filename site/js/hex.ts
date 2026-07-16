import { crc32, entropy, extractStrings, formatSize, hex } from '@core/bytes'
import { detectFormat } from '@core/formats/index'
import type { ParseResult } from '@core/region'
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

// ---------------------------------------------------------------- samples

const ascii = (s: string): number[] => [...s].map((c) => c.charCodeAt(0))
const u32be = (v: number): number[] => [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]
const u16le = (v: number): number[] => [v & 0xff, (v >> 8) & 0xff]
const u32le = (v: number): number[] => [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff]

function cat(...parts: (number[] | Uint8Array)[]): Uint8Array {
  const arrays = parts.map((p) => (p instanceof Uint8Array ? p : new Uint8Array(p)))
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0))
  let off = 0
  for (const a of arrays) {
    out.set(a, off)
    off += a.length
  }
  return out
}

function pngChunk(type: string, data: number[]): Uint8Array {
  const td = cat(ascii(type), data)
  return cat(u32be(data.length), td, u32be(crc32(td)))
}

function samplePng(): Uint8Array {
  return cat(
    [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
    pngChunk('IHDR', [...u32be(320), ...u32be(240), 8, 6, 0, 0, 0]),
    pngChunk('tEXt', [...ascii('Software'), 0, ...ascii('hexbase.dev sample')]),
    pngChunk('pHYs', [...u32be(2835), ...u32be(2835), 1]),
    pngChunk('IDAT', [0x78, 0x9c, 0x63, 0x64, 0x60, 0x60, 0x60, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x01]),
    pngChunk('IEND', []),
  )
}

function sampleZip(): Uint8Array {
  const name = ascii('hello/readme.txt')
  const data = ascii('Every ZIP is read from the end first.\n')
  const crc = crc32(new Uint8Array(data))
  const lfh = cat([0x50, 0x4b, 0x03, 0x04], u16le(20), u16le(0), u16le(0), u16le(0x6c22), u16le(0x5901), u32le(crc), u32le(data.length), u32le(data.length), u16le(name.length), u16le(0), name, data)
  const cd = cat(
    [0x50, 0x4b, 0x01, 0x02],
    u16le(20), u16le(20), u16le(0), u16le(0), u16le(0x6c22), u16le(0x5901),
    u32le(crc), u32le(data.length), u32le(data.length),
    u16le(name.length), u16le(0), u16le(0), u16le(0), u16le(0), u32le(0), u32le(0),
    name,
  )
  const eocd = cat([0x50, 0x4b, 0x05, 0x06], u16le(0), u16le(0), u16le(1), u16le(1), u32le(cd.length), u32le(lfh.length), u16le(0))
  return cat(lfh, cd, eocd)
}

function sampleGzip(): Uint8Array {
  return cat(
    [0x1f, 0x8b, 8, 8],
    u32le(1721088000), // mtime: 2024-07-16
    [0, 3],
    ascii('notes.txt'), [0],
    [0x4b, 0xad, 0x02, 0x00], // (not real deflate — structure demo)
    u32le(0x9ae62c1e), u32le(42),
  )
}

$('#sample-png').addEventListener('click', () => analyze(samplePng(), 'sample.png'))
$('#sample-zip').addEventListener('click', () => analyze(sampleZip(), 'sample.zip'))
$('#sample-gzip').addEventListener('click', () => analyze(sampleGzip(), 'notes.txt.gz'))

// ---------------------------------------------------------------- share

bindShare($('#share'), 'hex', () => (current ? { bytes: current.bytes, filename: current.name } : null))

const code = shareParam()
if (code) {
  loadShare(code)
    .then(({ bytes, filename }) => {
      analyze(bytes, filename ?? 'shared.bin')
      toast('Loaded shared file')
    })
    .catch((e) => showMsg(msg, 'err', e instanceof Error ? e.message : 'failed to load share'))
}
