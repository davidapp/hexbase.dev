import { formatSize, hex, parseHexInput, printable } from '@core/bytes'
import { decodePacket, FIRST_LAYER_CHOICES } from '@core/packet/decode'
import { frameTime, looksLikePcap, parsePcapFile, type PcapFile } from '@core/packet/pcap'
import { SAMPLE_PACKETS } from '@core/packet/samples'
import type { LayerId } from '@core/packet/net'
import { $, bindShare, el, HexView, initChrome, loadShare, RegionTree, renderResultHead, shareParam, showMsg, toast } from './ui'

initChrome()

const input = $<HTMLTextAreaElement>('#input')
const firstLayer = $<HTMLSelectElement>('#first-layer')
const msg = $('#pkt-msg')
const result = $('#result')
const summary = $('#summary')

for (const choice of FIRST_LAYER_CHOICES) {
  const opt = el('option', '', choice.label) as HTMLOptionElement
  opt.value = choice.id
  firstLayer.append(opt)
}

const hexview = new HexView($('#hexview'))
const tree = new RegionTree($('#tree'), $('#note'))
tree.onSelect = (region) => hexview.highlight(region.offset, region.length)

let currentBytes: Uint8Array | null = null

function decodeFrame(bytes: Uint8Array, layer: LayerId | 'auto'): void {
  currentBytes = bytes
  const parsed = decodePacket(bytes, layer)
  result.classList.remove('hidden')
  renderResultHead(summary, parsed)
  hexview.setData(bytes)
  tree.set(parsed.regions)
}

function decode(): void {
  msg.className = 'msg hidden'
  let bytes: Uint8Array
  try {
    bytes = parseHexInput(input.value)
  } catch (e) {
    showMsg(msg, 'err', e instanceof Error ? e.message : String(e))
    result.classList.add('hidden')
    return
  }
  if (bytes.length > 128 * 1024) {
    showMsg(msg, 'err', `${bytes.length} bytes is more than one packet — paste a single frame (≤128 KB)`)
    return
  }
  decodeFrame(bytes, firstLayer.value as LayerId | 'auto')
}

$('#decode').addEventListener('click', decode)
input.addEventListener('keydown', (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') decode()
})

// samples
const samplesBox = $('#samples')
for (const sample of SAMPLE_PACKETS) {
  const btn = el('button', 'btn small', sample.label)
  btn.title = sample.desc
  btn.style.marginRight = '6px'
  btn.addEventListener('click', () => {
    const bytes = sample.build()
    input.value = toDump(bytes)
    decode()
  })
  samplesBox.append(btn)
}

/** Pretty offset+hex+ascii dump for the textarea, so samples teach the format too. */
function toDump(bytes: Uint8Array): string {
  const lines: string[] = []
  for (let row = 0; row < bytes.length; row += 16) {
    const chunk = bytes.subarray(row, Math.min(row + 16, bytes.length))
    const hexPart = [...chunk].map((b, i) => hex(b) + (i === 7 ? '  ' : ' ')).join('')
    const asciiPart = [...chunk].map((b) => printable(b)).join('')
    lines.push(`${hex(row, 4)}  ${hexPart.padEnd(49)} ${asciiPart}`)
  }
  return lines.join('\n')
}

// ---------------------------------------------------------------- pcap files

const MAX_PCAP_BYTES = 32 * 1024 * 1024
const BRIEF_LIMIT = 400 // decode this many frames for the list's summary column
const ROW_LIMIT = 2000 // rows rendered in the list

const pcapSection = $('#pcap-section')
const pcapSummary = $('#pcap-summary')
const pcapCount = $('#pcap-count')
const framelist = $('#framelist')
let capture: PcapFile | null = null
let selectedRow: HTMLElement | null = null

function frameBrief(i: number): string {
  const f = capture!.frames[i]
  if (i >= BRIEF_LIMIT) return `${f.bytes.length} bytes`
  try {
    const parsed = decodePacket(f.bytes, f.firstLayer)
    return parsed.summary[parsed.summary.length - 1] ?? `${f.bytes.length} bytes`
  } catch {
    return `${f.bytes.length} bytes (decode failed)`
  }
}

function selectFrame(i: number, row: HTMLElement): void {
  const f = capture!.frames[i]
  selectedRow?.classList.remove('sel')
  row.classList.add('sel')
  selectedRow = row
  input.value = toDump(f.bytes)
  // reflect the frame's first layer in the selector when it's an offered choice
  if (FIRST_LAYER_CHOICES.some((c) => c.id === f.firstLayer)) firstLayer.value = f.firstLayer
  msg.className = 'msg hidden'
  decodeFrame(f.bytes, f.firstLayer)
}

function renderCapture(name: string, cap: PcapFile): void {
  capture = cap
  selectedRow = null
  renderResultHead(pcapSummary, {
    format: `${name} — ${cap.kind === 'pcapng' ? 'pcapng capture' : 'pcap capture'}`,
    summary: cap.meta,
    regions: [],
    warnings: cap.warnings,
  })
  framelist.textContent = ''
  const shown = Math.min(cap.frames.length, ROW_LIMIT)
  pcapCount.textContent =
    shown < cap.frames.length ? `showing ${shown} of ${cap.frames.length} frames` : `${cap.frames.length} frame${cap.frames.length === 1 ? '' : 's'}`
  const firstTs = cap.frames.find((f) => f.tsSec > 0)?.tsSec ?? 0
  const frag = document.createDocumentFragment()
  for (let i = 0; i < shown; i++) {
    const f = cap.frames[i]
    const row = el('div', 'frow')
    row.append(
      el('span', 'fnum', String(f.index)),
      el('span', 'ftime', frameTime(f, firstTs)),
      el('span', 'flen', String(f.bytes.length)),
      el('span', 'fs', frameBrief(i)),
    )
    row.addEventListener('click', () => selectFrame(i, row))
    frag.append(row)
  }
  framelist.append(frag)
  pcapSection.classList.remove('hidden')
  if (cap.frames.length > 0) selectFrame(0, framelist.firstElementChild as HTMLElement)
  else showMsg(msg, 'warn', 'capture file parsed, but it contains no frames')
}

function loadCaptureBytes(name: string, bytes: Uint8Array): void {
  msg.className = 'msg hidden'
  if (looksLikePcap(bytes)) {
    try {
      renderCapture(name, parsePcapFile(bytes))
    } catch (e) {
      showMsg(msg, 'err', e instanceof Error ? e.message : String(e))
    }
    return
  }
  // not a capture container — treat a small file as one raw frame
  if (bytes.length <= 128 * 1024) {
    pcapSection.classList.add('hidden')
    capture = null
    input.value = toDump(bytes)
    decode()
    toast(`${name}: not a pcap file — loaded as one raw frame`)
  } else {
    showMsg(msg, 'err', `${name} is not a pcap/pcapng capture (no magic bytes) and too large for a single frame`)
  }
}

function handleFile(file: File): void {
  if (file.size > MAX_PCAP_BYTES) {
    showMsg(msg, 'err', `${file.name} is ${formatSize(file.size)} — the in-browser limit is ${formatSize(MAX_PCAP_BYTES)}`)
    return
  }
  void file.arrayBuffer().then((buf) => loadCaptureBytes(file.name, new Uint8Array(buf)))
}

const pcapInput = $<HTMLInputElement>('#pcap-file')
pcapInput.addEventListener('change', () => {
  if (pcapInput.files?.[0]) handleFile(pcapInput.files[0])
  pcapInput.value = ''
})
document.addEventListener('dragover', (e) => e.preventDefault())
document.addEventListener('drop', (e) => {
  e.preventDefault()
  const file = e.dataTransfer?.files?.[0]
  if (file) handleFile(file)
})

// share: store the raw bytes; on load, render a dump and decode
bindShare($('#share'), 'packet', () => (currentBytes ? { bytes: currentBytes } : null))

const code = shareParam()
if (code) {
  loadShare(code)
    .then(({ bytes }) => {
      input.value = toDump(bytes)
      decode()
      toast('Loaded shared packet')
    })
    .catch((e) => showMsg(msg, 'err', e instanceof Error ? e.message : 'failed to load share'))
}

