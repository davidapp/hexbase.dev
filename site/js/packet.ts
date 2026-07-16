import { hex, parseHexInput, printable } from '@core/bytes'
import { decodePacket, FIRST_LAYER_CHOICES } from '@core/packet/decode'
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
  currentBytes = bytes
  const parsed = decodePacket(bytes, firstLayer.value as LayerId | 'auto')
  result.classList.remove('hidden')
  renderResultHead(summary, parsed)
  hexview.setData(bytes)
  tree.set(parsed.regions)
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

