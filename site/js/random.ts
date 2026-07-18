import { ALPHABETS, entropyBits, group, randomString, sweepTime, type Radix } from '@core/random'
import { $, copyText, el, hideMsg, initChrome, showMsg, toast } from './ui'

initChrome()

const UI_MAX = 4096

const lenInput = $<HTMLInputElement>('#len')
const countSel = $<HTMLSelectElement>('#count')
const groupedCb = $<HTMLInputElement>('#grouped')
const upperCb = $<HTMLInputElement>('#upper')
const upperWrap = $('#upper-wrap')
const results = $('#results')
const entropyNote = $('#entropy-note')
const msg = $('#rand-msg')
const baseButtons = [...document.querySelectorAll<HTMLButtonElement>('#base-tabs button')]

let base: Radix = 16
let strings: string[] = [] // always stored lowercase/ungrouped; display transforms apply at render

function currentLength(): number | null {
  const n = Number(lenInput.value)
  if (!Number.isInteger(n) || n < 1 || n > UI_MAX) return null
  return n
}

function setBase(next: Radix): void {
  base = next
  baseButtons.forEach((b) => b.setAttribute('aria-selected', String(Number(b.dataset.base) === next)))
  upperWrap.classList.toggle('hidden', next !== 16)
}

function display(s: string): string {
  const cased = base === 16 && upperCb.checked ? s.toUpperCase() : s
  if (!groupedCb.checked) return cased
  return group(cased, base === 2 ? 8 : 4)
}

function render(): void {
  results.innerHTML = ''
  for (const s of strings) {
    const pre = el('pre', 'out copyable', display(s))
    pre.dataset.copy = base === 16 && upperCb.checked ? s.toUpperCase() : s
    pre.style.margin = '0 0 8px'
    pre.title = 'Click to copy'
    results.append(pre)
  }
}

function updateEntropy(): void {
  const length = currentLength()
  if (length === null) {
    entropyNote.textContent = ''
    return
  }
  const bits = entropyBits(base, length)
  const rounded = Number.isInteger(bits) ? String(bits) : bits.toFixed(1)
  const unit = base === 10 ? 'decimal digits' : base === 2 ? 'binary digits' : 'hex chars'
  entropyNote.textContent = `${length} ${unit} = ${rounded} bits of entropy · sweeping that keyspace at 10¹² guesses/s takes ${sweepTime(bits)}`
}

function generate(): void {
  hideMsg(msg)
  const length = currentLength()
  if (length === null) {
    showMsg(msg, 'err', `length must be a whole number between 1 and ${UI_MAX}`)
    return
  }
  const count = Number(countSel.value)
  strings = Array.from({ length: count }, () => randomString(ALPHABETS[base], length))
  render()
  updateEntropy()
}

baseButtons.forEach((b) =>
  b.addEventListener('click', () => {
    setBase(Number(b.dataset.base) as Radix)
    generate()
  }),
)

document.querySelectorAll<HTMLButtonElement>('.len-preset').forEach((b) =>
  b.addEventListener('click', () => {
    lenInput.value = b.dataset.len!
    generate()
  }),
)

document.querySelectorAll<HTMLButtonElement>('.key-preset').forEach((b) =>
  b.addEventListener('click', () => {
    setBase(Number(b.dataset.base) as Radix)
    lenInput.value = b.dataset.len!
    generate()
  }),
)

$('#generate').addEventListener('click', generate)
lenInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') generate()
})
lenInput.addEventListener('input', updateEntropy)
countSel.addEventListener('change', generate)
groupedCb.addEventListener('change', render)
upperCb.addEventListener('change', render)

$('#copy-all').addEventListener('click', () => {
  if (strings.length === 0) {
    toast('Nothing to copy yet')
    return
  }
  const cased = base === 16 && upperCb.checked ? strings.map((s) => s.toUpperCase()) : strings
  void copyText(cased.join('\n'))
})

// deep-linkable: /tools/random/?base=16&len=64&n=5&upper=1
const params = new URLSearchParams(location.search)
const paramBase = Number(params.get('base'))
if (paramBase === 2 || paramBase === 10 || paramBase === 16) setBase(paramBase)
else setBase(16)
const paramLen = Number(params.get('len'))
if (Number.isInteger(paramLen) && paramLen >= 1 && paramLen <= UI_MAX) lenInput.value = String(paramLen)
const paramCount = params.get('n')
if (paramCount && [...countSel.options].some((o) => o.value === paramCount)) countSel.value = paramCount
if (params.get('upper') === '1') upperCb.checked = true

generate()
