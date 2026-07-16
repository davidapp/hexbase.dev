import { formatJson, jsonStats, minifyJson, parseJson, toTypeScript } from '@core/jsonTool'
import { $, bindShare, copyText, el, hideMsg, initChrome, initTabs, loadShare, shareParam, showMsg, toast } from './ui'

initChrome()
initTabs(document.body)

const input = $<HTMLTextAreaElement>('#input')
const output = $('#output')
const msg = $('#json-msg')
const errctx = $('#errctx')
const treeBox = $('#tree')
const treePath = $('#treepath')
const statsTable = $<HTMLTableElement>('#stats')
const indentSel = $<HTMLSelectElement>('#indent')
const sortChk = $<HTMLInputElement>('#sort')

const SAMPLE = `{
  "service": "hexbase",
  "version": 1,
  "tools": [
    { "id": "hex", "name": "Hex Inspector", "formats": 30 },
    { "id": "packet", "name": "Packet Decoder", "layers": ["eth", "ip", "tcp", "dns"] }
  ],
  "local_first": true,
  "uptime_target": 0.9999,
  "big_id_as_string": "9007199254740993",
  "released": null
}`

function indent(): number | '\t' {
  return indentSel.value === 'tab' ? '\t' : Number(indentSel.value)
}

function validateAndSideEffects(): unknown | undefined {
  const parsed = parseJson(input.value)
  if (parsed.ok) {
    hideMsg(msg)
    errctx.classList.add('hidden')
    renderTree(parsed.value)
    renderStats(parsed.value)
    return parsed.value
  }
  const { error } = parsed
  const where = error.line !== undefined ? ` at line ${error.line}, column ${error.column}` : ''
  showMsg(msg, 'err', `✗ invalid JSON${where}: ${error.message}`)
  if (error.index !== undefined && error.line !== undefined) {
    const lines = input.value.split('\n')
    const lineText = lines[error.line - 1] ?? ''
    const col = (error.column ?? 1) - 1
    errctx.textContent = `${String(error.line).padStart(4)} │ ${lineText}\n     │ ${' '.repeat(Math.max(0, col))}▲`
    errctx.classList.remove('hidden')
  } else {
    errctx.classList.add('hidden')
  }
  treeBox.textContent = ''
  statsTable.textContent = ''
  return undefined
}

$('#format').addEventListener('click', () => {
  if (validateAndSideEffects() === undefined) return
  output.textContent = formatJson(input.value, indent(), sortChk.checked)
  toast('Formatted')
})

$('#minify').addEventListener('click', () => {
  if (validateAndSideEffects() === undefined) return
  const out = minifyJson(input.value)
  output.textContent = out
  toast(`Minified — ${input.value.length.toLocaleString()} → ${out.length.toLocaleString()} chars`)
})

$('#typescript').addEventListener('click', () => {
  const value = validateAndSideEffects()
  if (value === undefined) return
  output.textContent = toTypeScript(value, 'Root')
  toast('Generated TypeScript')
})

$('#copy').addEventListener('click', () => void copyText(output.textContent ?? ''))
$('#sample').addEventListener('click', () => {
  input.value = SAMPLE
  output.textContent = formatJson(SAMPLE, indent(), false)
  validateAndSideEffects()
})
$('#clear').addEventListener('click', () => {
  input.value = ''
  output.textContent = ''
  treeBox.textContent = ''
  statsTable.textContent = ''
  hideMsg(msg)
  errctx.classList.add('hidden')
})

let debounceTimer: ReturnType<typeof setTimeout> | undefined
input.addEventListener('input', () => {
  clearTimeout(debounceTimer)
  debounceTimer = setTimeout(() => {
    if (input.value.trim()) validateAndSideEffects()
  }, 350)
})

// ---------------------------------------------------------------- tree view

function renderTree(value: unknown): void {
  treeBox.textContent = ''
  treeBox.append(treeNode('$', value, '$', 0))
}

function treeNode(label: string, value: unknown, path: string, depth: number): HTMLElement {
  const node = el('div', 'tnode')
  const row = el('div', 'trow')
  const tw = el('span', 'tw')
  const isObj = value !== null && typeof value === 'object'
  const entries: [string, unknown][] = Array.isArray(value)
    ? value.map((v, i) => [String(i), v] as [string, unknown])
    : isObj
      ? Object.entries(value as object)
      : []
  tw.textContent = entries.length ? (depth >= 2 ? '▸' : '▾') : '·'
  row.append(tw, el('span', 'tname', label))

  if (Array.isArray(value)) row.append(el('span', 'tval', `[ ${value.length} item${value.length === 1 ? '' : 's'} ]`))
  else if (isObj) row.append(el('span', 'tval', `{ ${entries.length} key${entries.length === 1 ? '' : 's'} }`))
  else row.append(el('span', 'tval', JSON.stringify(value)))

  node.append(row)
  if (entries.length) {
    const kids = el('div', 'tkids')
    for (const [k, v] of entries) {
      const childPath = Array.isArray(value) ? `${path}[${k}]` : /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(k) ? `${path}.${k}` : `${path}[${JSON.stringify(k)}]`
      kids.append(treeNode(k, v, childPath, depth + 1))
    }
    node.append(kids)
    if (depth >= 2) node.classList.add('collapsed')
    tw.addEventListener('click', (e) => {
      e.stopPropagation()
      const collapsed = node.classList.toggle('collapsed')
      tw.textContent = collapsed ? '▸' : '▾'
    })
  }
  row.addEventListener('click', () => {
    treePath.innerHTML = ''
    const b = el('b', '', path)
    b.classList.add('copyable')
    b.title = 'click shown path to copy'
    treePath.append(b, el('span', 'dim', '  · click to copy path'))
  })
  return node
}

// ---------------------------------------------------------------- stats

function renderStats(value: unknown): void {
  const s = jsonStats(value)
  const bytes = new TextEncoder().encode(input.value).length
  const rows: [string, string][] = [
    ['size', `${bytes.toLocaleString()} bytes (${input.value.length.toLocaleString()} chars)`],
    ['max depth', String(s.maxDepth)],
    ['objects', String(s.objects)],
    ['arrays', String(s.arrays)],
    ['keys', String(s.keys)],
    ['strings', String(s.strings)],
    ['numbers', String(s.numbers)],
    ['booleans / nulls', `${s.booleans} / ${s.nulls}`],
  ]
  statsTable.innerHTML = ''
  for (const [k, v] of rows) {
    const tr = el('tr')
    tr.append(el('th', '', k), el('td', 'mono', v))
    statsTable.append(tr)
  }
}

// ---------------------------------------------------------------- share

bindShare($('#share'), 'json', () => {
  const text = input.value.trim()
  return text ? { bytes: new TextEncoder().encode(text) } : null
})

const code = shareParam()
if (code) {
  loadShare(code)
    .then(({ bytes }) => {
      input.value = new TextDecoder().decode(bytes)
      validateAndSideEffects()
      output.textContent = ''
      toast('Loaded shared JSON')
    })
    .catch((e) => showMsg(msg, 'err', e instanceof Error ? e.message : 'failed to load share'))
}
