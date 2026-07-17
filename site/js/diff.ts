import { diffJson, diffLines, diffStats, type DiffEntry, type LineDiffOp } from '@core/jsonDiff'
import { parseJson, type JsonError } from '@core/jsonTool'
import { $, bindShare, copyText, el, hideMsg, initChrome, loadShare, shareParam, showMsg, toast } from './ui'

initChrome()

const left = $<HTMLTextAreaElement>('#left')
const right = $<HTMLTextAreaElement>('#right')
const msg = $('#diff-msg')
const stats = $('#diff-stats')
const resultSection = $('#diff-result')
const resultTitle = $('#diff-title')
const out = $('#diff-out')
const modeJson = $<HTMLButtonElement>('#mode-json')
const modeText = $<HTMLButtonElement>('#mode-text')

let mode: 'json' | 'text' = 'json'
let copyPayload = ''

const RENDER_ROW_LIMIT = 3000

function setMode(m: 'json' | 'text'): void {
  mode = m
  modeJson.setAttribute('aria-selected', String(m === 'json'))
  modeText.setAttribute('aria-selected', String(m === 'text'))
}
modeJson.addEventListener('click', () => setMode('json'))
modeText.addEventListener('click', () => setMode('text'))

function sideError(side: 'left' | 'right', err: JsonError): string {
  const pos = err.line != null ? ` at line ${err.line}, column ${err.column}` : ''
  return `${side} document is not valid JSON${pos}: ${err.message}`
}

const KIND_BADGE: Record<DiffEntry['kind'], { cls: string; label: string }> = {
  added: { cls: 'ok', label: '+' },
  removed: { cls: 'bad', label: '−' },
  changed: { cls: 'warn', label: '~' },
  type: { cls: 'warn', label: 'T' },
}

function compareJson(): void {
  const a = parseJson(left.value)
  if (!a.ok) {
    showMsg(msg, 'err', sideError('left', a.error))
    resultSection.classList.add('hidden')
    return
  }
  const b = parseJson(right.value)
  if (!b.ok) {
    showMsg(msg, 'err', sideError('right', b.error))
    resultSection.classList.add('hidden')
    return
  }
  const entries = diffJson(a.value, b.value)
  const s = diffStats(entries)
  stats.textContent = entries.length
    ? `${entries.length} difference${entries.length === 1 ? '' : 's'} · +${s.added} added · −${s.removed} removed · ~${s.changed} changed · ${s.type} type`
    : ''
  if (entries.length === 0) {
    showMsg(msg, 'ok', 'Structurally identical — same values at every path (key order and formatting ignored).')
    resultSection.classList.add('hidden')
    return
  }
  hideMsg(msg)
  out.textContent = ''
  const frag = document.createDocumentFragment()
  const shown = Math.min(entries.length, RENDER_ROW_LIMIT)
  for (let i = 0; i < shown; i++) {
    const e = entries[i]
    const row = el('div', 'drow')
    const badge = KIND_BADGE[e.kind]
    row.append(el('span', `dkind badge ${badge.cls}`, badge.label))
    row.append(el('span', 'dpath', e.path))
    const vals = el('span', 'dvals')
    if (e.kind === 'added') vals.textContent = `+ ${e.right}`
    else if (e.kind === 'removed') vals.textContent = `− ${e.left}`
    else vals.textContent = `${e.left}  →  ${e.right}`
    row.append(vals)
    frag.append(row)
  }
  out.append(frag)
  resultTitle.textContent =
    shown < entries.length ? `differences (showing ${shown} of ${entries.length})` : 'differences'
  resultSection.classList.remove('hidden')
  copyPayload = entries
    .map((e) => `${e.path}: ${e.kind === 'added' ? `+ ${e.right}` : e.kind === 'removed' ? `- ${e.left}` : `${e.left} -> ${e.right}`}`)
    .join('\n')
}

function compareText(): void {
  const ops = diffLines(left.value, right.value)
  const adds = ops.filter((o) => o.kind === 'add').length
  const dels = ops.filter((o) => o.kind === 'del').length
  stats.textContent = adds + dels === 0 ? '' : `+${adds} −${dels} lines`
  if (adds + dels === 0) {
    showMsg(msg, 'ok', 'The two texts are identical.')
    resultSection.classList.add('hidden')
    return
  }
  hideMsg(msg)
  out.textContent = ''
  const frag = document.createDocumentFragment()
  const shown = Math.min(ops.length, RENDER_ROW_LIMIT)
  for (let i = 0; i < shown; i++) {
    const op: LineDiffOp = ops[i]
    const row = el('div', `dline ${op.kind}`)
    row.append(el('span', 'ln', op.aLine ? String(op.aLine) : ''))
    row.append(el('span', 'ln', op.bLine ? String(op.bLine) : ''))
    row.append(el('span', 'dmark', op.kind === 'add' ? '+' : op.kind === 'del' ? '−' : ' '))
    row.append(el('span', 'dtext', op.text))
    frag.append(row)
  }
  out.append(frag)
  resultTitle.textContent = shown < ops.length ? `line diff (showing ${shown} of ${ops.length} lines)` : 'line diff'
  resultSection.classList.remove('hidden')
  copyPayload = ops.map((o) => `${o.kind === 'add' ? '+' : o.kind === 'del' ? '-' : ' '}${o.text}`).join('\n')
}

function compare(): void {
  if (mode === 'json') compareJson()
  else compareText()
}

$('#compare').addEventListener('click', compare)
for (const t of [left, right]) {
  t.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') compare()
  })
}

$('#swap').addEventListener('click', () => {
  const tmp = left.value
  left.value = right.value
  right.value = tmp
  if (!resultSection.classList.contains('hidden') || msg.classList.contains('ok')) compare()
})

$('#clear').addEventListener('click', () => {
  left.value = ''
  right.value = ''
  hideMsg(msg)
  stats.textContent = ''
  resultSection.classList.add('hidden')
})

$('#copy-diff').addEventListener('click', () => void copyText(copyPayload))

$('#sample').addEventListener('click', () => {
  left.value = JSON.stringify(
    {
      service: 'billing',
      version: 3,
      owner: { team: 'payments', oncall: 'ada' },
      regions: ['us-east-1', 'eu-west-1'],
      limits: { rps: 100, burst: 200 },
      deprecated: true,
    },
    null,
    2,
  )
  right.value = JSON.stringify(
    {
      version: '4',
      service: 'billing',
      owner: { team: 'payments', oncall: 'grace', slack: '#payments' },
      regions: ['us-east-1', 'eu-west-1', 'ap-south-1'],
      limits: { rps: 250, burst: 200 },
    },
    null,
    2,
  )
  setMode('json')
  compare()
})

// share: both documents + mode as one JSON payload
bindShare($('#share'), 'diff', () => {
  if (!left.value && !right.value) return null
  const payload = JSON.stringify({ mode, left: left.value, right: right.value })
  return { bytes: new TextEncoder().encode(payload) }
})

const code = shareParam()
if (code) {
  loadShare(code)
    .then(({ bytes }) => {
      const data = JSON.parse(new TextDecoder().decode(bytes)) as { mode?: string; left?: string; right?: string }
      left.value = data.left ?? ''
      right.value = data.right ?? ''
      setMode(data.mode === 'text' ? 'text' : 'json')
      compare()
      toast('Loaded shared comparison')
    })
    .catch((e) => showMsg(msg, 'err', e instanceof Error ? e.message : 'failed to load share'))
}
