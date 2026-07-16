import { EPOCHS, interpretNumber, isoUtc, parseDateString, relativeTime } from '@core/timestamp'
import { $, el, hideMsg, initChrome, showMsg } from './ui'

initChrome()

const input = $<HTMLInputElement>('#input')
const msg = $('#ts-msg')
const interpSection = $('#interp-section')
const interpTable = $<HTMLTableElement>('#interp')
const detailSection = $('#detail-section')
const detailTitle = $('#detail-title')
const detailTable = $<HTMLTableElement>('#detail')
const zonesTable = $<HTMLTableElement>('#zones')
const nowTable = $<HTMLTableElement>('#now-table')

const ZONES = ['UTC', 'America/Los_Angeles', 'America/New_York', 'Europe/London', 'Europe/Berlin', 'Asia/Shanghai', 'Asia/Tokyo', 'Australia/Sydney']

function copyableCell(text: string): HTMLTableCellElement {
  const td = el('td', 'mono')
  const span = el('span', 'copyable', text)
  td.append(span)
  return td
}

function kvRow(table: HTMLTableElement, key: string, value: string, dimNote = ''): void {
  const tr = el('tr')
  tr.append(el('th', '', key))
  tr.append(copyableCell(value))
  const note = el('td', 'dim', dimNote)
  note.style.width = '40%'
  tr.append(note)
  table.append(tr)
}

// ---------------------------------------------------------------- live "now"

function renderNow(): void {
  const ms = Date.now()
  nowTable.innerHTML = ''
  kvRow(nowTable, 'unix seconds', String(Math.floor(ms / 1000)))
  kvRow(nowTable, 'unix millis', String(ms))
  kvRow(nowTable, 'ISO 8601 UTC', isoUtc(ms))
  kvRow(nowTable, 'local', new Date(ms).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'long' }))
}
renderNow()
setInterval(renderNow, 1000)

// ---------------------------------------------------------------- conversion

function showDetail(ms: number, sourceLabel: string): void {
  detailSection.classList.remove('hidden')
  detailTitle.textContent = sourceLabel
  detailTable.innerHTML = ''
  const d = new Date(ms)
  kvRow(detailTable, 'ISO 8601 UTC', isoUtc(ms))
  kvRow(detailTable, 'ISO 8601 local', localIso(d))
  kvRow(detailTable, 'RFC 2822 style', d.toUTCString())
  kvRow(detailTable, 'relative', relativeTime(ms, Date.now()))
  kvRow(detailTable, 'day', d.toLocaleDateString('en-US', { weekday: 'long', timeZone: 'UTC' }) + ` · day ${dayOfYear(d)} of the year, ISO week ${isoWeek(d)}`)
  for (const epoch of EPOCHS) {
    try {
      kvRow(detailTable, epoch.name, epoch.fromUnixMs(ms), `${epoch.unit} since ${epoch.origin}`)
    } catch {
      /* out of range for this epoch */
    }
  }

  zonesTable.innerHTML = ''
  for (const zone of ZONES) {
    const fmt = new Intl.DateTimeFormat('en-CA', {
      timeZone: zone,
      dateStyle: 'short',
      timeStyle: 'long',
      hour12: false,
    })
    kvRow(zonesTable, zone.replace('_', ' '), fmt.format(d))
  }
}

function localIso(d: Date): string {
  const offset = -d.getTimezoneOffset()
  const sign = offset >= 0 ? '+' : '-'
  const abs = Math.abs(offset)
  const pad = (n: number) => String(n).padStart(2, '0')
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
    `T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}` +
    `${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)}`
  )
}

function dayOfYear(d: Date): number {
  return Math.floor((d.getTime() - Date.UTC(d.getUTCFullYear(), 0, 0)) / 86400000)
}

function isoWeek(d: Date): number {
  const date = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()))
  const dayNum = date.getUTCDay() || 7
  date.setUTCDate(date.getUTCDate() + 4 - dayNum)
  const yearStart = Date.UTC(date.getUTCFullYear(), 0, 1)
  return Math.ceil(((date.getTime() - yearStart) / 86400000 + 1) / 7)
}

function convert(): void {
  const raw = input.value.trim()
  hideMsg(msg)
  interpSection.classList.add('hidden')
  detailSection.classList.add('hidden')
  if (!raw) return

  if (/^-?\d+(\.\d+)?$/.test(raw)) {
    const readings = interpretNumber(raw)
    interpSection.classList.remove('hidden')
    interpTable.innerHTML = ''
    const head = el('tr')
    head.append(el('th', '', 'read as'), el('th', '', 'UTC instant'), el('th', '', 'relative'))
    interpTable.append(head)
    let first: (typeof readings)[number] | null = null
    for (const reading of readings) {
      const tr = el('tr')
      tr.style.cursor = 'pointer'
      if (!reading.plausible) tr.style.opacity = '0.45'
      const name = el('th', '', reading.epoch.name)
      const when = el('td', 'mono', safeIso(reading.unixMs))
      const rel = el('td', 'dim', Number.isFinite(reading.unixMs) ? relativeTime(reading.unixMs, Date.now()) : '')
      tr.append(name, when, rel)
      tr.addEventListener('click', () => showDetail(reading.unixMs, `${raw} as ${reading.epoch.name}`))
      interpTable.append(tr)
      if (!first && reading.plausible) first = reading
    }
    if (first) {
      showDetail(first.unixMs, `${raw} as ${first.epoch.name}`)
    } else {
      showMsg(msg, 'warn', 'no epoch puts this number between 1975 and 2120 — showing all readings anyway')
    }
    return
  }

  const ms = parseDateString(raw)
  if (ms === null) {
    showMsg(msg, 'err', `could not parse "${raw}" as a number or a date string (try ISO 8601: 2026-07-16T12:00:00Z)`)
    return
  }
  showDetail(ms, raw)
}

function safeIso(ms: number): string {
  try {
    return isoUtc(ms)
  } catch {
    return '(out of Date range)'
  }
}

$('#convert').addEventListener('click', convert)
input.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') convert()
})
$('#use-now').addEventListener('click', () => {
  input.value = String(Date.now())
  convert()
})

// ---------------------------------------------------------------- epoch reference table (from the same data the converter uses)

const epochTbody = $('#epoch-table tbody')
for (const epoch of EPOCHS) {
  if (epoch.id === 'unix_us' || epoch.id === 'unix_ns') continue
  const tr = el('tr')
  tr.append(el('td', '', epoch.name), el('td', '', epoch.unit), el('td', '', epoch.origin), el('td', '', epoch.note))
  epochTbody.append(tr)
}

// deep-linkable: /tools/timestamp/?t=1700000000
const preset = new URLSearchParams(location.search).get('t')
if (preset) {
  input.value = preset
  convert()
}
