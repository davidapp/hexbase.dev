import { bytesToHex, formatSize } from '@core/bytes'
import { describeChain, parseAnyDer, parseCertificate, splitPem, type CertParse } from '@core/x509'
import { $, bindShare, el, HexView, hideMsg, initChrome, loadShare, RegionTree, renderResultHead, shareParam, showMsg, toast } from './ui'
import { SAMPLE_CHAIN_PEM } from './certSample'

initChrome()

const input = $<HTMLTextAreaElement>('#input')
const msg = $('#cert-msg')
const result = $('#result')
const summary = $('#summary')
const certinfo = $('#certinfo')
const fingerprints = $('#fingerprints')
const chainSection = $('#chain-section')
const chainList = $('#chain')
const chainCount = $('#chain-count')

const hexview = new HexView($('#hexview'))
const tree = new RegionTree($('#tree'), $('#note'))
tree.onSelect = (region) => hexview.highlight(region.offset, region.length)

/** What Share uploads: the pasted text (so a whole chain round-trips) or the dropped DER. */
let currentInput: Uint8Array | null = null

async function renderFingerprints(der: Uint8Array): Promise<void> {
  fingerprints.textContent = ''
  for (const alg of ['SHA-256', 'SHA-1'] as const) {
    const digest = new Uint8Array(await crypto.subtle.digest(alg, new Uint8Array(der)))
    const value = bytesToHex(digest, ':')
    const row = el('tr')
    row.append(el('td', '', alg))
    const td = el('td', 'copyable')
    td.dataset.copy = value
    td.textContent = value
    td.style.wordBreak = 'break-all'
    row.append(td)
    fingerprints.append(row)
  }
}

/** Render one certificate (or, failing that, its generic ASN.1 tree). */
function showDer(der: Uint8Array): void {
  try {
    const parsed = parseCertificate(der)
    renderResultHead(summary, parsed.result)
    tree.set(parsed.result.regions)
  } catch (e) {
    try {
      const generic = parseAnyDer(der)
      renderResultHead(summary, generic)
      tree.set(generic.regions)
    } catch {
      showMsg(msg, 'err', e instanceof Error ? e.message : String(e))
      result.classList.add('hidden')
      return
    }
  }
  certinfo.textContent = formatSize(der.length)
  hexview.setData(der)
  result.classList.remove('hidden')
  void renderFingerprints(der)
}

const cnOf = (rdn: string): string => rdn.match(/CN=([^,]+)/)?.[1] ?? rdn

/** The chain panel: one row per certificate, ↑ ↓ to move, click/Enter to inspect. */
function renderChain(certs: CertParse[]): void {
  const links = describeChain(certs)
  chainList.textContent = ''
  chainList.setAttribute('role', 'listbox')
  chainList.setAttribute('aria-label', 'certificate chain')
  chainCount.textContent = `${certs.length} certificates`
  let selected: HTMLElement | null = null
  const select = (row: HTMLElement, c: CertParse) => {
    selected?.classList.remove('sel')
    selected?.setAttribute('aria-selected', 'false')
    if (selected) selected.tabIndex = -1
    row.classList.add('sel')
    row.setAttribute('aria-selected', 'true')
    row.tabIndex = 0
    selected = row
    showDer(c.der)
  }
  certs.forEach((c, i) => {
    const link = links[i]
    const row = el('div', 'chainrow')
    row.setAttribute('role', 'option')
    row.setAttribute('aria-selected', 'false')
    row.tabIndex = -1
    const until = c.facts.notAfter ? c.facts.notAfter.toISOString().slice(0, 10) : '?'
    row.append(el('span', 'cnum', `#${i + 1}`), el('span', 'crole', link.role), el('span', 'cname', `${cnOf(c.facts.subject)} · until ${until}`))
    const linkSpan = el('span', 'clink')
    linkSpan.append(document.createTextNode(link.notes.join(' · ') + (link.keyIdMatch === null ? '' : ' ')))
    if (link.keyIdMatch !== null) linkSpan.append(el('span', link.keyIdMatch ? 'ok' : 'bad', link.keyIdMatch ? '✓ key id' : '✗ key id'))
    row.append(linkSpan)
    row.addEventListener('click', () => select(row, c))
    chainList.append(row)
  })
  chainList.onkeydown = (e) => {
    const row = (e.target as HTMLElement).closest<HTMLElement>('.chainrow')
    if (!row) return
    const rows = [...chainList.querySelectorAll<HTMLElement>('.chainrow')]
    const i = rows.indexOf(row)
    const target = e.key === 'ArrowDown' ? rows[i + 1] : e.key === 'ArrowUp' ? rows[i - 1] : e.key === 'Home' ? rows[0] : e.key === 'End' ? rows[rows.length - 1] : undefined
    if (!target) return
    e.preventDefault()
    target.focus()
    target.click()
  }
  chainSection.classList.remove('hidden')
  const first = chainList.firstElementChild as HTMLElement | null
  if (first) select(first, certs[0])
}

/** Entry point for pasted text, dropped files and shared payloads. */
function decodeInput(raw: Uint8Array | string): void {
  hideMsg(msg)
  let ders: Uint8Array[]
  try {
    ders = splitPem(raw)
  } catch (e) {
    showMsg(msg, 'err', e instanceof Error ? e.message : String(e))
    result.classList.add('hidden')
    chainSection.classList.add('hidden')
    return
  }
  currentInput = typeof raw === 'string' ? new TextEncoder().encode(raw) : raw
  if (ders.length <= 1) {
    chainSection.classList.add('hidden')
    showDer(ders[0])
    return
  }
  const parsed = ders.map((d) => {
    try {
      return parseCertificate(d)
    } catch {
      return null
    }
  })
  const certs = parsed.filter((p): p is CertParse => p !== null)
  if (certs.length < parsed.length) {
    showMsg(msg, 'warn', `${parsed.length - certs.length} of ${parsed.length} blocks are not certificates and were skipped`)
  }
  if (certs.length === 0) {
    chainSection.classList.add('hidden')
    showDer(ders[0])
    return
  }
  renderChain(certs)
}

function decode(): void {
  decodeInput(input.value)
}

$('#decode').addEventListener('click', decode)
input.addEventListener('keydown', (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') decode()
})

$('#clear').addEventListener('click', () => {
  input.value = ''
  hideMsg(msg)
  result.classList.add('hidden')
  chainSection.classList.add('hidden')
  fingerprints.textContent = ''
  currentInput = null
})

$('#sample').addEventListener('click', () => {
  input.value = SAMPLE_CHAIN_PEM
  decode()
})

// drop a .crt/.cer/.der/.pem (or fullchain.pem) file anywhere
document.addEventListener('dragover', (e) => e.preventDefault())
document.addEventListener('drop', (e) => {
  e.preventDefault()
  const file = e.dataTransfer?.files?.[0]
  if (!file) return
  if (file.size > 1024 * 1024) {
    showMsg(msg, 'err', `${file.name} is ${formatSize(file.size)} — that's not a certificate (limit 1 MB)`)
    return
  }
  void file.arrayBuffer().then((buf) => {
    const bytes = new Uint8Array(buf)
    if (bytes[0] === 0x30) {
      input.value = `(binary DER from ${file.name} — ${formatSize(bytes.length)})`
      decodeInput(bytes)
    } else {
      input.value = new TextDecoder().decode(bytes)
      decode()
    }
  })
})

bindShare($('#share'), 'cert', () => (currentInput ? { bytes: currentInput } : null))

const code = shareParam()
if (code) {
  loadShare(code)
    .then(({ bytes }) => {
      if (bytes[0] === 0x30) {
        input.value = `(shared binary DER — ${formatSize(bytes.length)})`
        decodeInput(bytes)
      } else {
        input.value = new TextDecoder().decode(bytes)
        decode()
      }
      toast('Loaded shared certificate')
    })
    .catch((e) => showMsg(msg, 'err', e instanceof Error ? e.message : 'failed to load share'))
}
