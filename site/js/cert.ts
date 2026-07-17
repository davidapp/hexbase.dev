import { bytesToHex, formatSize } from '@core/bytes'
import { parseAnyDer, parseCertificate, toDer } from '@core/x509'
import { $, bindShare, el, HexView, hideMsg, initChrome, loadShare, RegionTree, renderResultHead, shareParam, showMsg, toast } from './ui'

initChrome()

const input = $<HTMLTextAreaElement>('#input')
const msg = $('#cert-msg')
const result = $('#result')
const summary = $('#summary')
const certinfo = $('#certinfo')
const fingerprints = $('#fingerprints')

const hexview = new HexView($('#hexview'))
const tree = new RegionTree($('#tree'), $('#note'))
tree.onSelect = (region) => hexview.highlight(region.offset, region.length)

let currentDer: Uint8Array | null = null

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

function decode(): void {
  hideMsg(msg)
  let der: Uint8Array
  try {
    der = toDer(input.value)
  } catch (e) {
    showMsg(msg, 'err', e instanceof Error ? e.message : String(e))
    result.classList.add('hidden')
    return
  }
  decodeDer(der)
}

function decodeDer(der: Uint8Array): void {
  currentDer = der
  try {
    const parsed = parseCertificate(der)
    renderResultHead(summary, parsed.result)
    tree.set(parsed.result.regions)
  } catch (e) {
    // Not a certificate — fall back to the generic ASN.1 tree when it's valid DER.
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

$('#decode').addEventListener('click', decode)
input.addEventListener('keydown', (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') decode()
})

$('#clear').addEventListener('click', () => {
  input.value = ''
  hideMsg(msg)
  result.classList.add('hidden')
  fingerprints.textContent = ''
  currentDer = null
})

// Real leaf certificate for example.com (fetched 2026-07; expires 2026-08 — the
// expiry countdown demonstrating itself is part of the lesson).
const SAMPLE_PEM = `-----BEGIN CERTIFICATE-----
MIID5zCCA42gAwIBAgIQGqc/6iV74zNLmilVLm+HjjAKBggqhkjOPQQDAjBRMQsw
CQYDVQQGEwJVUzEYMBYGA1UECgwPU1NMIENvcnBvcmF0aW9uMSgwJgYDVQQDDB9D
bG91ZGZsYXJlIFRMUyBJc3N1aW5nIEVDQyBDQSAzMB4XDTI2MDUzMTIxMzkxMloX
DTI2MDgyOTIxNDEyNlowFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAAR3K9vg9mgByiZluphXApVAUpQtIO9MPLbbdVxu2SDI
KEYKZhTqszaA9lNa6oAGtsi++/m+uwI35sAG+zkIpAeOo4ICgDCCAnwwDAYDVR0T
AQH/BAIwADAfBgNVHSMEGDAWgBSDA/3n9vVKTRVB9O0iFtMyCj7KZjBsBggrBgEF
BQcBAQRgMF4wOQYIKwYBBQUHMAKGLWh0dHA6Ly9pLmNmLWkuc3NsLmNvbS9DbG91
ZGZsYXJlLVRMUy1JLUUzLmNlcjAhBggrBgEFBQcwAYYVaHR0cDovL28uY2YtaS5z
c2wuY29tMCUGA1UdEQQeMByCC2V4YW1wbGUuY29tgg0qLmV4YW1wbGUuY29tMCMG
A1UdIAQcMBowCAYGZ4EMAQIBMA4GDCsGAQQBgqkwAQMBATATBgNVHSUEDDAKBggr
BgEFBQcDATBTBgNVHR8ETDBKMEigRqBEhkJodHRwOi8vYy5jZi1pLnNzbC5jb20v
YWU4MDFlZDFjNTViYjU3OWQ3OTIwOGIwZDc3MmFjZmI4Y2MzYTIwOC5jcmwwDgYD
VR0PAQH/BAQDAgeAMA8GCSsGAQQBgtpLLAQCBQAwggEEBgorBgEEAdZ5AgQCBIH1
BIHyAPAAdgCUTkOH+uzB74HzGSQmqBhlAcfTXzgCAT9yZ31VNy4Z2AAAAZ6AAzGJ
AAAEAwBHMEUCIQCBv0JM0mXaiiQ9efuArkk3O2t/RQ39q7O3oKtYCvOUhQIgdn2u
t5rn+AWzBqZ9m1VOlMLpT/jy2M92Is6itMy9rR8AdgDIo8R/x7OtuTVrAT9qehJt
4zpOQ6XGRvmXrTl1mR3PmgAAAZ6AAzGgAAAEAwBHMEUCIQCoc8r0LVigaz6pvG8s
v0+uBqzf+LPNPxwYxtgkuVdNMwIgAbK/qRNJIWljIVp30PFWjmM+SnoT80ShaPJM
GdbtNLMwCgYIKoZIzj0EAwIDSAAwRQIhALDciGbviRHUIMPez2CVH+Vc0NiaT8Br
FrUGD7dej3D4AiAfs90UtVHGYKTXYYPIJlVqUK1amlBBby7M2KI7pSMjxA==
-----END CERTIFICATE-----`

$('#sample').addEventListener('click', () => {
  input.value = SAMPLE_PEM
  decode()
})

// drop a .crt/.cer/.der/.pem file anywhere
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
    try {
      const der = toDer(bytes)
      if (der === bytes) input.value = `(binary DER from ${file.name} — ${formatSize(der.length)})`
      else input.value = new TextDecoder().decode(bytes)
      decodeDer(der)
    } catch (err) {
      showMsg(msg, 'err', err instanceof Error ? err.message : String(err))
    }
  })
})

bindShare($('#share'), 'cert', () => (currentDer ? { bytes: currentDer } : null))

const code = shareParam()
if (code) {
  loadShare(code)
    .then(({ bytes }) => {
      const der = toDer(bytes)
      if (der !== bytes) input.value = new TextDecoder().decode(bytes)
      else input.value = `(shared binary DER — ${formatSize(der.length)})`
      decodeDer(der)
      toast('Loaded shared certificate')
    })
    .catch((e) => showMsg(msg, 'err', e instanceof Error ? e.message : 'failed to load share'))
}
