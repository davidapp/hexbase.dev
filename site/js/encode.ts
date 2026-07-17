import {
  base64ToBytes,
  base64ToText,
  binaryToText,
  escapeHtml,
  fromUnicodeEscapes,
  hexToText,
  inspectString,
  md5,
  textToBase64,
  textToBinary,
  textToHexBytes,
  toUnicodeEscapes,
  unescapeHtml,
  urlDecode,
  urlEncode,
} from '@core/encode'
import { bytesToHex } from '@core/bytes'
import { decodeJwt, JWT_CLAIM_NOTES, verifyJwtHmac } from '@core/jwt'
import { $, copyText, el, hideMsg, initChrome, initTabs, showMsg, toast } from './ui'

initChrome()
// deep-linkable tabs: /tools/encode/?tab=jwt opens the JWT panel (read before
// initTabs, whose initial activation rewrites the URL)
const tabParam = new URLSearchParams(location.search).get('tab')
initTabs(document.body, (id) => {
  history.replaceState(null, '', id === 'base64' ? location.pathname : `?tab=${id}`)
})
if (tabParam) {
  document.querySelector<HTMLButtonElement>(`#main-tabs button[data-tab="${CSS.escape(tabParam)}"]`)?.click()
}

// copy buttons for output panes
document.querySelectorAll<HTMLButtonElement>('.copy-out').forEach((btn) => {
  btn.addEventListener('click', () => {
    const target = document.getElementById(btn.dataset.for!)
    void copyText(target?.textContent ?? '')
  })
})

function attempt(msgEl: HTMLElement, outEl: HTMLElement, fn: () => string): void {
  try {
    outEl.textContent = fn()
    hideMsg(msgEl)
  } catch (e) {
    showMsg(msgEl, 'err', e instanceof Error ? e.message : String(e))
  }
}

// ---------------------------------------------------------------- base64

const b64In = $<HTMLTextAreaElement>('#b64-in')
const b64Out = $('#b64-out')
const b64Msg = $('#b64-msg')
const b64Url = $<HTMLInputElement>('#b64-url')

$('#b64-enc').addEventListener('click', () => attempt(b64Msg, b64Out, () => textToBase64(b64In.value, b64Url.checked)))
$('#b64-dec').addEventListener('click', () =>
  attempt(b64Msg, b64Out, () => {
    try {
      return base64ToText(b64In.value)
    } catch (e) {
      // not UTF-8? show the bytes as hex instead of failing
      const bytes = base64ToBytes(b64In.value)
      showMsg(b64Msg, 'warn', 'decoded bytes are not valid UTF-8 — showing hex')
      return bytesToHex(bytes)
    }
  }),
)

// ---------------------------------------------------------------- url

const urlIn = $<HTMLTextAreaElement>('#url-in')
const urlOut = $('#url-out')
const urlMsg = $('#url-msg')

$('#url-enc').addEventListener('click', () => attempt(urlMsg, urlOut, () => urlEncode(urlIn.value, $<HTMLInputElement>('#url-full').checked)))
$('#url-dec').addEventListener('click', () => attempt(urlMsg, urlOut, () => urlDecode(urlIn.value, $<HTMLInputElement>('#url-plus').checked)))

// ---------------------------------------------------------------- html

const htmlIn = $<HTMLTextAreaElement>('#html-in')
const htmlOut = $('#html-out')

$('#html-enc').addEventListener('click', () => {
  htmlOut.textContent = escapeHtml(htmlIn.value, $<HTMLInputElement>('#html-full').checked ? 'full' : 'minimal')
})
$('#html-dec').addEventListener('click', () => {
  htmlOut.textContent = unescapeHtml(htmlIn.value)
})

// ---------------------------------------------------------------- hex / binary

const hbIn = $<HTMLTextAreaElement>('#hb-in')
const hbOut = $('#hb-out')
const hbMsg = $('#hb-msg')

$('#hb-tohex').addEventListener('click', () => attempt(hbMsg, hbOut, () => textToHexBytes(hbIn.value)))
$('#hb-fromhex').addEventListener('click', () => attempt(hbMsg, hbOut, () => hexToText(hbIn.value)))
$('#hb-tobin').addEventListener('click', () => attempt(hbMsg, hbOut, () => textToBinary(hbIn.value)))
$('#hb-frombin').addEventListener('click', () => attempt(hbMsg, hbOut, () => binaryToText(hbIn.value)))

// ---------------------------------------------------------------- unicode

const uniIn = $<HTMLTextAreaElement>('#uni-in')
const uniOut = $('#uni-out')
const chargrid = $('#chargrid')
const uniNote = $('#uni-note')

$('#uni-enc').addEventListener('click', () => {
  uniOut.textContent = toUnicodeEscapes(uniIn.value, $<HTMLInputElement>('#uni-es6').checked)
})
$('#uni-dec').addEventListener('click', () => {
  uniOut.textContent = fromUnicodeEscapes(uniIn.value)
})
$('#uni-inspect').addEventListener('click', () => {
  const text = uniIn.value
  chargrid.textContent = ''
  const info = inspectString(text, 300)
  for (const ch of info) {
    const card = el('div', 'charcard')
    card.append(el('div', 'ch', ch.char === ' ' ? '␣' : ch.char))
    card.append(el('div', 'cp', ch.label))
    card.append(el('div', 'u8', `utf8 ${ch.utf8}`))
    card.append(el('div', '', `utf16 ${ch.utf16}`))
    chargrid.append(card)
  }
  const cps = info.length
  const units = [...text].reduce((n, c) => n + c.length, 0)
  const bytes = new TextEncoder().encode(text).length
  const graphemes = typeof Intl !== 'undefined' && 'Segmenter' in Intl ? [...new Intl.Segmenter().segment(text)].length : null
  uniNote.textContent =
    `${graphemes !== null ? `${graphemes} grapheme${graphemes === 1 ? '' : 's'} (what you see) · ` : ''}` +
    `${cps} code point${cps === 1 ? '' : 's'} · ${units} UTF-16 units (JS .length) · ${bytes} UTF-8 bytes` +
    (graphemes !== null && graphemes !== cps ? ' — emoji and accents often span several code points!' : '')
})

// ---------------------------------------------------------------- jwt

const jwtIn = $<HTMLTextAreaElement>('#jwt-in')
const jwtOut = $('#jwt-out')
const jwtMsg = $('#jwt-msg')
const jwtClaims = $<HTMLTableElement>('#jwt-claims')

const JWT_SAMPLE =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'

function decodeJwtUi(): void {
  jwtClaims.innerHTML = ''
  try {
    const { header, payload } = decodeJwt(jwtIn.value)
    jwtOut.textContent = `// header\n${JSON.stringify(header, null, 2)}\n\n// payload\n${JSON.stringify(payload, null, 2)}`
    hideMsg(jwtMsg)
    const rows: [string, unknown, string][] = []
    for (const [k, v] of Object.entries(header)) rows.push([k, v, JWT_CLAIM_NOTES[k] ?? 'header field'])
    for (const [k, v] of Object.entries(payload)) rows.push([k, v, JWT_CLAIM_NOTES[k] ?? ''])
    for (const [k, v, note] of rows) {
      const tr = el('tr')
      let display = JSON.stringify(v)
      let extra = note
      if ((k === 'exp' || k === 'iat' || k === 'nbf') && typeof v === 'number') {
        const when = new Date(v * 1000)
        display = `${v} → ${when.toISOString().replace('.000Z', 'Z')}`
        if (k === 'exp') {
          const live = v * 1000 > Date.now()
          extra = `${note} — ${live ? 'still valid' : 'EXPIRED'}`
        }
      }
      tr.append(el('th', '', k), el('td', 'mono', display), el('td', 'dim', extra))
      jwtClaims.append(tr)
    }
    if (String(header.alg).toLowerCase() === 'none') {
      showMsg(jwtMsg, 'warn', '⚠ alg is "none" — this token is unsigned. Any server accepting it is broken.')
    }
  } catch (e) {
    jwtOut.textContent = ''
    showMsg(jwtMsg, 'err', e instanceof Error ? e.message : String(e))
  }
}

$('#jwt-dec').addEventListener('click', decodeJwtUi)
$('#jwt-sample').addEventListener('click', () => {
  jwtIn.value = JWT_SAMPLE
  $<HTMLInputElement>('#jwt-secret').value = 'your-256-bit-secret'
  decodeJwtUi()
})
$('#jwt-verify').addEventListener('click', () => {
  const secret = $<HTMLInputElement>('#jwt-secret').value
  if (!secret) {
    showMsg(jwtMsg, 'warn', 'enter the shared secret to verify an HS256/384/512 signature')
    return
  }
  verifyJwtHmac(jwtIn.value, secret)
    .then((ok) => {
      if (ok) showMsg(jwtMsg, 'ok', '✓ signature is valid for this secret')
      else showMsg(jwtMsg, 'err', '✗ signature does NOT match this secret')
    })
    .catch((e) => showMsg(jwtMsg, 'err', e instanceof Error ? e.message : String(e)))
})

// ---------------------------------------------------------------- hash

const hashIn = $<HTMLTextAreaElement>('#hash-in')
const hashOut = $<HTMLTableElement>('#hash-out')

$('#hash-run').addEventListener('click', () => {
  void (async () => {
    const bytes = new TextEncoder().encode(hashIn.value)
    hashOut.innerHTML = ''
    const rows: [string, string][] = [['MD5', md5(bytes)]]
    for (const algo of ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']) {
      const digest = new Uint8Array(await crypto.subtle.digest(algo, bytes))
      rows.push([algo, [...digest].map((b) => b.toString(16).padStart(2, '0')).join('')])
    }
    for (const [name, digest] of rows) {
      const tr = el('tr')
      const td = el('td', 'mono')
      const span = el('span', 'copyable', digest)
      td.append(span)
      td.style.wordBreak = 'break-all'
      tr.append(el('th', '', name), td)
      hashOut.append(tr)
    }
    toast(`Hashed ${bytes.length} bytes`)
  })()
})
