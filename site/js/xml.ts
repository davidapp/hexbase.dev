import { escapeHtml, unescapeHtml } from '@core/encode'
import { formatXml, minifyXml, xmlStats } from '@core/xmlTool'
import { $, bindShare, copyText, el, hideMsg, initChrome, loadShare, shareParam, showMsg, toast } from './ui'

initChrome()

const input = $<HTMLTextAreaElement>('#input')
const output = $('#output')
const msg = $('#xml-msg')
const xpathInput = $<HTMLInputElement>('#xpath')
const xpathOut = $('#xpath-out')

const SAMPLE = `<?xml version="1.0" encoding="UTF-8"?>
<catalog>
  <book id="b1" lang="en">
    <title>The Art of Computer Programming</title>
    <author>Donald Knuth</author>
    <price currency="USD">199.99</price>
  </book>
  <book id="b2" lang="en">
    <title>Structure and Interpretation of Computer Programs</title>
    <author>Abelson &amp; Sussman</author>
    <price currency="USD">29.99</price>
  </book>
  <book id="b3" lang="ja">
    <title>プログラミング言語C</title>
    <author>K&amp;R</author>
    <price currency="JPY">3200</price>
  </book>
  <!-- prices last checked 2026-07 -->
</catalog>`

/** Browser-grade validation via DOMParser (draconian, like the spec demands). */
function validate(text: string): { ok: true; doc: Document } | { ok: false; error: string } {
  const doc = new DOMParser().parseFromString(text, 'application/xml')
  const err = doc.querySelector('parsererror')
  if (err) {
    const detail = (err.textContent ?? 'parse error').replace(/\s+/g, ' ').trim()
    return { ok: false, error: detail }
  }
  return { ok: true, doc }
}

function requireValid(): Document | null {
  if (!input.value.trim()) {
    showMsg(msg, 'warn', 'input is empty')
    return null
  }
  const v = validate(input.value)
  if (!v.ok) {
    showMsg(msg, 'err', `✗ not well-formed: ${v.error}`)
    return null
  }
  const stats = xmlStats(input.value)
  showMsg(msg, 'ok', `✓ well-formed — ${stats.elements} elements, ${stats.attributes} attributes, depth ${stats.maxDepth}${stats.comments ? `, ${stats.comments} comments` : ''}`)
  return v.doc
}

$('#validate').addEventListener('click', requireValid)
$('#format').addEventListener('click', () => {
  if (!requireValid()) return
  output.textContent = formatXml(input.value, 2)
  toast('Formatted')
})
$('#minify').addEventListener('click', () => {
  if (!requireValid()) return
  const out = minifyXml(input.value)
  output.textContent = out
  toast(`Minified — ${input.value.length.toLocaleString()} → ${out.length.toLocaleString()} chars`)
})
$('#escape').addEventListener('click', () => {
  output.textContent = escapeHtml(input.value)
  hideMsg(msg)
})
$('#unescape').addEventListener('click', () => {
  output.textContent = unescapeHtml(input.value)
  hideMsg(msg)
})
$('#copy').addEventListener('click', () => void copyText(output.textContent ?? ''))
$('#sample').addEventListener('click', () => {
  input.value = SAMPLE
  output.textContent = formatXml(SAMPLE, 2)
  requireValid()
})
$('#clear').addEventListener('click', () => {
  input.value = ''
  output.textContent = ''
  xpathOut.textContent = ''
  hideMsg(msg)
})

// ---------------------------------------------------------------- xpath

function serializeNode(node: Node): string {
  if (node.nodeType === Node.ATTRIBUTE_NODE) return `${(node as Attr).name}="${(node as Attr).value}"`
  if (node.nodeType === Node.TEXT_NODE) return JSON.stringify(node.textContent)
  return new XMLSerializer().serializeToString(node)
}

function runXpath(): void {
  xpathOut.textContent = ''
  const expr = xpathInput.value.trim()
  if (!expr) return
  const v = validate(input.value)
  if (!v.ok) {
    showMsg(msg, 'err', `fix the XML first: ${v.error}`)
    return
  }
  try {
    const res = v.doc.evaluate(expr, v.doc, null, XPathResult.ANY_TYPE, null)
    if (res.resultType === XPathResult.NUMBER_TYPE) {
      xpathOut.textContent = `number: ${res.numberValue}`
    } else if (res.resultType === XPathResult.STRING_TYPE) {
      xpathOut.textContent = `string: ${JSON.stringify(res.stringValue)}`
    } else if (res.resultType === XPathResult.BOOLEAN_TYPE) {
      xpathOut.textContent = `boolean: ${res.booleanValue}`
    } else {
      const items: string[] = []
      let node = res.iterateNext()
      while (node && items.length < 100) {
        items.push(serializeNode(node))
        node = res.iterateNext()
      }
      if (items.length === 0) {
        xpathOut.textContent = 'no matches'
      } else {
        xpathOut.append(el('div', 'sumline', `${items.length} match${items.length === 1 ? '' : 'es'}`))
        for (const item of items) {
          const div = el('div', 'mono')
          div.style.cssText = 'padding:4px 0;border-top:1px solid var(--border);font-size:.8rem;white-space:pre-wrap'
          div.textContent = item
          xpathOut.append(div)
        }
      }
    }
  } catch (e) {
    showMsg(msg, 'err', `invalid XPath: ${e instanceof Error ? e.message : String(e)}`)
  }
}

$('#run-xpath').addEventListener('click', runXpath)
xpathInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') runXpath()
})

// ---------------------------------------------------------------- share

bindShare($('#share'), 'xml', () => {
  const text = input.value.trim()
  return text ? { bytes: new TextEncoder().encode(text) } : null
})

const code = shareParam()
if (code) {
  loadShare(code)
    .then(({ bytes }) => {
      input.value = new TextDecoder().decode(bytes)
      requireValid()
      toast('Loaded shared XML')
    })
    .catch((e) => showMsg(msg, 'err', e instanceof Error ? e.message : 'failed to load share'))
}
