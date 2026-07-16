/**
 * A tolerant XML pretty-printer built on a lightweight tokenizer.
 * It never builds a DOM, so it works in Workers/Node and survives
 * mildly broken markup. Strict validation happens in the browser
 * via DOMParser (see the XML tool page).
 */

export interface XmlToken {
  type: 'open' | 'close' | 'self' | 'text' | 'comment' | 'cdata' | 'pi' | 'doctype'
  src: string
}

export function tokenizeXml(xml: string): XmlToken[] {
  const tokens: XmlToken[] = []
  let i = 0
  while (i < xml.length) {
    if (xml[i] === '<') {
      if (xml.startsWith('<!--', i)) {
        const end = xml.indexOf('-->', i + 4)
        const stop = end === -1 ? xml.length : end + 3
        tokens.push({ type: 'comment', src: xml.slice(i, stop) })
        i = stop
      } else if (xml.startsWith('<![CDATA[', i)) {
        const end = xml.indexOf(']]>', i + 9)
        const stop = end === -1 ? xml.length : end + 3
        tokens.push({ type: 'cdata', src: xml.slice(i, stop) })
        i = stop
      } else if (xml.startsWith('<?', i)) {
        const end = xml.indexOf('?>', i + 2)
        const stop = end === -1 ? xml.length : end + 2
        tokens.push({ type: 'pi', src: xml.slice(i, stop) })
        i = stop
      } else if (xml.startsWith('<!', i)) {
        // DOCTYPE, possibly with an [ ... ] internal subset
        let depth = 0
        let j = i
        for (; j < xml.length; j++) {
          const c = xml[j]
          if (c === '[') depth++
          else if (c === ']') depth--
          else if (c === '>' && depth <= 0) break
        }
        tokens.push({ type: 'doctype', src: xml.slice(i, Math.min(j + 1, xml.length)) })
        i = j + 1
      } else {
        // regular tag — find '>' while respecting quoted attribute values
        let j = i + 1
        let quote: string | null = null
        for (; j < xml.length; j++) {
          const c = xml[j]
          if (quote) {
            if (c === quote) quote = null
          } else if (c === '"' || c === "'") {
            quote = c
          } else if (c === '>') {
            break
          }
        }
        const src = xml.slice(i, Math.min(j + 1, xml.length))
        const type: XmlToken['type'] = src.startsWith('</') ? 'close' : /\/>\s*$/.test(src) ? 'self' : 'open'
        tokens.push({ type, src })
        i = j + 1
      }
    } else {
      const next = xml.indexOf('<', i)
      const stop = next === -1 ? xml.length : next
      tokens.push({ type: 'text', src: xml.slice(i, stop) })
      i = stop
    }
  }
  return tokens
}

/** Collapse a tag that was wrapped across lines back onto one line. */
function unwrapTag(src: string): string {
  return src.replace(/\s*\r?\n\s*/g, ' ')
}

export function formatXml(xml: string, indentSize = 2): string {
  const tokens = tokenizeXml(xml)
  const pad = (d: number) => ' '.repeat(d * indentSize)
  const lines: string[] = []
  let depth = 0
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]
    if (t.type === 'text') {
      const text = t.src.trim()
      if (!text) continue
      const next = tokens[i + 1]
      // keep `<name>value</name>` on a single line
      if (tokens[i - 1]?.type === 'open' && next?.type === 'close' && lines.length > 0) {
        lines[lines.length - 1] += text.replace(/\s+/g, ' ') + unwrapTag(next.src)
        i++
        depth = Math.max(0, depth - 1)
        continue
      }
      lines.push(pad(depth) + text.replace(/\s+/g, ' '))
    } else if (t.type === 'close') {
      depth = Math.max(0, depth - 1)
      lines.push(pad(depth) + unwrapTag(t.src))
    } else if (t.type === 'open') {
      lines.push(pad(depth) + unwrapTag(t.src))
      depth++
    } else {
      lines.push(pad(depth) + unwrapTag(t.src.trim()))
    }
  }
  return lines.join('\n')
}

export function minifyXml(xml: string): string {
  const tokens = tokenizeXml(xml)
  let out = ''
  for (const t of tokens) {
    if (t.type === 'text') {
      const text = t.src.trim()
      if (!text) continue
      out += text.replace(/\s+/g, ' ')
    } else {
      out += unwrapTag(t.src)
    }
  }
  return out
}

export interface XmlStats {
  elements: number
  attributes: number
  comments: number
  maxDepth: number
}

export function xmlStats(xml: string): XmlStats {
  const tokens = tokenizeXml(xml)
  const s: XmlStats = { elements: 0, attributes: 0, comments: 0, maxDepth: 0 }
  let depth = 0
  for (const t of tokens) {
    if (t.type === 'open' || t.type === 'self') {
      s.elements++
      s.attributes += (unwrapTag(t.src).match(/[\w:.-]+\s*=\s*("[^"]*"|'[^']*')/g) ?? []).length
      if (t.type === 'open') {
        depth++
        s.maxDepth = Math.max(s.maxDepth, depth)
      } else {
        s.maxDepth = Math.max(s.maxDepth, depth + 1)
      }
    } else if (t.type === 'close') {
      depth = Math.max(0, depth - 1)
    } else if (t.type === 'comment') {
      s.comments++
    }
  }
  return s
}
