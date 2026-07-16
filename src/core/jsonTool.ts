export interface JsonError {
  message: string
  index?: number
  line?: number
  column?: number
}

export type ParseOutcome = { ok: true; value: unknown } | { ok: false; error: JsonError }

/**
 * JSON.parse, but failures are re-scanned by our own validator so the error
 * carries an exact index/line/column and a human explanation (engines no
 * longer include positions reliably).
 */
export function parseJson(text: string): ParseOutcome {
  try {
    return { ok: true, value: JSON.parse(text) }
  } catch (e) {
    const engineMsg = e instanceof Error ? e.message : String(e)
    const error = locateJsonError(text) ?? { message: engineMsg }
    if (error.index !== undefined && error.line === undefined) {
      let line = 1
      let column = 1
      for (let i = 0; i < error.index && i < text.length; i++) {
        if (text[i] === '\n') {
          line++
          column = 1
        } else column++
      }
      error.line = line
      error.column = column
    }
    return { ok: false, error }
  }
}

/** Minimal recursive-descent scanner used only to pinpoint and explain errors. */
function locateJsonError(text: string): JsonError | null {
  let i = 0
  const n = text.length

  class Located {
    constructor(
      public message: string,
      public index: number,
    ) {}
  }
  const fail = (message: string, at = i): never => {
    throw new Located(message, Math.min(at, n))
  }
  const ws = () => {
    while (i < n && (text[i] === ' ' || text[i] === '\t' || text[i] === '\n' || text[i] === '\r')) i++
  }

  const string = (): void => {
    const start = i
    i++ // opening quote
    while (i < n) {
      const c = text[i]
      if (c === '"') {
        i++
        return
      }
      if (c === '\\') {
        const esc = text[i + 1]
        if (esc === 'u') {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(i + 2, i + 6))) fail('\\u must be followed by exactly 4 hex digits', i)
          i += 6
          continue
        }
        if (!'"\\/bfnrt'.includes(esc)) fail(`invalid escape sequence \\${esc ?? ''} (valid: \\" \\\\ \\/ \\b \\f \\n \\r \\t \\uXXXX)`, i)
        i += 2
        continue
      }
      if (c === '\n' || c === '\r') fail('unescaped newline inside a string — use \\n', i)
      if (c < ' ') fail('unescaped control character inside a string', i)
      i++
    }
    fail('unclosed string', start)
  }

  const number = (): void => {
    const start = i
    if (text[i] === '-') i++
    if (text[i] === '0' && /[0-9]/.test(text[i + 1] ?? '')) fail('numbers may not have leading zeros', start)
    if (!/[0-9]/.test(text[i] ?? '')) fail('a minus sign must be followed by digits', start)
    while (/[0-9]/.test(text[i] ?? '')) i++
    if (text[i] === '.') {
      i++
      if (!/[0-9]/.test(text[i] ?? '')) fail('a decimal point must be followed by digits (".5" and "1." are invalid)', i - 1)
      while (/[0-9]/.test(text[i] ?? '')) i++
    }
    if (text[i] === 'e' || text[i] === 'E') {
      i++
      if (text[i] === '+' || text[i] === '-') i++
      if (!/[0-9]/.test(text[i] ?? '')) fail('exponent must have digits', i)
      while (/[0-9]/.test(text[i] ?? '')) i++
    }
  }

  const value = (): void => {
    ws()
    if (i >= n) fail('unexpected end of input — expected a value')
    const c = text[i]
    if (c === '{') return object()
    if (c === '[') return array()
    if (c === '"') return string()
    if (c === '-' || (c >= '0' && c <= '9')) return number()
    if (text.startsWith('true', i)) {
      i += 4
      return
    }
    if (text.startsWith('false', i)) {
      i += 5
      return
    }
    if (text.startsWith('null', i)) {
      i += 4
      return
    }
    if (c === "'") fail('strings must use double quotes — single quotes are not JSON')
    if (text.startsWith('undefined', i)) fail('undefined is not valid JSON — use null')
    if (text.startsWith('NaN', i) || text.startsWith('Infinity', i) || text.startsWith('-Infinity', i)) {
      fail('NaN and Infinity are not valid JSON numbers')
    }
    fail(`unexpected character ${JSON.stringify(c)}`)
  }

  const object = (): void => {
    i++ // {
    ws()
    if (text[i] === '}') {
      i++
      return
    }
    for (;;) {
      ws()
      if (i >= n) fail('unexpected end of input — unclosed object (missing })')
      if (text[i] === '}') fail('trailing comma before } — JSON does not allow trailing commas', i)
      if (text[i] !== '"') {
        if (/[A-Za-z_$]/.test(text[i])) fail('property names must be double-quoted in JSON (unlike JavaScript object literals)')
        fail('expected a double-quoted property name')
      }
      string()
      ws()
      if (text[i] !== ':') fail("expected ':' after property name")
      i++
      value()
      ws()
      if (text[i] === ',') {
        i++
        continue
      }
      if (text[i] === '}') {
        i++
        return
      }
      if (i >= n) fail('unexpected end of input — unclosed object (missing })')
      fail("expected ',' or '}' in object")
    }
  }

  const array = (): void => {
    i++ // [
    ws()
    if (text[i] === ']') {
      i++
      return
    }
    for (;;) {
      ws()
      if (text[i] === ']') fail('trailing comma before ] — JSON does not allow trailing commas', i)
      value()
      ws()
      if (text[i] === ',') {
        i++
        continue
      }
      if (text[i] === ']') {
        i++
        return
      }
      if (i >= n) fail('unexpected end of input — unclosed array (missing ])')
      fail("expected ',' or ']' in array")
    }
  }

  try {
    value()
    ws()
    if (i < n) {
      const rest = text.slice(i, i + 20)
      if (rest.startsWith('{') || rest.startsWith('[') || rest.startsWith('"')) {
        fail('unexpected second value after the first one — is this NDJSON (one JSON document per line)?')
      }
      fail('unexpected content after the JSON value')
    }
    return null // our scanner found nothing wrong; fall back to the engine message
  } catch (e) {
    if (e instanceof Located) return { message: e.message, index: e.index }
    return null
  }
}

function sortValue(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortValue)
  if (v !== null && typeof v === 'object') {
    const out: Record<string, unknown> = {}
    for (const k of Object.keys(v as object).sort()) {
      out[k] = sortValue((v as Record<string, unknown>)[k])
    }
    return out
  }
  return v
}

export function formatJson(text: string, indent: number | '\t' = 2, sortKeys = false): string {
  const parsed = parseJson(text)
  if (!parsed.ok) throw new Error(parsed.error.message)
  const value = sortKeys ? sortValue(parsed.value) : parsed.value
  return JSON.stringify(value, null, indent)
}

export function minifyJson(text: string): string {
  const parsed = parseJson(text)
  if (!parsed.ok) throw new Error(parsed.error.message)
  return JSON.stringify(parsed.value)
}

export interface JsonStats {
  maxDepth: number
  objects: number
  arrays: number
  keys: number
  strings: number
  numbers: number
  booleans: number
  nulls: number
}

export function jsonStats(value: unknown): JsonStats {
  const s: JsonStats = { maxDepth: 0, objects: 0, arrays: 0, keys: 0, strings: 0, numbers: 0, booleans: 0, nulls: 0 }
  const walk = (v: unknown, depth: number): void => {
    s.maxDepth = Math.max(s.maxDepth, depth)
    if (v === null) s.nulls++
    else if (Array.isArray(v)) {
      s.arrays++
      for (const item of v) walk(item, depth + 1)
    } else if (typeof v === 'object') {
      s.objects++
      const entries = Object.entries(v as object)
      s.keys += entries.length
      for (const [, val] of entries) walk(val, depth + 1)
    } else if (typeof v === 'string') s.strings++
    else if (typeof v === 'number') s.numbers++
    else if (typeof v === 'boolean') s.booleans++
  }
  walk(value, 1)
  return s
}

// ---------------------------------------------------------------- JSON → TypeScript

type Shape =
  | { kind: 'primitive'; name: string }
  | { kind: 'array'; element: Shape | null }
  | { kind: 'object'; fields: Map<string, { shape: Shape; optional: boolean }> }
  | { kind: 'union'; members: Shape[] }

function shapeOf(v: unknown): Shape {
  if (v === null) return { kind: 'primitive', name: 'null' }
  if (Array.isArray(v)) {
    if (v.length === 0) return { kind: 'array', element: null }
    let el = shapeOf(v[0])
    for (let i = 1; i < v.length; i++) el = mergeShapes(el, shapeOf(v[i]))
    return { kind: 'array', element: el }
  }
  switch (typeof v) {
    case 'string':
      return { kind: 'primitive', name: 'string' }
    case 'number':
      return { kind: 'primitive', name: 'number' }
    case 'boolean':
      return { kind: 'primitive', name: 'boolean' }
    case 'object': {
      const fields = new Map<string, { shape: Shape; optional: boolean }>()
      for (const [k, val] of Object.entries(v as object)) {
        fields.set(k, { shape: shapeOf(val), optional: false })
      }
      return { kind: 'object', fields }
    }
    default:
      return { kind: 'primitive', name: 'unknown' }
  }
}

function mergeShapes(a: Shape, b: Shape): Shape {
  if (a.kind === 'primitive' && b.kind === 'primitive' && a.name === b.name) return a
  if (a.kind === 'array' && b.kind === 'array') {
    if (!a.element) return b
    if (!b.element) return a
    return { kind: 'array', element: mergeShapes(a.element, b.element) }
  }
  if (a.kind === 'object' && b.kind === 'object') {
    const fields = new Map(a.fields)
    for (const [k, f] of b.fields) {
      const existing = fields.get(k)
      if (existing) fields.set(k, { shape: mergeShapes(existing.shape, f.shape), optional: existing.optional || f.optional })
      else fields.set(k, { shape: f.shape, optional: true })
    }
    for (const [k, f] of a.fields) {
      if (!b.fields.has(k)) fields.set(k, { ...f, optional: true })
    }
    return { kind: 'object', fields }
  }
  const members: Shape[] = []
  const push = (s: Shape) => {
    for (const m of s.kind === 'union' ? s.members : [s]) {
      if (m.kind === 'primitive' && members.some((x) => x.kind === 'primitive' && x.name === m.name)) continue
      members.push(m)
    }
  }
  push(a)
  push(b)
  return members.length === 1 ? members[0] : { kind: 'union', members }
}

const IDENT_RE = /^[A-Za-z_$][A-Za-z0-9_$]*$/

function pascalCase(s: string): string {
  const cleaned = s.replace(/[^A-Za-z0-9]+/g, ' ').trim()
  if (!cleaned) return 'Item'
  return cleaned
    .split(' ')
    .map((w) => w[0].toUpperCase() + w.slice(1))
    .join('')
}

function singular(s: string): string {
  if (/ies$/i.test(s)) return s.slice(0, -3) + 'y'
  if (/[sx]es$/i.test(s)) return s.slice(0, -2)
  if (/s$/i.test(s) && !/ss$/i.test(s)) return s.slice(0, -1)
  return s
}

/** Generate TypeScript interfaces from a parsed JSON value. */
export function toTypeScript(value: unknown, rootName = 'Root'): string {
  const interfaces: string[] = []
  const used = new Set<string>()

  const uniqueName = (hint: string): string => {
    let base = pascalCase(hint)
    if (/^\d/.test(base)) base = '_' + base
    let name = base
    let n = 2
    while (used.has(name)) name = base + n++
    used.add(name)
    return name
  }

  const render = (s: Shape, hint: string): string => {
    switch (s.kind) {
      case 'primitive':
        return s.name
      case 'array': {
        if (!s.element) return 'unknown[]'
        const el = render(s.element, singular(hint))
        return el.includes('|') ? `(${el})[]` : `${el}[]`
      }
      case 'union':
        return s.members.map((m) => render(m, hint)).join(' | ')
      case 'object': {
        const name = uniqueName(hint)
        const lines = [...s.fields].map(([k, f]) => {
          const key = IDENT_RE.test(k) ? k : JSON.stringify(k)
          return `  ${key}${f.optional ? '?' : ''}: ${render(f.shape, k)};`
        })
        interfaces.push(`export interface ${name} {\n${lines.join('\n')}\n}`)
        return name
      }
    }
  }

  const shape = shapeOf(value)
  const rootType = render(shape, rootName)
  if (shape.kind !== 'object') {
    interfaces.push(`export type ${uniqueName(rootName)} = ${rootType};`)
  }
  return interfaces.reverse().join('\n\n') + '\n'
}
