/**
 * Structural JSON diff plus a Myers line diff for plain text.
 * Pure logic, no DOM — shared by the diff tool page and the tests.
 */

export type DiffKind = 'added' | 'removed' | 'changed' | 'type'

export interface DiffEntry {
  /** JSONPath-style location, e.g. $.users[3].name */
  path: string
  kind: DiffKind
  /** Short rendering of the left/right values (absent when not applicable). */
  left?: string
  right?: string
}

const RENDER_LIMIT = 100

/** Compact single-line rendering of any JSON value, truncated for display. */
export function renderValue(v: unknown): string {
  const s = JSON.stringify(v)
  if (s === undefined) return 'undefined'
  return s.length > RENDER_LIMIT ? s.slice(0, RENDER_LIMIT - 1) + '…' : s
}

function typeOf(v: unknown): string {
  if (v === null) return 'null'
  if (Array.isArray(v)) return 'array'
  return typeof v
}

/** Does this key survive a round-trip as a JS dot path, or does it need brackets? */
function keySegment(key: string): string {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key) ? `.${key}` : `[${JSON.stringify(key)}]`
}

/**
 * Structural diff of two parsed JSON values.
 * Objects diff by key; arrays diff by index (an insertion therefore shifts
 * everything after it — that trade-off is documented on the tool page).
 */
export function diffJson(a: unknown, b: unknown, maxEntries = 5000): DiffEntry[] {
  const out: DiffEntry[] = []
  walk(a, b, '$', out, maxEntries)
  return out
}

function walk(a: unknown, b: unknown, path: string, out: DiffEntry[], max: number): void {
  if (out.length >= max) return
  const ta = typeOf(a)
  const tb = typeOf(b)
  if (ta !== tb) {
    out.push({ path, kind: 'type', left: `${renderValue(a)} (${ta})`, right: `${renderValue(b)} (${tb})` })
    return
  }
  if (ta === 'object') {
    const ao = a as Record<string, unknown>
    const bo = b as Record<string, unknown>
    for (const key of Object.keys(ao)) {
      if (out.length >= max) return
      if (key in bo) walk(ao[key], bo[key], path + keySegment(key), out, max)
      else out.push({ path: path + keySegment(key), kind: 'removed', left: renderValue(ao[key]) })
    }
    for (const key of Object.keys(bo)) {
      if (out.length >= max) return
      if (!(key in ao)) out.push({ path: path + keySegment(key), kind: 'added', right: renderValue(bo[key]) })
    }
    return
  }
  if (ta === 'array') {
    const aa = a as unknown[]
    const ba = b as unknown[]
    const shared = Math.min(aa.length, ba.length)
    for (let i = 0; i < shared; i++) {
      if (out.length >= max) return
      walk(aa[i], ba[i], `${path}[${i}]`, out, max)
    }
    for (let i = shared; i < aa.length; i++) {
      if (out.length >= max) return
      out.push({ path: `${path}[${i}]`, kind: 'removed', left: renderValue(aa[i]) })
    }
    for (let i = shared; i < ba.length; i++) {
      if (out.length >= max) return
      out.push({ path: `${path}[${i}]`, kind: 'added', right: renderValue(ba[i]) })
    }
    return
  }
  // primitives (string, number, boolean, null already equal-typed here)
  if (a !== b) {
    out.push({ path, kind: 'changed', left: renderValue(a), right: renderValue(b) })
  }
}

// ---------------------------------------------------------------- line diff

export interface LineDiffOp {
  kind: 'same' | 'add' | 'del'
  text: string
  /** 1-based line numbers in the left/right documents (absent where not present). */
  aLine?: number
  bLine?: number
}

/** Beyond this many total lines, fall back to prefix/suffix trimming (O(n)). */
const MYERS_LINE_LIMIT = 20000

/**
 * Line-based diff. Uses Myers' O(ND) algorithm; for very large inputs it
 * degrades to common-prefix/suffix trimming with a block replace in between.
 */
export function diffLines(aText: string, bText: string): LineDiffOp[] {
  const a = aText.split('\n')
  const b = bText.split('\n')
  if (aText === bText) return a.map((text, i) => ({ kind: 'same', text, aLine: i + 1, bLine: i + 1 }))
  if (a.length + b.length > MYERS_LINE_LIMIT) return blockDiff(a, b)
  return myers(a, b)
}

function blockDiff(a: string[], b: string[]): LineDiffOp[] {
  let pre = 0
  while (pre < a.length && pre < b.length && a[pre] === b[pre]) pre++
  let suf = 0
  while (suf < a.length - pre && suf < b.length - pre && a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++
  const out: LineDiffOp[] = []
  for (let i = 0; i < pre; i++) out.push({ kind: 'same', text: a[i], aLine: i + 1, bLine: i + 1 })
  for (let i = pre; i < a.length - suf; i++) out.push({ kind: 'del', text: a[i], aLine: i + 1 })
  for (let i = pre; i < b.length - suf; i++) out.push({ kind: 'add', text: b[i], bLine: i + 1 })
  for (let i = 0; i < suf; i++)
    out.push({ kind: 'same', text: a[a.length - suf + i], aLine: a.length - suf + i + 1, bLine: b.length - suf + i + 1 })
  return out
}

function myers(a: string[], b: string[]): LineDiffOp[] {
  const N = a.length
  const M = b.length
  const MAX = N + M
  const size = 2 * MAX + 1
  const offset = MAX
  let v = new Int32Array(size)
  const trace: Int32Array[] = []
  let dFound = -1

  outer: for (let d = 0; d <= MAX; d++) {
    trace.push(v.slice())
    const next = v.slice()
    for (let k = -d; k <= d; k += 2) {
      let x: number
      if (k === -d || (k !== d && v[offset + k - 1] < v[offset + k + 1])) x = v[offset + k + 1]
      else x = v[offset + k - 1] + 1
      let y = x - k
      while (x < N && y < M && a[x] === b[y]) {
        x++
        y++
      }
      next[offset + k] = x
      if (x >= N && y >= M) {
        dFound = d
        v = next
        break outer
      }
    }
    v = next
  }

  // Backtrack through the recorded frontiers to reconstruct the edit script.
  const ops: LineDiffOp[] = []
  let x = N
  let y = M
  for (let d = dFound; d > 0; d--) {
    const prev = trace[d]
    const k = x - y
    let prevK: number
    if (k === -d || (k !== d && prev[offset + k - 1] < prev[offset + k + 1])) prevK = k + 1
    else prevK = k - 1
    const prevX = prev[offset + prevK]
    const prevY = prevX - prevK
    while (x > prevX && y > prevY) {
      x--
      y--
      ops.push({ kind: 'same', text: a[x], aLine: x + 1, bLine: y + 1 })
    }
    if (x === prevX) {
      y--
      ops.push({ kind: 'add', text: b[y], bLine: y + 1 })
    } else {
      x--
      ops.push({ kind: 'del', text: a[x], aLine: x + 1 })
    }
  }
  while (x > 0 && y > 0) {
    x--
    y--
    ops.push({ kind: 'same', text: a[x], aLine: x + 1, bLine: y + 1 })
  }
  while (x > 0) {
    x--
    ops.push({ kind: 'del', text: a[x], aLine: x + 1 })
  }
  while (y > 0) {
    y--
    ops.push({ kind: 'add', text: b[y], bLine: y + 1 })
  }
  return ops.reverse()
}

export interface DiffStats {
  added: number
  removed: number
  changed: number
  type: number
}

export function diffStats(entries: DiffEntry[]): DiffStats {
  const s: DiffStats = { added: 0, removed: 0, changed: 0, type: 0 }
  for (const e of entries) s[e.kind]++
  return s
}
