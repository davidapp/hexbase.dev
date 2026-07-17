import { describe, expect, it } from 'vitest'
import { diffJson, diffLines, diffStats, renderValue } from '../src/core/jsonDiff'

describe('structural JSON diff', () => {
  it('reports no entries for identical documents', () => {
    const doc = { a: 1, b: [1, 2, { c: null }], d: 'x' }
    expect(diffJson(doc, JSON.parse(JSON.stringify(doc)))).toEqual([])
  })

  it('finds changed primitives with exact paths', () => {
    const out = diffJson({ user: { name: 'ada', age: 36 } }, { user: { name: 'ada', age: 37 } })
    expect(out).toEqual([{ path: '$.user.age', kind: 'changed', left: '36', right: '37' }])
  })

  it('finds added and removed keys', () => {
    const out = diffJson({ a: 1, gone: true }, { a: 1, fresh: 'hi' })
    expect(out).toContainEqual({ path: '$.gone', kind: 'removed', left: 'true' })
    expect(out).toContainEqual({ path: '$.fresh', kind: 'added', right: '"hi"' })
  })

  it('reports type changes rather than recursing into mismatched shapes', () => {
    const out = diffJson({ v: [1, 2] }, { v: { 0: 1 } })
    expect(out).toHaveLength(1)
    expect(out[0].kind).toBe('type')
    expect(out[0].left).toContain('(array)')
    expect(out[0].right).toContain('(object)')
  })

  it('treats null as its own type', () => {
    const out = diffJson({ v: null }, { v: 0 })
    expect(out[0].kind).toBe('type')
  })

  it('diffs arrays by index, including length changes', () => {
    const out = diffJson([1, 2, 3], [1, 9])
    expect(out).toContainEqual({ path: '$[1]', kind: 'changed', left: '2', right: '9' })
    expect(out).toContainEqual({ path: '$[2]', kind: 'removed', left: '3' })
  })

  it('bracket-quotes keys that are not identifier-safe', () => {
    const out = diffJson({ 'a key': 1 }, { 'a key': 2 })
    expect(out[0].path).toBe('$["a key"]')
  })

  it('respects the entry cap', () => {
    const a: Record<string, number> = {}
    const b: Record<string, number> = {}
    for (let i = 0; i < 100; i++) {
      a[`k${i}`] = i
      b[`k${i}`] = i + 1
    }
    expect(diffJson(a, b, 10)).toHaveLength(10)
  })

  it('truncates long value renderings', () => {
    expect(renderValue('x'.repeat(500)).length).toBeLessThanOrEqual(101)
  })

  it('counts stats by kind', () => {
    const s = diffStats(diffJson({ a: 1, b: 2, c: 3 }, { a: 9, c: 3, d: 4 }))
    expect(s).toEqual({ added: 1, removed: 1, changed: 1, type: 0 })
  })
})

describe('line diff (Myers)', () => {
  const script = (a: string, b: string) =>
    diffLines(a, b)
      .map((op) => (op.kind === 'same' ? ` ${op.text}` : op.kind === 'add' ? `+${op.text}` : `-${op.text}`))
      .join('\n')

  it('handles identical inputs', () => {
    const ops = diffLines('a\nb', 'a\nb')
    expect(ops.every((o) => o.kind === 'same')).toBe(true)
  })

  it('produces a minimal script for a small edit', () => {
    expect(script('a\nb\nc', 'a\nx\nc')).toBe(' a\n-b\n+x\n c')
  })

  it('handles pure insertion and deletion at both ends', () => {
    expect(script('b', 'a\nb')).toBe('+a\n b')
    expect(script('a\nb', 'b')).toBe('-a\n b')
    expect(script('a', 'a\nz')).toBe(' a\n+z')
  })

  it('tracks 1-based line numbers on both sides', () => {
    const ops = diffLines('a\nb\nc', 'a\nc')
    const same = ops.filter((o) => o.kind === 'same')
    expect(same[0]).toMatchObject({ aLine: 1, bLine: 1 })
    expect(same[1]).toMatchObject({ aLine: 3, bLine: 2 })
    expect(ops.find((o) => o.kind === 'del')).toMatchObject({ aLine: 2 })
  })

  it('round-trips: applying the script reconstructs both sides', () => {
    const a = 'one\ntwo\nthree\nfour\nfive'
    const b = 'zero\none\ntwo 2\nfour\nfive\nsix'
    const ops = diffLines(a, b)
    const left = ops.filter((o) => o.kind !== 'add').map((o) => o.text).join('\n')
    const right = ops.filter((o) => o.kind !== 'del').map((o) => o.text).join('\n')
    expect(left).toBe(a)
    expect(right).toBe(b)
  })

  it('falls back gracefully on very large inputs', () => {
    const a = Array.from({ length: 15000 }, (_, i) => `line ${i}`).join('\n')
    const b = 'prefix\n' + a
    const ops = diffLines(a, b)
    expect(ops.filter((o) => o.kind === 'add')).toHaveLength(1)
    const right = ops.filter((o) => o.kind !== 'del').map((o) => o.text).join('\n')
    expect(right).toBe(b)
  })
})
