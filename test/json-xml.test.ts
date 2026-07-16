import { describe, expect, it } from 'vitest'
import { formatJson, jsonStats, minifyJson, parseJson, toTypeScript } from '../src/core/jsonTool'
import { formatXml, minifyXml, xmlStats } from '../src/core/xmlTool'

describe('json', () => {
  it('reports error position with line/column', () => {
    const out = parseJson('{\n  "a": 1,\n  "b": }\n')
    expect(out.ok).toBe(false)
    if (!out.ok) {
      expect(out.error.line).toBe(3)
      expect(out.error.column).toBeGreaterThan(5)
    }
  })
  it('formats with sorted keys', () => {
    expect(formatJson('{"b":2,"a":{"z":1,"y":2}}', 2, true)).toBe('{\n  "a": {\n    "y": 2,\n    "z": 1\n  },\n  "b": 2\n}')
  })
  it('minifies', () => {
    expect(minifyJson('{ "a" : [ 1, 2 ] }')).toBe('{"a":[1,2]}')
  })
  it('computes stats', () => {
    const s = jsonStats(JSON.parse('{"a":[1,"x",null],"b":{"c":true}}'))
    expect(s.objects).toBe(2)
    expect(s.arrays).toBe(1)
    expect(s.keys).toBe(3)
    expect(s.nulls).toBe(1)
    expect(s.maxDepth).toBe(3)
  })
  it('generates TypeScript with optional merged fields', () => {
    const ts = toTypeScript(JSON.parse('{"users":[{"id":1,"name":"a"},{"id":2,"admin":true}]}'), 'Response')
    expect(ts).toContain('export interface Response {')
    expect(ts).toContain('users: User[];')
    expect(ts).toContain('name?: string;')
    expect(ts).toContain('admin?: boolean;')
    expect(ts).toContain('id: number;')
  })
  it('quotes non-identifier keys', () => {
    const ts = toTypeScript(JSON.parse('{"content-type":"a"}'))
    expect(ts).toContain('"content-type": string;')
  })
})

describe('xml', () => {
  it('pretty-prints nested elements', () => {
    const out = formatXml('<root><item id="1"><name>First</name></item><empty/></root>')
    expect(out).toBe(['<root>', '  <item id="1">', '    <name>First</name>', '  </item>', '  <empty/>', '</root>'].join('\n'))
  })
  it('keeps comments, CDATA and prolog intact', () => {
    const src = '<?xml version="1.0"?><a><!-- hi --><b><![CDATA[x < y]]></b></a>'
    const out = formatXml(src)
    expect(out).toContain('<?xml version="1.0"?>')
    expect(out).toContain('<!-- hi -->')
    expect(out).toContain('<![CDATA[x < y]]>')
  })
  it('minifies whitespace between tags', () => {
    expect(minifyXml('<a>\n  <b>text</b>\n</a>')).toBe('<a><b>text</b></a>')
  })
  it('counts elements and attributes', () => {
    const s = xmlStats('<a x="1" y="2"><b/><c z="3">t</c></a>')
    expect(s.elements).toBe(3)
    expect(s.attributes).toBe(3)
    expect(s.maxDepth).toBe(2)
  })
})
