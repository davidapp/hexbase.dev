import { formatSize, latin1 } from '../bytes'
import { region, type ParseResult, type Region } from '../region'
import { startsWith, sigOf, type FormatDef } from './def'

export const pdf: FormatDef = {
  id: 'pdf',
  name: 'PDF document',
  mime: 'application/pdf',
  detect: (b) => startsWith(b, sigOf('%PDF-')),
  parse(bytes): ParseResult {
    const regions: Region[] = []
    const warnings: string[] = []
    const summary: string[] = []

    const head = latin1(bytes.subarray(0, Math.min(bytes.length, 32)))
    const versionMatch = /^%PDF-(\d\.\d)/.exec(head)
    const version = versionMatch?.[1] ?? '?'
    const headerLen = head.indexOf('\n') === -1 ? 8 : head.indexOf('\n') + 1
    regions.push(
      region('Header', 0, headerLen, {
        value: `%PDF-${version}`,
        note: 'PDF is a text-based container with binary streams inside. The version here can be overridden by the document catalog.',
        flag: 'ok',
      }),
    )
    if (bytes.length > headerLen + 4 && bytes[headerLen] === 0x25 && bytes[headerLen + 1] >= 0x80) {
      regions.push(
        region('Binary marker comment', headerLen, 5, {
          note: 'A comment with 4 bytes ≥ 0x80, so file-transfer tools treat the PDF as binary and never "fix" its line endings.',
        }),
      )
    }

    // Work on the tail for startxref/%%EOF, and sample the body for object counts.
    const tail = latin1(bytes.subarray(Math.max(0, bytes.length - 2048)))
    const tailBase = Math.max(0, bytes.length - 2048)

    const eofIdx = tail.lastIndexOf('%%EOF')
    if (eofIdx === -1) {
      warnings.push('no %%EOF marker found — file is truncated')
    } else {
      regions.push(region('%%EOF', tailBase + eofIdx, 5, { note: 'End-of-file marker. Readers scan backwards from here.', flag: 'ok' }))
    }

    const sxIdx = tail.lastIndexOf('startxref')
    if (sxIdx !== -1) {
      const after = tail.slice(sxIdx + 9, sxIdx + 40)
      const numMatch = /(\d+)/.exec(after)
      const xrefOffset = numMatch ? Number(numMatch[1]) : -1
      regions.push(
        region('startxref', tailBase + sxIdx, 9 + (numMatch ? numMatch.index + numMatch[1].length : 0), {
          value: xrefOffset >= 0 ? `→ 0x${xrefOffset.toString(16).toUpperCase()}` : '',
          note: 'Byte offset of the cross-reference table/stream — the index that maps object numbers to file offsets. This is why appending to a PDF ("incremental update") works: old data stays, a new xref points at the changes.',
        }),
      )
      if (xrefOffset >= 0 && xrefOffset < bytes.length) {
        const xrefHead = latin1(bytes.subarray(xrefOffset, Math.min(bytes.length, xrefOffset + 4)))
        regions.push(
          region(xrefHead === 'xref' ? 'Cross-reference table' : 'Cross-reference stream', xrefOffset, Math.min(64, bytes.length - xrefOffset), {
            note: xrefHead === 'xref' ? 'Classic text xref table ("xref" keyword).' : 'PDF 1.5+ compressed xref stream (an object, itself indexed).',
          }),
        )
      } else if (xrefOffset >= bytes.length) {
        warnings.push('startxref points past the end of the file')
      }
    }

    // Cheap body sampling (cap 2 MB) for object/stream counts and flags.
    const sample = latin1(bytes.subarray(0, Math.min(bytes.length, 2 * 1024 * 1024)))
    const objCount = (sample.match(/\d+\s+\d+\s+obj\b/g) ?? []).length
    const streamCount = (sample.match(/\bstream\b/g) ?? []).length
    const sampled = bytes.length > 2 * 1024 * 1024

    regions.push(
      region('Body (objects)', headerLen, Math.max(0, (sxIdx !== -1 ? tailBase + sxIdx : bytes.length) - headerLen), {
        value: `${sampled ? '≥' : ''}${objCount} indirect objects, ${sampled ? '≥' : ''}${streamCount} streams`,
        note: 'A PDF body is a soup of numbered objects ("3 0 obj … endobj"). Pages, fonts and images reference each other by object number.',
      }),
    )

    summary.push(`PDF ${version}, ${sampled ? 'at least ' : ''}${objCount} objects`)
    if (sample.includes('/Encrypt')) summary.push('encrypted (has /Encrypt dictionary)')
    if (sample.includes('/Linearized')) summary.push('linearized ("fast web view" — page 1 data is up front)')
    if (sample.includes('/AcroForm')) summary.push('contains form fields (AcroForm)')
    if (sample.includes('/JavaScript') || sample.includes('/JS')) summary.push('contains JavaScript — worth a closer look in untrusted files')

    return { format: 'PDF document', summary, regions, warnings }
  },
}
