import { ByteReader, formatSize, hex } from '../bytes'
import { region, type ParseResult, type Region } from '../region'
import { startsWith, type FormatDef } from './def'

const OS_NAMES: Record<number, string> = {
  0: 'FAT (DOS/Windows)',
  1: 'Amiga',
  2: 'VMS',
  3: 'Unix',
  4: 'VM/CMS',
  5: 'Atari TOS',
  6: 'HPFS (OS/2)',
  7: 'Macintosh (classic)',
  10: 'TOPS-20',
  11: 'NTFS (Windows)',
  13: 'Acorn RISC OS',
  255: 'unknown',
}

export const gzip: FormatDef = {
  id: 'gzip',
  name: 'gzip compressed data',
  mime: 'application/gzip',
  detect: (b) => startsWith(b, [0x1f, 0x8b]),
  parse(bytes): ParseResult {
    const regions: Region[] = []
    const warnings: string[] = []
    const summary: string[] = []
    const r = new ByteReader(bytes, 0)

    try {
      r.skip(2)
      const method = r.u8()
      const flags = r.u8()
      const mtime = r.u32le()
      const xfl = r.u8()
      const os = r.u8()

      const flagNames: string[] = []
      if (flags & 1) flagNames.push('FTEXT')
      if (flags & 2) flagNames.push('FHCRC')
      if (flags & 4) flagNames.push('FEXTRA')
      if (flags & 8) flagNames.push('FNAME')
      if (flags & 16) flagNames.push('FCOMMENT')

      regions.push(
        region('Header', 0, 10, {
          value: 'gzip v4.3',
          children: [
            region('Magic', 0, 2, { value: '1F 8B', note: 'The gzip signature, unchanged since 1992.', flag: 'ok' }),
            region('Method', 2, 1, { value: method === 8 ? '8 — DEFLATE' : String(method), note: 'DEFLATE is the only method ever standardized.' }),
            region('Flags', 3, 1, { value: flagNames.length ? flagNames.join(' | ') : 'none' }),
            region('Modification time', 4, 4, {
              value: mtime === 0 ? '0 — not set' : new Date(mtime * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC'),
              note: 'Unix timestamp (little-endian u32) of the original file.',
            }),
            region('Extra flags', 8, 1, { value: xfl === 2 ? '2 — max compression' : xfl === 4 ? '4 — fastest' : String(xfl) }),
            region('OS', 9, 1, { value: `${os} — ${OS_NAMES[os] ?? 'unknown'}`, note: 'The OS/filesystem where the file was compressed.' }),
          ],
        }),
      )

      if (flags & 4) {
        const xlen = r.u16le()
        regions.push(region('Extra field', r.pos - 2, 2 + xlen, { value: formatSize(xlen) }))
        r.skip(xlen)
      }
      let name = ''
      if (flags & 8) {
        const start = r.pos
        while (!r.eof() && bytes[r.pos] !== 0) r.pos++
        name = new TextDecoder('latin1').decode(bytes.subarray(start, r.pos))
        r.skip(1)
        regions.push(region('Original file name', start, r.pos - start, { value: name, note: 'NUL-terminated Latin-1 string.' }))
      }
      if (flags & 16) {
        const start = r.pos
        while (!r.eof() && bytes[r.pos] !== 0) r.pos++
        r.skip(1)
        regions.push(region('Comment', start, r.pos - start, {}))
      }
      if (flags & 2) {
        regions.push(region('Header CRC16', r.pos, 2, { value: hex(r.u16le(), 4) }))
      }

      const deflateStart = r.pos
      const deflateLen = Math.max(0, bytes.length - 8 - deflateStart)
      regions.push(
        region('DEFLATE stream', deflateStart, deflateLen, {
          value: formatSize(deflateLen),
          note: 'Raw DEFLATE blocks (RFC 1951): LZ77 back-references + Huffman coding. No random access — you must decompress from the start.',
        }),
      )

      if (bytes.length >= deflateStart + 8) {
        const t = new ByteReader(bytes, bytes.length - 8)
        const crc = t.u32le()
        const isize = t.u32le()
        regions.push(
          region('Trailer', bytes.length - 8, 8, {
            children: [
              region('CRC-32', bytes.length - 8, 4, { value: hex(crc, 8), note: 'CRC of the uncompressed data.' }),
              region('ISIZE', bytes.length - 4, 4, {
                value: formatSize(isize),
                note: 'Uncompressed size modulo 2³² — files over 4 GB wrap around, a classic gotcha.',
              }),
            ],
          }),
        )
        summary.push(`${formatSize(bytes.length)} compressed → ${formatSize(isize)} uncompressed (mod 4 GB)`)
      }
      if (name) summary.push(`original name: ${name}`)
      summary.push(`compressed on ${OS_NAMES[os] ?? 'unknown OS'}${mtime ? `, ${new Date(mtime * 1000).toISOString().slice(0, 10)}` : ''}`)
    } catch (e) {
      warnings.push(`file truncated: ${e instanceof Error ? e.message : String(e)}`)
    }

    return { format: 'gzip compressed data', summary, regions, warnings }
  },
}
