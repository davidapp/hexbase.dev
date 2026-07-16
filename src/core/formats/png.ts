import { ByteReader, crc32, formatSize, hex, latin1 } from '../bytes'
import { region, type ParseResult, type Region } from '../region'
import { startsWith, type FormatDef } from './def'

const CHUNK_NOTES: Record<string, string> = {
  IHDR: 'Image header — dimensions, bit depth, color type. Always the first chunk.',
  PLTE: 'Palette — up to 256 RGB entries for indexed-color images.',
  IDAT: 'Image data — zlib-compressed filtered scanlines. Often split across many IDAT chunks.',
  IEND: 'End of image. Always last, always empty.',
  tEXt: 'Uncompressed Latin-1 text metadata (keyword\\0value).',
  zTXt: 'Compressed text metadata.',
  iTXt: 'International (UTF-8) text metadata.',
  pHYs: 'Physical pixel dimensions — how many pixels per metre (DPI).',
  gAMA: 'Image gamma value.',
  sRGB: 'Declares the image uses the sRGB color space.',
  iCCP: 'Embedded ICC color profile.',
  tRNS: 'Transparency data for images without a full alpha channel.',
  bKGD: 'Suggested background color.',
  tIME: 'Last-modification timestamp.',
  sBIT: 'Significant bits per channel.',
  cHRM: 'Chromaticity coordinates of the display primaries.',
  acTL: 'APNG animation control (frame count, loop count) — this is an animated PNG.',
  fcTL: 'APNG frame control.',
  fdAT: 'APNG frame data.',
  eXIf: 'EXIF metadata block.',
}

const COLOR_TYPES: Record<number, string> = {
  0: 'grayscale',
  2: 'truecolor (RGB)',
  3: 'indexed (palette)',
  4: 'grayscale + alpha',
  6: 'truecolor + alpha (RGBA)',
}

export const png: FormatDef = {
  id: 'png',
  name: 'PNG image',
  mime: 'image/png',
  detect: (b) => startsWith(b, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  parse(bytes): ParseResult {
    const regions: Region[] = []
    const warnings: string[] = []
    const summary: string[] = []

    regions.push(
      region('PNG signature', 0, 8, {
        value: '89 50 4E 47 0D 0A 1A 0A',
        note: '"\\x89PNG\\r\\n\\x1a\\n". The \\x89 detects 7-bit transmission damage, CRLF+LF detect line-ending conversion, and \\x1a (Ctrl-Z) stops accidental TYPE-ing under DOS.',
        flag: 'ok',
      }),
    )

    const r = new ByteReader(bytes, 8)
    let chunkCount = 0
    let badCrc = 0
    let apng = false
    let sawEnd = false

    try {
      while (!r.eof() && chunkCount < 10000 && !sawEnd) {
        const start = r.pos
        const len = r.u32be()
        const type = r.ascii(4)
        const dataStart = r.pos
        r.skip(len)
        const crcStored = r.u32be()
        const crcComputed = crc32(bytes, dataStart - 4, dataStart + len)
        const crcOk = crcStored === crcComputed
        if (!crcOk) {
          badCrc++
          if (badCrc <= 3) warnings.push(`${type} chunk at offset 0x${hex(start, 4)}: bad CRC (stored ${hex(crcStored, 8)}, computed ${hex(crcComputed, 8)})`)
        }
        chunkCount++

        const children: Region[] = [
          region('Length', start, 4, { value: String(len), note: 'Byte length of the data field (big-endian u32).' }),
          region('Type', start + 4, 4, {
            value: type,
            note: 'Four ASCII letters. Lowercase first letter = ancillary (decoder may skip it); uppercase = critical.',
          }),
        ]

        const sub = new ByteReader(bytes, dataStart)
        if (type === 'IHDR' && len >= 13) {
          const w = sub.u32be()
          const h = sub.u32be()
          const bitDepth = sub.u8()
          const colorType = sub.u8()
          const compression = sub.u8()
          const filter = sub.u8()
          const interlace = sub.u8()
          children.push(
            region('Width', dataStart, 4, { value: `${w} px` }),
            region('Height', dataStart + 4, 4, { value: `${h} px` }),
            region('Bit depth', dataStart + 8, 1, { value: String(bitDepth), note: 'Bits per sample or per palette index (1, 2, 4, 8 or 16).' }),
            region('Color type', dataStart + 9, 1, { value: `${colorType} — ${COLOR_TYPES[colorType] ?? 'invalid'}` }),
            region('Compression', dataStart + 10, 1, { value: String(compression), note: 'Always 0 = zlib/DEFLATE.' }),
            region('Filter method', dataStart + 11, 1, { value: String(filter), note: 'Always 0 = adaptive filtering with one filter byte per scanline.' }),
            region('Interlace', dataStart + 12, 1, {
              value: interlace ? '1 — Adam7' : '0 — none',
              note: 'Adam7 interlacing lets a decoder show a rough preview after ~2% of the data.',
            }),
          )
          summary.push(`${w} × ${h} px, ${bitDepth}-bit ${COLOR_TYPES[colorType] ?? '?'}${interlace ? ', Adam7 interlaced' : ''}`)
        } else if (type === 'tEXt' && len > 0 && len < 4096) {
          const data = bytes.subarray(dataStart, dataStart + len)
          const nul = data.indexOf(0)
          if (nul > 0) {
            const keyword = latin1(data.subarray(0, nul))
            const text = latin1(data.subarray(nul + 1)).slice(0, 80)
            children.push(
              region('Keyword', dataStart, nul, { value: keyword }),
              region('Text', dataStart + nul + 1, len - nul - 1, { value: text }),
            )
          }
        } else if (type === 'acTL' && len >= 8) {
          apng = true
          const frames = sub.u32be()
          const plays = sub.u32be()
          children.push(
            region('Frames', dataStart, 4, { value: String(frames) }),
            region('Plays', dataStart + 4, 4, { value: plays === 0 ? '0 — loop forever' : String(plays) }),
          )
        } else if (type === 'pHYs' && len >= 9) {
          const x = sub.u32be()
          const y = sub.u32be()
          const unit = sub.u8()
          const dpi = unit === 1 ? ` (≈${Math.round(x * 0.0254)} DPI)` : ''
          children.push(region('Pixels per unit', dataStart, 8, { value: `${x} × ${y}${dpi}` }), region('Unit', dataStart + 8, 1, { value: unit === 1 ? '1 — metre' : '0 — unspecified' }))
        } else if (len > 0) {
          children.push(region('Data', dataStart, len, { value: formatSize(len) }))
        }

        children.push(
          region('CRC', dataStart + len, 4, {
            value: hex(crcStored, 8),
            note: 'CRC-32 over the type + data fields (not the length).',
            flag: crcOk ? 'ok' : 'bad',
          }),
        )

        regions.push(
          region(`${type}`, start, 12 + len, {
            value: len === 0 ? 'empty' : formatSize(len),
            note: CHUNK_NOTES[type] ?? (type[0] >= 'a' ? 'Ancillary chunk (unknown type).' : 'Unknown critical chunk.'),
            flag: crcOk ? undefined : 'bad',
            children,
          }),
        )

        if (type === 'IEND') sawEnd = true
      }
    } catch (e) {
      warnings.push(`file truncated: ${e instanceof Error ? e.message : String(e)}`)
    }

    if (sawEnd && r.pos < bytes.length) {
      regions.push(
        region('Trailing data', r.pos, bytes.length - r.pos, {
          value: formatSize(bytes.length - r.pos),
          note: 'Bytes after IEND are not part of the image. Sometimes harmless padding — sometimes a hidden payload or a polyglot file.',
          flag: 'warn',
        }),
      )
      warnings.push(`${bytes.length - r.pos} bytes of trailing data after IEND`)
    }
    if (!sawEnd && warnings.length === 0) warnings.push('no IEND chunk found — file may be truncated')

    summary.push(`${chunkCount} chunks${badCrc ? ` (${badCrc} with bad CRC)` : ''}`)
    if (apng) summary.push('Animated PNG (APNG)')

    return { format: 'PNG image', summary, regions, warnings }
  },
}
