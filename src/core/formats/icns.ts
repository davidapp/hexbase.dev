import { ByteReader, formatSize, latin1 } from '../bytes'
import { region, type ParseResult, type Region } from '../region'
import { startsWith, sigOf, type FormatDef } from './def'

const ICON_TYPES: Record<string, string> = {
  'ic04': '16×16 ARGB',
  'ic05': '32×32 ARGB',
  'ic07': '128×128 (PNG)',
  'ic08': '256×256 (PNG)',
  'ic09': '512×512 (PNG)',
  'ic10': '1024×1024 / 512×512@2x (PNG)',
  'ic11': '32×32 / 16×16@2x (PNG)',
  'ic12': '64×64 / 32×32@2x (PNG)',
  'ic13': '256×256 / 128×128@2x (PNG)',
  'ic14': '512×512 / 256×256@2x (PNG)',
  'icp4': '16×16 (PNG/JP2)',
  'icp5': '32×32 (PNG/JP2)',
  'icp6': '48×48 (PNG/JP2)',
  'is32': '16×16 RGB (legacy)',
  's8mk': '16×16 alpha mask (legacy)',
  'il32': '32×32 RGB (legacy)',
  'l8mk': '32×32 alpha mask (legacy)',
  'ih32': '48×48 RGB (legacy)',
  'h8mk': '48×48 alpha mask (legacy)',
  'it32': '128×128 RGB (legacy)',
  't8mk': '128×128 alpha mask (legacy)',
  'ICN#': '32×32 1-bit + mask (System 7 era)',
  'icl4': '32×32 4-bit (System 7 era)',
  'icl8': '32×32 8-bit (System 7 era)',
  'TOC ': 'table of contents',
  'icnV': 'Icon Composer version',
  'name': 'variant name',
  'info': 'info plist',
  'sbtp': 'template icon variant',
  'slct': 'selected icon variant',
  'sdrk': 'dark-mode icon variant',
}

/** Apple Icon Image (.icns) — a flat list of tagged, sized icon entries. */
export const icns: FormatDef = {
  id: 'icns',
  name: 'Apple icon image (.icns)',
  detect: (b) => startsWith(b, sigOf('icns')),
  parse(bytes): ParseResult {
    const regions: Region[] = []
    const warnings: string[] = []
    const summary: string[] = []
    const r = new ByteReader(bytes, 0)

    try {
      r.skip(4)
      const totalSize = r.u32be()
      regions.push(
        region('Header', 0, 8, {
          value: formatSize(totalSize),
          note: 'The icon format of every .app bundle since Mac OS 8.5 (1998). OSType tags + lengths, nothing more.',
          children: [
            region('Magic', 0, 4, { value: '"icns"', flag: 'ok' }),
            region('Total size', 4, 4, { value: formatSize(totalSize), flag: totalSize === bytes.length ? 'ok' : 'warn' }),
          ],
        }),
      )
      if (totalSize !== bytes.length) warnings.push(`header says ${totalSize} bytes but the file is ${bytes.length}`)

      const sizesFound: string[] = []
      let entries = 0
      while (r.remaining() >= 8 && entries < 200) {
        const start = r.pos
        const type = r.ascii(4)
        const len = r.u32be()
        if (len < 8 || start + len > bytes.length) {
          warnings.push(`entry "${type}" at offset ${start} has an invalid length — stopping`)
          break
        }
        entries++
        const dataStart = start + 8
        const isPng = startsWith(bytes, [0x89, 0x50, 0x4e, 0x47], dataStart)
        const isJp2 = startsWith(bytes, [0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50], dataStart)
        const label = ICON_TYPES[type] ?? 'unknown type'
        if (label.includes('×')) sizesFound.push(label.split(' ')[0] + (label.includes('@2x') ? '@2x' : ''))
        regions.push(
          region(`"${type}"`, start, len, {
            value: `${label}, ${formatSize(len - 8)}${isPng ? ' — PNG data' : isJp2 ? ' — JPEG 2000 data' : ''}`,
            note: isPng ? 'Modern entries are just PNG files wearing an OSType tag — extract the bytes from offset +8 and you have a .png.' : undefined,
          }),
        )
        r.seek(start + len)
      }

      summary.push(`${entries} entr${entries === 1 ? 'y' : 'ies'}${sizesFound.length ? ': ' + sizesFound.join(', ') : ''}`)
      summary.push('Extract on macOS: iconutil -c iconset file.icns')
    } catch (e) {
      warnings.push(`file truncated: ${e instanceof Error ? e.message : String(e)}`)
    }

    return { format: 'Apple icon image (.icns)', summary, regions, warnings }
  },
}
