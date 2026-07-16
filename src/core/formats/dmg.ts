import { ByteReader, formatSize, hex, latin1 } from '../bytes'
import { region, type ParseResult, type Region } from '../region'
import type { FormatDef } from './def'

const CHECKSUM_TYPES: Record<number, string> = { 0: 'none', 1: 'UDIF CRC-32', 2: 'CRC-32', 0x20: 'unknown (0x20)' }

/**
 * Apple UDIF disk image (.dmg). The identifying structure is the 512-byte
 * "koly" trailer at EOF — the file body is opaque compressed block data,
 * which is why a .dmg has no magic at offset 0.
 */
export const dmg: FormatDef = {
  id: 'dmg',
  name: 'Apple disk image (.dmg)',
  detect: (b) => b.length >= 512 && latin1(b.subarray(b.length - 512, b.length - 508)) === 'koly',
  parse(bytes): ParseResult {
    const regions: Region[] = []
    const warnings: string[] = []
    const summary: string[] = []
    const k = bytes.length - 512
    const r = new ByteReader(bytes, k + 4)

    const version = r.u32be()
    const headerSize = r.u32be()
    const flags = r.u32be()
    r.u64be() // running data fork offset
    const dataForkOffset = Number(r.u64be())
    const dataForkLength = Number(r.u64be())
    const rsrcForkOffset = Number(r.u64be())
    const rsrcForkLength = Number(r.u64be())
    const segmentNumber = r.u32be()
    const segmentCount = r.u32be()
    const segmentId = bytes.subarray(k + 64, k + 80)
    r.seek(k + 80)
    const dataCksumType = r.u32be()
    r.seek(k + 216)
    const xmlOffset = Number(r.u64be())
    const xmlLength = Number(r.u64be())
    r.seek(k + 488)
    const imageVariant = r.u32be()
    const sectorCount = Number(r.u64be())

    const uuid = [...segmentId].map((b, i) => ([4, 6, 8, 10].includes(i) ? '-' : '') + hex(b)).join('').toLowerCase()

    if (dataForkLength > 0 && dataForkOffset + dataForkLength <= bytes.length) {
      regions.push(
        region('Data fork (compressed blocks)', dataForkOffset, dataForkLength, {
          value: formatSize(dataForkLength),
          note: 'The disk sectors, stored as runs of zlib/bzip2/LZFSE/raw blocks. The blkx table in the XML plist says which run maps to which sectors.',
        }),
      )
    }
    if (rsrcForkLength > 0 && rsrcForkOffset + rsrcForkLength <= bytes.length) {
      regions.push(region('Resource fork', rsrcForkOffset, rsrcForkLength, { value: formatSize(rsrcForkLength), note: 'Legacy (pre-XML) block table storage.' }))
    }
    if (xmlLength > 0 && xmlOffset + xmlLength <= bytes.length) {
      const preview = latin1(bytes.subarray(xmlOffset, xmlOffset + Math.min(xmlLength, 3000)))
      const nameMatch = /<key>Name<\/key>\s*<string>([^<]{1,80})<\/string>/.exec(preview)
      regions.push(
        region('XML property list', xmlOffset, xmlLength, {
          value: formatSize(xmlLength) + (nameMatch ? ` — "${nameMatch[1]}"` : ''),
          note: 'A plain-text plist embedded in the image: partition names and the blkx block map. Yes — there is XML inside your .dmg.',
        }),
      )
    }

    regions.push(
      region('koly trailer', k, 512, {
        value: `UDIF v${version}`,
        note: '"koly" — the UDIF trailer, always the last 512 bytes and big-endian. Tools identify a .dmg by seeking to EOF−512, not by the first bytes.',
        children: [
          region('Signature', k, 4, { value: '"koly"', flag: 'ok' }),
          region('Version / header size', k + 4, 8, { value: `v${version}, ${headerSize} B` }),
          region('Flags', k + 12, 4, { value: '0x' + hex(flags, 8) + (flags & 1 ? ' (flattened)' : '') }),
          region('Data fork', k + 24, 16, { value: `0x${dataForkOffset.toString(16)} + ${formatSize(dataForkLength)}` }),
          region('Resource fork', k + 40, 16, { value: rsrcForkLength ? `0x${rsrcForkOffset.toString(16)} + ${formatSize(rsrcForkLength)}` : 'none' }),
          region('Segment', k + 56, 8, { value: `${segmentNumber} of ${segmentCount}`, note: 'Multi-segment images (.dmgpart) were a thing when media was small.' }),
          region('Segment UUID', k + 64, 16, { value: uuid }),
          region('Data checksum type', k + 80, 8, { value: CHECKSUM_TYPES[dataCksumType] ?? `type ${dataCksumType}` }),
          region('XML plist location', k + 216, 16, { value: `0x${xmlOffset.toString(16)} + ${formatSize(xmlLength)}` }),
          region('Image variant', k + 488, 4, { value: String(imageVariant) }),
          region('Sector count', k + 492, 8, { value: `${sectorCount} × 512 B = ${formatSize(sectorCount * 512)}`, note: 'Size of the virtual disk once mounted (not the file size).' }),
        ],
      }),
    )

    if (segmentCount > 1) warnings.push(`segment ${segmentNumber} of ${segmentCount} — this is one part of a multi-segment image`)
    summary.push(`UDIF v${version}, virtual disk ${formatSize(sectorCount * 512)} in ${formatSize(bytes.length)} file`)
    summary.push(`data fork ${formatSize(dataForkLength)}${xmlLength ? `, blkx plist ${formatSize(xmlLength)}` : ''}`)
    summary.push('Inspect on macOS: hdiutil imageinfo file.dmg')

    return { format: 'Apple disk image (.dmg)', summary, regions, warnings }
  },
}
