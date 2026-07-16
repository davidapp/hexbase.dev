import { ByteReader, formatSize, hex, latin1 } from '../bytes'
import { region, type ParseResult, type Region } from '../region'
import { startsWith, type FormatDef } from './def'

const METHODS: Record<number, string> = {
  0: 'stored (no compression)',
  1: 'shrunk',
  6: 'imploded',
  8: 'deflate',
  9: 'deflate64',
  12: 'bzip2',
  14: 'LZMA',
  93: 'zstd',
  95: 'XZ',
  98: 'PPMd',
  99: 'AES encrypted',
}

const pad2 = (n: number) => String(n).padStart(2, '0')

function dosDateTime(date: number, time: number): string {
  const day = date & 0x1f
  const month = (date >> 5) & 0x0f
  const year = ((date >> 9) & 0x7f) + 1980
  const sec = (time & 0x1f) * 2
  const min = (time >> 5) & 0x3f
  const hour = (time >> 11) & 0x1f
  return `${year}-${pad2(month)}-${pad2(day)} ${pad2(hour)}:${pad2(min)}:${pad2(sec)}`
}

/** What kind of ZIP is this really? Office docs, JARs and APKs are all ZIPs. */
function sniffSubtype(names: string[]): string | null {
  if (names.includes('[Content_Types].xml')) {
    if (names.some((n) => n.startsWith('word/'))) return 'Word document (.docx)'
    if (names.some((n) => n.startsWith('xl/'))) return 'Excel workbook (.xlsx)'
    if (names.some((n) => n.startsWith('ppt/'))) return 'PowerPoint deck (.pptx)'
    return 'Office Open XML document'
  }
  if (names.includes('AndroidManifest.xml')) return 'Android package (.apk)'
  if (names.includes('META-INF/MANIFEST.MF')) return 'Java archive (.jar)'
  if (names.includes('mimetype')) return 'EPUB or OpenDocument'
  return null
}

export const zip: FormatDef = {
  id: 'zip',
  name: 'ZIP archive',
  mime: 'application/zip',
  detect: (b) => startsWith(b, [0x50, 0x4b, 0x03, 0x04]) || startsWith(b, [0x50, 0x4b, 0x05, 0x06]) || startsWith(b, [0x50, 0x4b, 0x07, 0x08]),
  parse(bytes): ParseResult {
    const regions: Region[] = []
    const warnings: string[] = []
    const summary: string[] = []

    // ZIPs are read back-to-front: find the End Of Central Directory record.
    let eocd = -1
    const scanFloor = Math.max(0, bytes.length - 22 - 65535)
    for (let i = bytes.length - 22; i >= scanFloor; i--) {
      if (bytes[i] === 0x50 && bytes[i + 1] === 0x4b && bytes[i + 2] === 0x05 && bytes[i + 3] === 0x06) {
        eocd = i
        break
      }
    }

    if (startsWith(bytes, [0x50, 0x4b, 0x03, 0x04])) {
      regions.push(
        region('First local file header', 0, 4, {
          value: 'PK\\x03\\x04',
          note: '"PK" is Phil Katz, author of PKZIP (1989). Each stored file starts with a local header, but the authoritative index is the central directory at the end of the file.',
          flag: 'ok',
        }),
      )
    }

    if (eocd === -1) {
      warnings.push('no End Of Central Directory record found — truncated or not really a ZIP')
      return { format: 'ZIP archive', summary: ['central directory missing'], regions, warnings }
    }

    const r = new ByteReader(bytes, eocd + 4)
    const diskNum = r.u16le()
    const cdDisk = r.u16le()
    const entriesDisk = r.u16le()
    const entriesTotal = r.u16le()
    const cdSize = r.u32le()
    const cdOffset = r.u32le()
    const commentLen = r.u16le()

    const names: string[] = []
    const entryRegions: Region[] = []
    let totalComp = 0
    let totalUncomp = 0
    let encrypted = 0

    try {
      const cd = new ByteReader(bytes, cdOffset)
      for (let i = 0; i < entriesTotal; i++) {
        const start = cd.pos
        if (cd.u32le() !== 0x02014b50) {
          warnings.push(`central directory entry ${i} has a bad signature at offset 0x${hex(start, 4)}`)
          break
        }
        cd.u16le() // version made by
        cd.u16le() // version needed
        const flags = cd.u16le()
        const method = cd.u16le()
        const mtime = cd.u16le()
        const mdate = cd.u16le()
        const crc = cd.u32le()
        const comp = cd.u32le()
        const uncomp = cd.u32le()
        const nameLen = cd.u16le()
        const extraLen = cd.u16le()
        const cmtLen = cd.u16le()
        cd.u16le() // disk
        cd.u16le() // internal attrs
        cd.u32le() // external attrs
        const lho = cd.u32le()
        const name = latin1(cd.slice(nameLen))
        cd.skip(extraLen + cmtLen)

        names.push(name)
        totalComp += comp
        totalUncomp += uncomp
        const isEncrypted = (flags & 1) !== 0
        if (isEncrypted) encrypted++

        if (i < 200) {
          entryRegions.push(
            region(name || '(unnamed)', start, cd.pos - start, {
              value: `${formatSize(uncomp)} → ${formatSize(comp)}`,
              note: `${METHODS[method] ?? `method ${method}`}, modified ${dosDateTime(mdate, mtime)}${isEncrypted ? ', ENCRYPTED' : ''}, CRC ${hex(crc, 8)}, local header at 0x${hex(lho, 4)}`,
              flag: isEncrypted ? 'warn' : undefined,
            }),
          )
        }
      }
      if (entriesTotal > 200) warnings.push(`showing first 200 of ${entriesTotal} entries`)
    } catch (e) {
      warnings.push(`central directory truncated: ${e instanceof Error ? e.message : String(e)}`)
    }

    if (cdOffset > 4) {
      regions.push(
        region('File data (local headers + compressed streams)', 0, cdOffset, {
          value: formatSize(cdOffset),
          note: 'Each file: a local header (PK\\x03\\x04), the file name, then the compressed bytes.',
        }),
      )
    }

    regions.push(
      region('Central directory', cdOffset, cdSize, {
        value: `${entriesTotal} entries`,
        note: 'The archive index. Tools list a ZIP by reading this, never by walking local headers — which is why appended/edited ZIPs can lie about their contents.',
        children: entryRegions,
      }),
    )

    regions.push(
      region('End of central directory', eocd, 22 + commentLen, {
        value: `${entriesTotal} entries`,
        note: 'Found by scanning backwards from the end of the file. Points at the central directory.',
        children: [
          region('Signature', eocd, 4, { value: 'PK\\x05\\x06', flag: 'ok' }),
          region('Disk numbers', eocd + 4, 4, { value: `disk ${diskNum}, CD starts on disk ${cdDisk}`, note: 'From the floppy-disk era: ZIPs could span multiple disks.' }),
          region('Entry counts', eocd + 8, 4, { value: `${entriesDisk} on this disk, ${entriesTotal} total` }),
          region('Central directory size', eocd + 12, 4, { value: formatSize(cdSize) }),
          region('Central directory offset', eocd + 16, 4, { value: '0x' + hex(cdOffset, 4) }),
          region('Comment length', eocd + 20, 2, { value: String(commentLen) }),
          ...(commentLen > 0
            ? [region('Comment', eocd + 22, commentLen, { value: latin1(bytes.subarray(eocd + 22, eocd + 22 + Math.min(commentLen, 80))) })]
            : []),
        ],
      }),
    )

    const subtype = sniffSubtype(names)
    if (subtype) summary.push(`Actually: ${subtype} (ZIP container)`)
    summary.push(`${entriesTotal} entries, ${formatSize(totalUncomp)} → ${formatSize(totalComp)}${totalUncomp > 0 ? ` (${Math.round((totalComp / Math.max(totalUncomp, 1)) * 100)}%)` : ''}`)
    if (encrypted > 0) summary.push(`${encrypted} encrypted entr${encrypted === 1 ? 'y' : 'ies'}`)

    return { format: subtype ? `ZIP archive — ${subtype}` : 'ZIP archive', summary, regions, warnings }
  },
}
