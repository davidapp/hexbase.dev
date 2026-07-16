import { ByteReader, formatSize, latin1 } from '../bytes'
import { region, type ParseResult, type Region } from '../region'
import { startsWith, type FormatDef } from './def'

const APPLE_DATES_EPOCH_MS = Date.UTC(2000, 0, 1) // AppleSingle dates count from 2000-01-01, signed

const ENTRY_IDS: Record<number, [string, string]> = {
  1: ['Data fork', 'The actual file contents (AppleSingle only — AppleDouble keeps data in the visible file).'],
  2: ['Resource fork', 'Classic Mac structured data: icons, code, custom metadata. Still used for some fonts and legacy apps.'],
  3: ['Real name', 'The file\'s original name on the Mac.'],
  4: ['Comment', 'Finder comment.'],
  5: ['Icon, B&W', ''],
  6: ['Icon, color', ''],
  8: ['File dates', 'Create/modify/backup/access as signed 32-bit seconds since 2000-01-01. 0x80000000 = unset.'],
  9: ['Finder info', '32 bytes: type + creator codes, Finder flags — plus extended attributes (xattrs) appended in the modern implementation.'],
  10: ['Macintosh file info', ''],
  11: ['ProDOS file info', ''],
  12: ['MS-DOS file info', ''],
  13: ['Short name (AFP)', ''],
  14: ['AFP file info', ''],
  15: ['Directory ID', ''],
}

/**
 * AppleSingle / AppleDouble — the format behind the `._foo` companion files
 * macOS drops on FAT/NTFS/SMB volumes to carry resource forks and xattrs.
 */
export const appleFork: FormatDef = {
  id: 'applefork',
  name: 'AppleSingle/AppleDouble',
  detect: (b) => startsWith(b, [0x00, 0x05, 0x16, 0x00]) || startsWith(b, [0x00, 0x05, 0x16, 0x07]),
  parse(bytes): ParseResult {
    const regions: Region[] = []
    const warnings: string[] = []
    const summary: string[] = []
    const isDouble = bytes[3] === 0x07
    const name = isDouble ? 'AppleDouble' : 'AppleSingle'

    try {
      const r = new ByteReader(bytes, 0)
      r.skip(4)
      const version = r.u32be()
      r.skip(16) // filler
      const entryCount = r.u16be()

      regions.push(
        region('Header', 0, 26, {
          value: `${name}, ${entryCount} entries`,
          note: isDouble
            ? 'AppleDouble (magic 00051607): the metadata half of a file split in two — this is what those hidden "._" files on USB sticks and SMB shares are.'
            : 'AppleSingle (magic 00051600): data fork + resource fork + metadata all in one file.',
          children: [
            region('Magic', 0, 4, { value: isDouble ? '00 05 16 07' : '00 05 16 00', flag: 'ok' }),
            region('Version', 4, 4, { value: '0x' + version.toString(16).padStart(8, '0') }),
            region('Filler', 8, 16, { note: 'Historically "Mesa" home-of-AppleSingle padding; zeros today.' }),
            region('Entry count', 24, 2, { value: String(entryCount) }),
          ],
        }),
      )

      const kinds: string[] = []
      for (let i = 0; i < Math.min(entryCount, 32); i++) {
        const base = 26 + i * 12
        const e = new ByteReader(bytes, base)
        const id = e.u32be()
        const offset = e.u32be()
        const length = e.u32be()
        const [entryName, entryNote] = ENTRY_IDS[id] ?? [`entry type ${id}`, '']
        kinds.push(entryName)

        const children: Region[] = [region('Descriptor', base, 12, { value: `id ${id}, offset 0x${offset.toString(16)}, ${formatSize(length)}` })]
        if (offset + length <= bytes.length && length > 0) {
          let value = formatSize(length)
          let note = entryNote
          if (id === 3 || id === 4 || id === 13) {
            value = `"${latin1(bytes.subarray(offset, offset + Math.min(length, 80)))}"`
          } else if (id === 9 && length >= 8) {
            const type = latin1(bytes.subarray(offset, offset + 4))
            const creator = latin1(bytes.subarray(offset + 4, offset + 8))
            const hasAttr = length > 32 && latin1(bytes.subarray(offset + 32 + 2, offset + 32 + 6)) === 'ATTR'
            value = `type "${type}", creator "${creator}"${hasAttr ? ' + xattrs' : ''}`
            if (hasAttr) note += ' This one carries extended attributes (the "ATTR" block after the classic 32 bytes).'
          } else if (id === 8 && length >= 16) {
            const d = new ByteReader(bytes, offset)
            const labels = ['created', 'modified', 'backup', 'accessed']
            const parts: string[] = []
            for (const label of labels) {
              const raw = d.u32be()
              const signed = raw >= 0x80000000 ? raw - 0x100000000 : raw
              parts.push(raw === 0x80000000 ? `${label}: unset` : `${label}: ${new Date(APPLE_DATES_EPOCH_MS + signed * 1000).toISOString().slice(0, 10)}`)
            }
            value = parts.join(', ')
          }
          children.push(region('Data', offset, length, { value, note: note || undefined }))
        } else if (length > 0) {
          warnings.push(`entry "${entryName}" points outside the file — truncated?`)
        }
        regions.push(region(entryName, base, 12, { value: formatSize(length), note: entryNote || undefined, children }))
      }

      summary.push(`${name} container, ${entryCount} entries: ${kinds.join(', ')}`)
      if (isDouble) summary.push('Suppress "._" files when copying: use ditto/rsync flags, or dot_clean to merge them back')
    } catch (e) {
      warnings.push(`file truncated: ${e instanceof Error ? e.message : String(e)}`)
    }

    return { format: `${name} (Apple metadata container)`, summary, regions, warnings }
  },
}
