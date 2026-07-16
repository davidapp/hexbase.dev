import { formatSize, latin1 } from '../bytes'
import { region, type ParseResult, type Region } from '../region'
import type { FormatDef } from './def'

const TYPES: Record<string, string> = {
  '0': 'file',
  '\0': 'file',
  '1': 'hard link',
  '2': 'symlink',
  '3': 'char device',
  '4': 'block device',
  '5': 'directory',
  '6': 'FIFO',
  L: 'GNU long name',
  K: 'GNU long link',
  x: 'PAX extended header',
  g: 'PAX global header',
}

function octal(bytes: Uint8Array, start: number, len: number): number {
  const s = latin1(bytes.subarray(start, start + len)).replace(/[\0 ]+$/g, '').replace(/^[\0 ]+/g, '')
  if (!s) return 0
  const v = parseInt(s, 8)
  return Number.isFinite(v) ? v : 0
}

export const tar: FormatDef = {
  id: 'tar',
  name: 'tar archive',
  detect: (b) => b.length >= 512 && latin1(b.subarray(257, 262)) === 'ustar',
  parse(bytes): ParseResult {
    const regions: Region[] = []
    const warnings: string[] = []
    const summary: string[] = []
    let entries = 0
    let totalSize = 0
    let pos = 0

    const isZeroBlock = (off: number): boolean => {
      for (let i = off; i < off + 512 && i < bytes.length; i++) if (bytes[i] !== 0) return false
      return true
    }

    while (pos + 512 <= bytes.length) {
      if (isZeroBlock(pos)) {
        regions.push(
          region('End-of-archive marker', pos, Math.min(1024, bytes.length - pos), {
            note: 'Two 512-byte blocks of zeros signal the end. tar files are often zero-padded further to a blocking factor (10240 B).',
          }),
        )
        break
      }
      const name = latin1(bytes.subarray(pos, pos + 100)).replace(/\0+$/, '')
      const size = octal(bytes, pos + 124, 12)
      const mtime = octal(bytes, pos + 136, 12)
      const type = String.fromCharCode(bytes[pos + 156] || 0x30)
      const mode = octal(bytes, pos + 100, 8)
      const prefix = latin1(bytes.subarray(pos + 345, pos + 500)).replace(/\0.*$/s, '')
      const fullName = prefix ? `${prefix}/${name}` : name

      const dataBlocks = Math.ceil(size / 512)
      entries++
      if (type === '0' || type === '\0') totalSize += size

      if (entries <= 100) {
        regions.push(
          region(fullName || '(unnamed)', pos, 512 + dataBlocks * 512, {
            value: `${TYPES[type] ?? `type ${type}`}, ${formatSize(size)}`,
            note: `mode ${mode.toString(8).padStart(4, '0')}, modified ${mtime ? new Date(mtime * 1000).toISOString().slice(0, 19).replace('T', ' ') + ' UTC' : '(unset)'}`,
            children: [
              region('Header block', pos, 512, {
                note: 'All-text header: name, size and mtime are stored as OCTAL ASCII strings — a 1970s Unix design that survives everywhere.',
              }),
              ...(size > 0 ? [region('File data', pos + 512, size, { value: formatSize(size) })] : []),
            ],
          }),
        )
      }
      pos += 512 + dataBlocks * 512
    }
    if (entries > 100) warnings.push(`showing first 100 of ${entries} entries`)

    summary.push(`${entries} entries, ${formatSize(totalSize)} of file data`)
    summary.push('POSIX ustar format — headers and numbers are plain ASCII (numbers in octal), everything padded to 512-byte blocks')

    return { format: 'tar archive', summary, regions, warnings }
  },
}
