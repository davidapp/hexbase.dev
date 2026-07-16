import { ByteReader, formatSize, hex, latin1 } from '../bytes'
import { region, type ParseResult, type Region } from '../region'
import type { FormatDef } from './def'

const CPU_TYPES: Record<number, string> = {
  0x7: 'x86',
  0x1000007: 'x86-64',
  0xc: 'ARM',
  0x100000c: 'ARM64',
  0x12: 'PowerPC',
  0x1000012: 'PowerPC64',
}

const FILE_TYPES: Record<number, string> = {
  1: 'object file (.o)',
  2: 'executable',
  4: 'core dump',
  5: 'preloaded executable',
  6: 'dynamic library (.dylib)',
  7: 'dynamic linker (dyld)',
  8: 'bundle',
  10: 'debug symbols (.dSYM)',
  11: 'kernel extension',
}

const LC_NAMES: Record<number, string> = {
  0x1: 'LC_SEGMENT',
  0x2: 'LC_SYMTAB',
  0xb: 'LC_DYSYMTAB',
  0xc: 'LC_LOAD_DYLIB',
  0xd: 'LC_ID_DYLIB',
  0xe: 'LC_LOAD_DYLINKER',
  0x19: 'LC_SEGMENT_64',
  0x1b: 'LC_UUID',
  0x1d: 'LC_CODE_SIGNATURE',
  0x26: 'LC_FUNCTION_STARTS',
  0x29: 'LC_DATA_IN_CODE',
  0x2a: 'LC_SOURCE_VERSION',
  0x32: 'LC_BUILD_VERSION',
  0x80000018: 'LC_LOAD_WEAK_DYLIB',
  0x80000022: 'LC_DYLD_INFO_ONLY',
  0x80000028: 'LC_MAIN',
  0x8000001c: 'LC_RPATH',
  0x80000033: 'LC_DYLD_EXPORTS_TRIE',
  0x80000034: 'LC_DYLD_CHAINED_FIXUPS',
}

function parseThin(bytes: Uint8Array, base: number, regions: Region[], summary: string[], warnings: string[]): void {
  const magicBE = (bytes[base] << 24) | (bytes[base + 1] << 16) | (bytes[base + 2] << 8) | bytes[base + 3]
  const is64 = (magicBE >>> 0) === 0xfeedfacf || (magicBE >>> 0) === 0xcffaedfe
  const isLE = bytes[base] === 0xce || bytes[base] === 0xcf
  const r = new ByteReader(bytes, base + 4)
  const u32 = () => (isLE ? r.u32le() : r.u32be())

  const cputype = u32()
  u32() // cpusubtype
  const filetype = u32()
  const ncmds = u32()
  const sizeofcmds = u32()
  u32() // flags
  if (is64) u32() // reserved

  const headerLen = is64 ? 32 : 28
  regions.push(
    region('Mach header', base, headerLen, {
      value: `${CPU_TYPES[cputype] ?? '0x' + cputype.toString(16)}, ${FILE_TYPES[filetype] ?? 'type ' + filetype}`,
      children: [
        region('Magic', base, 4, { value: `${hex(bytes[base])} ${hex(bytes[base + 1])} ${hex(bytes[base + 2])} ${hex(bytes[base + 3])} — ${is64 ? '64-bit' : '32-bit'}, ${isLE ? 'little' : 'big'}-endian`, flag: 'ok' }),
        region('CPU type', base + 4, 4, { value: CPU_TYPES[cputype] ?? '0x' + cputype.toString(16) }),
        region('File type', base + 12, 4, { value: FILE_TYPES[filetype] ?? String(filetype) }),
        region('Load commands', base + 16, 8, { value: `${ncmds} commands, ${formatSize(sizeofcmds)}` }),
      ],
    }),
  )
  summary.push(`${is64 ? '64-bit' : '32-bit'} ${CPU_TYPES[cputype] ?? 'unknown CPU'} ${FILE_TYPES[filetype] ?? '?'}`)

  const lcRegions: Region[] = []
  let pos = base + headerLen
  const dylibs: string[] = []
  try {
    for (let i = 0; i < Math.min(ncmds, 64); i++) {
      const c = new ByteReader(bytes, pos)
      const cmd = isLE ? c.u32le() : c.u32be()
      const cmdsize = isLE ? c.u32le() : c.u32be()
      if (cmdsize < 8) break
      const name = LC_NAMES[cmd >>> 0] ?? `LC 0x${(cmd >>> 0).toString(16)}`
      let value = formatSize(cmdsize)
      if ((cmd >>> 0) === 0x19 || (cmd >>> 0) === 0x1) {
        value = latin1(bytes.subarray(pos + 8, pos + 24)).replace(/\0+$/, '')
      } else if ((cmd >>> 0) === 0xc || (cmd >>> 0) === 0xd || (cmd >>> 0) === 0x80000018) {
        const strOff = isLE ? c.u32le() : c.u32be()
        const dylib = latin1(bytes.subarray(pos + strOff, pos + Math.min(cmdsize, strOff + 200))).replace(/\0.*$/s, '')
        value = dylib
        if ((cmd >>> 0) !== 0xd) dylibs.push(dylib)
      } else if ((cmd >>> 0) === 0x1b) {
        const u = bytes.subarray(pos + 8, pos + 24)
        value = [...u].map((b, j) => ([4, 6, 8, 10].includes(j) ? '-' : '') + hex(b)).join('').toLowerCase()
      }
      lcRegions.push(region(name, pos, cmdsize, { value }))
      pos += cmdsize
    }
  } catch (e) {
    warnings.push(`load commands truncated: ${e instanceof Error ? e.message : String(e)}`)
  }
  if (ncmds > 64) warnings.push(`showing first 64 of ${ncmds} load commands`)
  regions.push(
    region('Load commands', base + headerLen, sizeofcmds, {
      value: `${ncmds} commands`,
      note: 'Instructions for dyld: which segments to map, which dylibs to load, where main() is, the code signature…',
      children: lcRegions,
    }),
  )
  if (dylibs.length) summary.push(`links ${dylibs.length} dylib${dylibs.length === 1 ? '' : 's'} (${dylibs.slice(0, 3).map((d) => d.split('/').pop()).join(', ')}${dylibs.length > 3 ? ', …' : ''})`)
}

export const macho: FormatDef = {
  id: 'macho',
  name: 'Mach-O binary (macOS/iOS)',
  detect: (b) => {
    if (b.length < 8) return false
    const m = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]
    const magic = m >>> 0
    if (magic === 0xfeedface || magic === 0xfeedfacf || magic === 0xcefaedfe || magic === 0xcffaedfe) return true
    if (magic === 0xcafebabe) {
      // Shared magic with Java .class — fat Mach-O has a small arch count here.
      const narch = ((b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7]) >>> 0
      return narch >= 1 && narch <= 30
    }
    return false
  },
  parse(bytes): ParseResult {
    const regions: Region[] = []
    const warnings: string[] = []
    const summary: string[] = []

    const magic = (((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0)
    if (magic === 0xcafebabe) {
      const r = new ByteReader(bytes, 4)
      const narch = r.u32be()
      const archRegions: Region[] = []
      summary.push(`universal ("fat") binary with ${narch} architectures`)
      for (let i = 0; i < Math.min(narch, 8); i++) {
        const start = 8 + i * 20
        const a = new ByteReader(bytes, start)
        const cputype = a.u32be()
        a.u32be() // subtype
        const offset = a.u32be()
        const size = a.u32be()
        archRegions.push(region(`Arch ${i + 1}: ${CPU_TYPES[cputype] ?? '0x' + cputype.toString(16)}`, start, 20, { value: `slice at 0x${hex(offset, 4)}, ${formatSize(size)}` }))
        if (offset + 32 <= bytes.length) {
          const sliceRegions: Region[] = []
          parseThin(bytes, offset, sliceRegions, summary, warnings)
          regions.push(region(`${CPU_TYPES[cputype] ?? 'unknown'} slice`, offset, size, { children: sliceRegions }))
        }
      }
      regions.unshift(
        region('Fat header', 0, 8 + narch * 20, {
          value: `${narch} architectures`,
          note: 'A universal binary: one file, several complete Mach-O slices. The header is big-endian even on little-endian machines. Same CAFEBABE magic as Java class files — they are distinguished by what follows.',
          children: archRegions,
        }),
      )
      return { format: 'Mach-O universal binary', summary, regions, warnings }
    }

    parseThin(bytes, 0, regions, summary, warnings)
    return { format: 'Mach-O binary', summary, regions, warnings }
  },
}
