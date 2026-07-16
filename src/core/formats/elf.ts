import { ByteReader, formatSize, hex, latin1 } from '../bytes'
import { region, type ParseResult, type Region } from '../region'
import { startsWith, type FormatDef } from './def'

const MACHINES: Record<number, string> = {
  0x03: 'x86 (i386)',
  0x08: 'MIPS',
  0x14: 'PowerPC',
  0x15: 'PowerPC64',
  0x16: 'S390',
  0x28: 'ARM (32-bit)',
  0x2a: 'SuperH',
  0x32: 'IA-64',
  0x3e: 'x86-64 (AMD64)',
  0xb7: 'AArch64 (ARM64)',
  0xf3: 'RISC-V',
  0xf7: 'BPF',
  0x102: 'LoongArch',
}

const TYPES: Record<number, string> = {
  1: 'REL — relocatable object (.o)',
  2: 'EXEC — executable (fixed load address)',
  3: 'DYN — shared object or PIE executable',
  4: 'CORE — core dump',
}

const OSABI: Record<number, string> = {
  0: 'System V (generic)',
  3: 'Linux (GNU)',
  6: 'Solaris',
  9: 'FreeBSD',
  12: 'OpenBSD',
}

const PT_NAMES: Record<number, [string, string]> = {
  0: ['NULL', 'unused entry'],
  1: ['LOAD', 'segment to map into memory'],
  2: ['DYNAMIC', 'dynamic linking information'],
  3: ['INTERP', 'path of the runtime interpreter (the dynamic linker)'],
  4: ['NOTE', 'auxiliary notes (build id, ABI tags)'],
  6: ['PHDR', 'the program header table itself'],
  7: ['TLS', 'thread-local storage template'],
  0x6474e550: ['GNU_EH_FRAME', 'exception-handling frame index'],
  0x6474e551: ['GNU_STACK', 'stack permissions — RW here means a non-executable stack'],
  0x6474e552: ['GNU_RELRO', 'region made read-only after relocation (security hardening)'],
  0x6474e553: ['GNU_PROPERTY', 'program properties (e.g. IBT/SHSTK flags)'],
}

export const elf: FormatDef = {
  id: 'elf',
  name: 'ELF binary',
  detect: (b) => startsWith(b, [0x7f, 0x45, 0x4c, 0x46]),
  parse(bytes): ParseResult {
    const regions: Region[] = []
    const warnings: string[] = []
    const summary: string[] = []

    try {
      const is64 = bytes[4] === 2
      const isLE = bytes[5] === 1
      const osabi = bytes[7]

      regions.push(
        region('e_ident', 0, 16, {
          value: `${is64 ? '64-bit' : '32-bit'}, ${isLE ? 'little' : 'big'}-endian`,
          note: 'Identification bytes — everything a loader needs before it knows the byte order.',
          children: [
            region('Magic', 0, 4, { value: '7F "ELF"', flag: 'ok' }),
            region('EI_CLASS', 4, 1, { value: is64 ? '2 — 64-bit' : '1 — 32-bit' }),
            region('EI_DATA', 5, 1, { value: isLE ? '1 — little-endian (LSB first)' : '2 — big-endian (MSB first)' }),
            region('EI_VERSION', 6, 1, { value: String(bytes[6]) }),
            region('EI_OSABI', 7, 1, { value: `${osabi} — ${OSABI[osabi] ?? 'other'}` }),
            region('Padding', 8, 8, { note: 'Reserved, must be zero.' }),
          ],
        }),
      )

      const r = new ByteReader(bytes, 16)
      const u16 = () => (isLE ? r.u16le() : r.u16be())
      const u32 = () => (isLE ? r.u32le() : r.u32be())
      const uAddr = () => (is64 ? (isLE ? r.u64le() : r.u64be()) : BigInt(isLE ? r.u32le() : r.u32be()))

      const typePos = r.pos
      const type = u16()
      const machine = u16()
      u32() // e_version
      const entryPos = r.pos
      const entry = uAddr()
      const phoff = uAddr()
      const shoff = uAddr()
      u32() // e_flags
      const ehsize = u16()
      const phentsize = u16()
      const phnum = u16()
      const shentsize = u16()
      const shnum = u16()
      const shstrndx = u16()

      const addrW = is64 ? 8 : 4
      regions.push(
        region('ELF header (rest)', 16, ehsize - 16, {
          children: [
            region('e_type', typePos, 2, { value: TYPES[type] ?? String(type), note: 'Modern distro executables are usually DYN because they are position-independent (ASLR).' }),
            region('e_machine', typePos + 2, 2, { value: MACHINES[machine] ?? `0x${hex(machine, 2)}` }),
            region('e_entry', entryPos, addrW, { value: '0x' + entry.toString(16), note: 'Virtual address where execution starts (_start, not main).' }),
            region('e_phoff', entryPos + addrW, addrW, { value: '0x' + phoff.toString(16), note: 'File offset of the program header table.' }),
            region('e_shoff', entryPos + addrW * 2, addrW, { value: '0x' + shoff.toString(16), note: 'File offset of the section header table.' }),
            region('Counts', entryPos + addrW * 3 + 4 + 2, 10, {
              value: `${phnum} program headers, ${shnum} sections`,
              note: `Program headers (${phentsize} B each) describe runtime segments; sections (${shentsize} B each, name table index ${shstrndx}) describe link-time structure.`,
            }),
          ],
        }),
      )

      summary.push(`${is64 ? '64-bit' : '32-bit'} ${isLE ? 'LSB' : 'MSB'} ${(TYPES[type] ?? '?').split(' — ')[0]}, ${MACHINES[machine] ?? 'unknown machine'}`)
      summary.push(`entry point 0x${entry.toString(16)}, ${phnum} program headers, ${shnum} sections`)

      // Program headers
      const phStart = Number(phoff)
      if (phStart > 0 && phnum > 0 && phStart < bytes.length) {
        const phRegions: Region[] = []
        const p = new ByteReader(bytes, phStart)
        const pu32 = () => (isLE ? p.u32le() : p.u32be())
        const puAddr = () => (is64 ? (isLE ? p.u64le() : p.u64be()) : BigInt(isLE ? p.u32le() : p.u32be()))
        for (let i = 0; i < Math.min(phnum, 32); i++) {
          const start = phStart + i * phentsize
          p.seek(start)
          const ptype = pu32()
          let flags: number
          let offset: bigint, vaddr: bigint, filesz: bigint, memsz: bigint
          if (is64) {
            flags = pu32()
            offset = puAddr()
            vaddr = puAddr()
            puAddr() // paddr
            filesz = puAddr()
            memsz = puAddr()
          } else {
            offset = puAddr()
            vaddr = puAddr()
            puAddr() // paddr
            filesz = puAddr()
            memsz = puAddr()
            flags = pu32()
          }
          const [pname, pnote] = PT_NAMES[ptype] ?? [`0x${ptype.toString(16)}`, 'unknown segment type']
          const perms = `${flags & 4 ? 'R' : '-'}${flags & 2 ? 'W' : '-'}${flags & 1 ? 'X' : '-'}`
          let extra = ''
          if (ptype === 3) {
            const interp = latin1(bytes.subarray(Number(offset), Number(offset) + Number(filesz))).replace(/\0.*$/, '')
            extra = ` → ${interp}`
            summary.push(`interpreter: ${interp}`)
          }
          phRegions.push(
            region(`${pname} [${perms}]`, start, phentsize, {
              value: `file 0x${offset.toString(16)}+${formatSize(Number(filesz))} → vaddr 0x${vaddr.toString(16)}${memsz > filesz ? ` (${formatSize(Number(memsz - filesz))} zero-filled = .bss)` : ''}${extra}`,
              note: pnote,
            }),
          )
        }
        if (phnum > 32) warnings.push(`showing first 32 of ${phnum} program headers`)
        regions.push(
          region('Program header table', phStart, phnum * phentsize, {
            value: `${phnum} entries`,
            note: 'The runtime view: what the kernel/loader maps into memory. R/W/X shows each segment’s permissions.',
            children: phRegions,
          }),
        )
      }

      const shStart = Number(shoff)
      if (shStart > 0 && shnum > 0 && shStart + shnum * shentsize <= bytes.length) {
        regions.push(
          region('Section header table', shStart, shnum * shentsize, {
            value: `${shnum} entries`,
            note: 'The link-time view (.text, .data, .rodata, .symtab…). Strippable — a program runs fine without it.',
          }),
        )
      }
    } catch (e) {
      warnings.push(`file truncated: ${e instanceof Error ? e.message : String(e)}`)
    }

    return { format: 'ELF binary', summary, regions, warnings }
  },
}
