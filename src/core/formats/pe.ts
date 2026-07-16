import { ByteReader, formatSize, hex, latin1 } from '../bytes'
import { region, type ParseResult, type Region } from '../region'
import { startsWith, type FormatDef } from './def'

const MACHINES: Record<number, string> = {
  0x014c: 'x86 (i386)',
  0x0200: 'IA-64',
  0x8664: 'x86-64 (AMD64)',
  0x01c0: 'ARM',
  0x01c4: 'ARM Thumb-2',
  0xaa64: 'ARM64',
  0x5032: 'RISC-V 32',
  0x5064: 'RISC-V 64',
}

const SUBSYSTEMS: Record<number, string> = {
  1: 'native (driver)',
  2: 'Windows GUI',
  3: 'Windows console',
  5: 'OS/2 console',
  7: 'POSIX console',
  9: 'Windows CE GUI',
  10: 'EFI application',
  11: 'EFI boot service driver',
  12: 'EFI runtime driver',
  16: 'Windows boot application',
}

export const pe: FormatDef = {
  id: 'pe',
  name: 'PE executable (Windows)',
  detect: (b) => startsWith(b, [0x4d, 0x5a]),
  parse(bytes): ParseResult {
    const regions: Region[] = []
    const warnings: string[] = []
    const summary: string[] = []

    try {
      const r = new ByteReader(bytes, 0x3c)
      const lfanew = r.u32le()

      regions.push(
        region('DOS header', 0, 64, {
          value: 'MZ',
          note: '"MZ" = Mark Zbikowski, who designed the DOS executable format. Every Windows EXE still starts with a tiny DOS program.',
          children: [
            region('Magic', 0, 2, { value: '4D 5A — "MZ"', flag: 'ok' }),
            region('e_lfanew', 0x3c, 4, { value: '0x' + hex(lfanew, 4), note: 'File offset of the real (PE) header.' }),
          ],
        }),
      )
      if (lfanew > 64) {
        regions.push(
          region('DOS stub', 64, lfanew - 64, {
            note: 'The 16-bit program that prints "This program cannot be run in DOS mode." when you try exactly that.',
          }),
        )
      }

      if (lfanew + 24 > bytes.length || latin1(bytes.subarray(lfanew, lfanew + 4)) !== 'PE\0\0') {
        warnings.push('no PE\\0\\0 signature at e_lfanew — this is a plain DOS executable or corrupt file')
        return { format: 'MZ executable (DOS)', summary: ['DOS MZ executable without PE header'], regions, warnings }
      }

      const c = new ByteReader(bytes, lfanew + 4)
      const machine = c.u16le()
      const nSections = c.u16le()
      const timestamp = c.u32le()
      c.u32le() // symtab ptr
      c.u32le() // symbol count
      const optSize = c.u16le()
      const characteristics = c.u16le()
      const isDll = (characteristics & 0x2000) !== 0

      regions.push(
        region('PE signature + COFF header', lfanew, 24, {
          value: MACHINES[machine] ?? `machine 0x${hex(machine, 4)}`,
          children: [
            region('Signature', lfanew, 4, { value: '"PE\\0\\0"', flag: 'ok' }),
            region('Machine', lfanew + 4, 2, { value: `0x${hex(machine, 4)} — ${MACHINES[machine] ?? 'unknown'}` }),
            region('Sections', lfanew + 6, 2, { value: String(nSections) }),
            region('Timestamp', lfanew + 8, 4, {
              value: timestamp === 0 ? '0 — not set' : new Date(timestamp * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC'),
              note: 'Unix timestamp of linking. Modern reproducible builds store a hash here instead of a real time.',
            }),
            region('Optional header size', lfanew + 20, 2, { value: String(optSize) }),
            region('Characteristics', lfanew + 22, 2, {
              value: `0x${hex(characteristics, 4)}${isDll ? ' — DLL' : characteristics & 2 ? ' — executable' : ''}`,
            }),
          ],
        }),
      )

      const optStart = lfanew + 24
      let subsystem = -1
      let entryRva = 0
      let imageBase = 0n
      let pePlus = false
      if (optSize >= 70 && optStart + optSize <= bytes.length) {
        const o = new ByteReader(bytes, optStart)
        const magic = o.u16le()
        pePlus = magic === 0x20b
        o.skip(14) // linker versions + sizeof code/init data... (2 + 4*3 = 14)
        entryRva = o.u32le()
        o.u32le() // base of code
        if (pePlus) {
          imageBase = o.u64le()
        } else {
          o.u32le() // base of data
          imageBase = BigInt(o.u32le())
        }
        const sub = new ByteReader(bytes, optStart + 68)
        subsystem = sub.u16le()
        const dllChars = sub.u16le()
        const flags: string[] = []
        if (dllChars & 0x0020) flags.push('CFG')
        if (dllChars & 0x0040) flags.push('ASLR')
        if (dllChars & 0x0100) flags.push('DEP/NX')
        if (dllChars & 0x4000) flags.push('CET')
        regions.push(
          region(`Optional header (${pePlus ? 'PE32+' : 'PE32'})`, optStart, optSize, {
            value: `${SUBSYSTEMS[subsystem] ?? 'unknown subsystem'}`,
            note: '"Optional" only for object files — every real executable has one. PE32+ is the 64-bit variant.',
            children: [
              region('Magic', optStart, 2, { value: pePlus ? '0x20B — PE32+ (64-bit)' : '0x10B — PE32 (32-bit)' }),
              region('Entry point RVA', optStart + 16, 4, { value: '0x' + hex(entryRva, 4), note: 'Relative to the image base once loaded.' }),
              region('Image base', optStart + (pePlus ? 24 : 28), pePlus ? 8 : 4, { value: '0x' + imageBase.toString(16), note: 'Preferred load address; ASLR relocates from here.' }),
              region('Subsystem', optStart + 68, 2, { value: `${subsystem} — ${SUBSYSTEMS[subsystem] ?? 'unknown'}` }),
              region('DLL characteristics', optStart + 70, 2, { value: flags.length ? flags.join(' + ') : 'none', note: 'Security mitigations: ASLR (dynamic base), DEP (no-execute), CFG (control-flow guard), CET (shadow stack).' }),
            ],
          }),
        )
      }

      // Section table
      const secStart = optStart + optSize
      const secRegions: Region[] = []
      const s = new ByteReader(bytes, secStart)
      for (let i = 0; i < Math.min(nSections, 40); i++) {
        const st = secStart + i * 40
        s.seek(st)
        const name = latin1(s.slice(8)).replace(/\0+$/, '')
        const vsize = s.u32le()
        const vaddr = s.u32le()
        const rawSize = s.u32le()
        const rawPtr = s.u32le()
        s.skip(12)
        const ch = s.u32le()
        const perms = `${ch & 0x40000000 ? 'R' : '-'}${ch & 0x80000000 ? 'W' : '-'}${ch & 0x20000000 ? 'X' : '-'}`
        secRegions.push(
          region(`${name || '(unnamed)'} [${perms}]`, st, 40, {
            value: `raw 0x${hex(rawPtr, 4)}+${formatSize(rawSize)} → RVA 0x${hex(vaddr, 4)} (${formatSize(vsize)})`,
            note:
              name === '.text' ? 'Executable code.'
              : name === '.data' ? 'Initialized writable data.'
              : name === '.rdata' ? 'Read-only data (constants, import tables).'
              : name === '.bss' ? 'Zero-initialized data (no bytes on disk).'
              : name === '.rsrc' ? 'Resources: icons, dialogs, version info.'
              : name === '.reloc' ? 'Base relocations for ASLR.'
              : undefined,
          }),
        )
      }
      if (nSections > 40) warnings.push(`showing first 40 of ${nSections} sections`)
      regions.push(
        region('Section table', secStart, nSections * 40, {
          value: `${nSections} sections`,
          children: secRegions,
        }),
      )

      summary.push(`${pePlus ? 'PE32+ (64-bit)' : 'PE32 (32-bit)'} ${isDll ? 'DLL' : 'executable'}, ${MACHINES[machine] ?? 'unknown machine'}`)
      if (subsystem >= 0) summary.push(`subsystem: ${SUBSYSTEMS[subsystem] ?? subsystem}, entry RVA 0x${hex(entryRva, 4)}, image base 0x${imageBase.toString(16)}`)
      summary.push(`${nSections} sections${timestamp ? `, linked ${new Date(timestamp * 1000).toISOString().slice(0, 10)}` : ''}`)
    } catch (e) {
      warnings.push(`file truncated: ${e instanceof Error ? e.message : String(e)}`)
    }

    return { format: 'PE executable (Windows)', summary, regions, warnings }
  },
}
