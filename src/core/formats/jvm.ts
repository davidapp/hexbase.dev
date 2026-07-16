import { ByteReader } from '../bytes'
import { region, type ParseResult, type Region } from '../region'
import type { FormatDef } from './def'

/** class-file major version → Java release (major 45 = Java 1.1). */
function javaVersion(major: number): string {
  if (major < 45) return 'pre-Java'
  if (major <= 48) return `Java 1.${major - 44}`
  return `Java ${major - 44}`
}

export const jvmClass: FormatDef = {
  id: 'class',
  name: 'Java class file',
  detect: (b) => {
    if (b.length < 10) return false
    if (!(b[0] === 0xca && b[1] === 0xfe && b[2] === 0xba && b[3] === 0xbe)) return false
    const major = (b[6] << 8) | b[7]
    return major >= 45 && major < 120 // distinguishes from fat Mach-O (small u32 arch count)
  },
  parse(bytes): ParseResult {
    const regions: Region[] = []
    const warnings: string[] = []
    const summary: string[] = []
    try {
      const r = new ByteReader(bytes, 4)
      const minor = r.u16be()
      const major = r.u16be()
      const cpCount = r.u16be()
      regions.push(
        region('Header', 0, 10, {
          children: [
            region('Magic', 0, 4, {
              value: 'CA FE BA BE',
              note: 'James Gosling picked 0xCAFEBABE in 1994 — grunge-era coffee-shop humor that shipped in every JVM since.',
              flag: 'ok',
            }),
            region('Minor version', 4, 2, { value: minor === 0xffff ? '65535 — preview features enabled' : String(minor) }),
            region('Major version', 6, 2, { value: `${major} — ${javaVersion(major)}`, note: 'major − 44 = Java release. javac refuses class files newer than itself.' }),
            region('Constant pool count', 8, 2, { value: `${cpCount} (${cpCount - 1} entries)`, note: 'Off by one by spec: the count is #entries + 1, and index 0 is reserved.' }),
          ],
        }),
      )
      regions.push(
        region('Constant pool + class body', 10, bytes.length - 10, {
          note: 'Variable-length constant pool (strings, class refs, method refs), then access flags, fields, methods with bytecode, and attributes.',
        }),
      )
      summary.push(`compiled for ${javaVersion(major)} (class file ${major}.${minor})`)
      summary.push(`${cpCount - 1} constant pool entries`)
    } catch (e) {
      warnings.push(`file truncated: ${e instanceof Error ? e.message : String(e)}`)
    }
    return { format: 'Java class file', summary, regions, warnings }
  },
}
