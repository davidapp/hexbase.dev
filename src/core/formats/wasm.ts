import { formatSize, latin1 } from '../bytes'
import { region, type ParseResult, type Region } from '../region'
import { startsWith, type FormatDef } from './def'

const SECTIONS: Record<number, [string, string]> = {
  0: ['custom', 'Named vendor section — "name" (debug symbols), "producers" (toolchain), source maps…'],
  1: ['type', 'Function signatures used by the module.'],
  2: ['import', 'Functions/memories/tables/globals the host must provide.'],
  3: ['function', 'Maps each function to its type signature.'],
  4: ['table', 'Tables (mainly for indirect calls / funcrefs).'],
  5: ['memory', 'Linear memory declarations (pages of 64 KiB).'],
  6: ['global', 'Global variables.'],
  7: ['export', 'Names the module exposes to the host.'],
  8: ['start', 'Function to run automatically on instantiation.'],
  9: ['element', 'Table initialisers.'],
  10: ['code', 'The actual function bodies (stack-machine bytecode).'],
  11: ['data', 'Linear-memory initialisers.'],
  12: ['data count', 'Number of data segments (enables single-pass validation).'],
  13: ['tag', 'Exception tags.'],
}

function uleb(bytes: Uint8Array, pos: number): { value: number; size: number } {
  let result = 0
  let shift = 0
  let size = 0
  for (;;) {
    if (pos + size >= bytes.length) throw new RangeError('truncated LEB128 value')
    const b = bytes[pos + size]
    result |= (b & 0x7f) << shift
    size++
    if ((b & 0x80) === 0) break
    shift += 7
    if (shift > 35) throw new RangeError('LEB128 value too long')
  }
  return { value: result >>> 0, size }
}

export const wasm: FormatDef = {
  id: 'wasm',
  name: 'WebAssembly module',
  mime: 'application/wasm',
  detect: (b) => startsWith(b, [0x00, 0x61, 0x73, 0x6d]),
  parse(bytes): ParseResult {
    const regions: Region[] = []
    const warnings: string[] = []
    const summary: string[] = []
    const sectionNames: string[] = []

    regions.push(
      region('Header', 0, 8, {
        children: [
          region('Magic', 0, 4, { value: '"\\0asm"', flag: 'ok' }),
          region('Version', 4, 4, { value: String(bytes[4] | (bytes[5] << 8) | (bytes[6] << 16) | (bytes[7] << 24)), note: 'Binary format version — 1 since the 2017 MVP.' }),
        ],
      }),
    )

    let pos = 8
    try {
      let guard = 0
      while (pos < bytes.length && guard++ < 500) {
        const start = pos
        const id = bytes[pos]
        pos++
        const size = uleb(bytes, pos)
        pos += size.size
        const payloadStart = pos
        const payloadEnd = payloadStart + size.value
        if (payloadEnd > bytes.length) {
          warnings.push(`section at offset ${start} claims ${size.value} bytes but the file ends first`)
          break
        }
        const [name, note] = SECTIONS[id] ?? [`id ${id}`, 'Unknown section.']
        let value = formatSize(size.value)

        if (id === 0) {
          const nameLen = uleb(bytes, payloadStart)
          const customName = latin1(bytes.subarray(payloadStart + nameLen.size, payloadStart + nameLen.size + Math.min(nameLen.value, 64)))
          value = `"${customName}" — ${formatSize(size.value)}`
          sectionNames.push(`custom("${customName}")`)
        } else {
          sectionNames.push(name)
          // Most sections start with an item count.
          if (id >= 1 && id <= 11 && id !== 8 && size.value > 0) {
            try {
              const count = uleb(bytes, payloadStart)
              value = `${count.value} item${count.value === 1 ? '' : 's'}, ${formatSize(size.value)}`
            } catch {
              /* leave size-only value */
            }
          }
        }

        regions.push(region(`${name} section`, start, payloadEnd - start, { value, note }))
        pos = payloadEnd
      }
    } catch (e) {
      warnings.push(`file truncated: ${e instanceof Error ? e.message : String(e)}`)
    }

    summary.push(`WebAssembly binary, ${sectionNames.length} sections`)
    summary.push(sectionNames.join(' · '))

    return { format: 'WebAssembly module', summary, regions, warnings }
  },
}
