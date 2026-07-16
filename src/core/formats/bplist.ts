import { ByteReader, bytesToHex, formatSize, latin1 } from '../bytes'
import { region, type ParseResult, type Region } from '../region'
import { startsWith, sigOf, type FormatDef } from './def'

const COCOA_EPOCH_MS = 978307200000
const MAX_OBJECTS_SHOWN = 400
const MAX_DEPTH = 8

/**
 * Apple binary property list (bplist00). Layout:
 *   "bplist00" header · object table · offset table · 32-byte trailer.
 * The trailer (read first, like ZIP's EOCD) says where the offset table is;
 * the offset table maps object index → file offset; objects reference each
 * other by index. We decode the whole object graph.
 */
export const bplist: FormatDef = {
  id: 'bplist',
  name: 'Binary property list (Apple)',
  detect: (b) => startsWith(b, sigOf('bplist0')),
  parse(bytes): ParseResult {
    const regions: Region[] = []
    const warnings: string[] = []
    const summary: string[] = []

    regions.push(
      region('Header', 0, 8, {
        value: latin1(bytes.subarray(0, 8)),
        note: '"bplist00" — Apple\'s binary plist, used by NSUserDefaults, Info.plist caches, Spotlight, iOS backups… `plutil -p file` pretty-prints one.',
        flag: 'ok',
      }),
    )

    if (bytes.length < 40) {
      warnings.push('file too small to hold a bplist trailer')
      return { format: 'Binary property list (Apple)', summary, regions, warnings }
    }

    // ---- trailer ----
    const tStart = bytes.length - 32
    const t = new ByteReader(bytes, tStart)
    t.skip(5)
    t.u8() // sort version
    const offsetIntSize = t.u8()
    const objectRefSize = t.u8()
    const numObjects = Number(t.u64be())
    const topObject = Number(t.u64be())
    const offsetTableOffset = Number(t.u64be())

    const trailerRegion = region('Trailer', tStart, 32, {
      value: `${numObjects} objects`,
      note: 'Fixed 32 bytes at EOF, read first — like ZIP, a bplist is parsed back-to-front.',
      children: [
        region('Offset int size', tStart + 6, 1, { value: `${offsetIntSize} byte${offsetIntSize === 1 ? '' : 's'}`, note: 'Width of each entry in the offset table (grows with file size).' }),
        region('Object ref size', tStart + 7, 1, { value: `${objectRefSize} byte${objectRefSize === 1 ? '' : 's'}`, note: 'Width of the object indices arrays/dicts use to reference children.' }),
        region('Object count', tStart + 8, 8, { value: String(numObjects) }),
        region('Top object index', tStart + 16, 8, { value: String(topObject), note: 'The root of the object graph (usually a dict).' }),
        region('Offset table offset', tStart + 24, 8, { value: '0x' + offsetTableOffset.toString(16).toUpperCase() }),
      ],
    })

    if (
      offsetIntSize < 1 || offsetIntSize > 8 || objectRefSize < 1 || objectRefSize > 8 ||
      numObjects <= 0 || numObjects > 1_000_000 || topObject >= numObjects ||
      offsetTableOffset + numObjects * offsetIntSize > tStart
    ) {
      warnings.push('trailer values are implausible — file is truncated or not a bplist')
      regions.push(trailerRegion)
      return { format: 'Binary property list (Apple)', summary, regions, warnings }
    }

    const readUIntAt = (pos: number, size: number): number => {
      let v = 0
      for (let i = 0; i < size; i++) v = v * 256 + bytes[pos + i]
      return v
    }

    const offsets: number[] = []
    for (let i = 0; i < numObjects; i++) offsets.push(readUIntAt(offsetTableOffset + i * offsetIntSize, offsetIntSize))

    // ---- object graph ----
    const TYPE_NOTES: Record<number, string> = {
      0x1: 'Integer — 2^n bytes, big-endian.',
      0x2: 'Real — 4-byte float or 8-byte double, big-endian.',
      0x3: 'Date — 8-byte double: seconds since 2001-01-01 (the Cocoa epoch).',
      0x4: 'Raw NSData bytes.',
      0x5: 'ASCII string — one byte per char.',
      0x6: 'Unicode string — UTF-16 big-endian.',
      0x8: 'UID — object reference used by NSKeyedArchiver archives.',
      0xa: 'Array — a list of object references.',
      0xc: 'Set — like an array, unordered.',
      0xd: 'Dictionary — all key refs first, then all value refs.',
    }

    let shown = 0
    const parseObject = (index: number, depth: number, stack: Set<number>): { region: Region; brief: string } => {
      const off = offsets[index]
      const bad = (why: string): { region: Region; brief: string } => ({
        region: region(`object ${index}`, Math.min(off, bytes.length - 1), 1, { note: why, flag: 'bad' }),
        brief: '?',
      })
      if (off === undefined || off >= tStart) return bad('object offset points outside the object table')
      if (stack.has(index)) return bad('circular reference')
      if (depth > MAX_DEPTH) {
        return { region: region('…', off, 1, { note: `nesting deeper than ${MAX_DEPTH} levels not expanded` }), brief: '…' }
      }
      shown++

      const marker = bytes[off]
      const hi = marker >> 4
      const lo = marker & 0x0f

      // count field: small counts live in the marker's low nibble; bigger ones
      // are a full int object inlined right after the marker byte.
      let count = lo
      let headLen = 1
      if (lo === 0x0f && (hi === 0x4 || hi === 0x5 || hi === 0x6 || hi === 0xa || hi === 0xc || hi === 0xd)) {
        const intMarker = bytes[off + 1]
        const intSize = 1 << (intMarker & 0x0f)
        count = readUIntAt(off + 2, intSize)
        headLen = 2 + intSize
      }

      const mk = (name: string, length: number, extra: Partial<Region>, brief: string) => ({
        region: region(name, off, length, { note: TYPE_NOTES[hi], ...extra }),
        brief,
      })

      switch (hi) {
        case 0x0: {
          if (marker === 0x00) return mk('null', 1, { value: 'null' }, 'null')
          if (marker === 0x08) return mk('boolean', 1, { value: 'false' }, 'false')
          if (marker === 0x09) return mk('boolean', 1, { value: 'true' }, 'true')
          return mk('fill/unknown', 1, { value: '0x' + marker.toString(16) }, '?')
        }
        case 0x1: {
          const size = 1 << lo
          let value: string
          if (size <= 6) {
            value = String(readUIntAt(off + 1, size))
          } else {
            let v = 0n
            for (let i = 0; i < size; i++) v = (v << 8n) | BigInt(bytes[off + 1 + i])
            if (size === 8 && v >= 0x8000000000000000n) v -= 0x10000000000000000n // 8-byte ints are signed
            value = v.toString()
          }
          return mk('integer', 1 + size, { value }, value)
        }
        case 0x2: {
          const size = 1 << lo
          const view = new DataView(bytes.buffer, bytes.byteOffset + off + 1)
          const value = size === 4 ? view.getFloat32(0) : view.getFloat64(0)
          return mk('real', 1 + size, { value: String(value) }, String(value))
        }
        case 0x3: {
          const view = new DataView(bytes.buffer, bytes.byteOffset + off + 1)
          const secs = view.getFloat64(0)
          const iso = new Date(COCOA_EPOCH_MS + secs * 1000).toISOString().replace('.000Z', 'Z')
          return mk('date', 9, { value: iso, note: `${TYPE_NOTES[0x3]} Raw value: ${secs}.` }, iso)
        }
        case 0x4: {
          const preview = bytesToHex(bytes.subarray(off + headLen, off + headLen + Math.min(count, 12)))
          const brief = `${formatSize(count)} data`
          return mk('data', headLen + count, { value: `${brief}${count > 0 ? ` — ${preview}${count > 12 ? ' …' : ''}` : ''}` }, brief)
        }
        case 0x5: {
          const s = latin1(bytes.subarray(off + headLen, off + headLen + count))
          const shownStr = s.length > 60 ? s.slice(0, 60) + '…' : s
          return mk('string (ASCII)', headLen + count, { value: `"${shownStr}"` }, `"${shownStr}"`)
        }
        case 0x6: {
          let s = ''
          for (let i = 0; i < count && i < 300; i++) {
            s += String.fromCharCode((bytes[off + headLen + i * 2] << 8) | bytes[off + headLen + i * 2 + 1])
          }
          const shownStr = s.length > 60 ? s.slice(0, 60) + '…' : s
          return mk('string (UTF-16BE)', headLen + count * 2, { value: `"${shownStr}"` }, `"${shownStr}"`)
        }
        case 0x8: {
          const size = lo + 1
          const value = 'UID ' + readUIntAt(off + 1, size)
          return mk('uid', 1 + size, { value }, value)
        }
        case 0xa:
        case 0xc: {
          const isSet = hi === 0xc
          const total = headLen + count * objectRefSize
          const children: Region[] = []
          const next = new Set(stack).add(index)
          for (let i = 0; i < count && i < 100; i++) {
            if (shown > MAX_OBJECTS_SHOWN) break
            const ref = readUIntAt(off + headLen + i * objectRefSize, objectRefSize)
            const child = parseObject(ref, depth + 1, next)
            child.region.name = `[${i}] ${child.region.name}`
            children.push(child.region)
          }
          if (count > children.length) children.push(region(`… ${count - children.length} more`, off, total, {}))
          return mk(isSet ? 'set' : 'array', total, { value: `${count} item${count === 1 ? '' : 's'}`, children }, `[${count} item${count === 1 ? '' : 's'}]`)
        }
        case 0xd: {
          const total = headLen + count * 2 * objectRefSize
          const children: Region[] = []
          const next = new Set(stack).add(index)
          for (let i = 0; i < count && i < 100; i++) {
            if (shown > MAX_OBJECTS_SHOWN) break
            const keyRef = readUIntAt(off + headLen + i * objectRefSize, objectRefSize)
            const valRef = readUIntAt(off + headLen + (count + i) * objectRefSize, objectRefSize)
            const key = parseObject(keyRef, depth + 1, next)
            const val = parseObject(valRef, depth + 1, next)
            val.region.name = key.brief.replace(/^"|"$/g, '') || `key ${i}`
            children.push(val.region)
          }
          if (count > children.length) children.push(region(`… ${count - children.length} more`, off, total, {}))
          return mk('dict', total, { value: `${count} pair${count === 1 ? '' : 's'}`, children }, `{${count} pair${count === 1 ? '' : 's'}}`)
        }
        default:
          return mk(`unknown marker 0x${marker.toString(16)}`, 1, { flag: 'warn' }, '?')
      }
    }

    try {
      const top = parseObject(topObject, 0, new Set())
      top.region.name = `root ${top.region.name}`
      regions.push(
        region('Object table', 8, offsetTableOffset - 8, {
          value: `${numObjects} objects`,
          note: 'Objects are stored once and referenced by index — repeated strings/values are deduplicated.',
          children: [top.region],
        }),
      )
      summary.push(`root: ${top.brief}, ${numObjects} objects`)
      if (shown >= MAX_OBJECTS_SHOWN) warnings.push(`large plist — expanded only the first ${MAX_OBJECTS_SHOWN} objects`)
    } catch (e) {
      warnings.push(`object graph truncated: ${e instanceof Error ? e.message : String(e)}`)
    }

    regions.push(
      region('Offset table', offsetTableOffset, numObjects * offsetIntSize, {
        value: `${numObjects} × ${offsetIntSize} B`,
        note: 'Maps object index → file offset. This indirection is what makes random access possible.',
      }),
    )
    regions.push(trailerRegion)

    summary.push('Convert on macOS: plutil -convert xml1 file.plist (and binary1 to go back)')
    return { format: 'Binary property list (Apple)', summary, regions, warnings }
  },
}
