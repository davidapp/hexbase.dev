import { ByteReader, formatSize, latin1 } from '../bytes'
import { region, type ParseResult, type Region } from '../region'
import { startsWith, sigOf, type FormatDef } from './def'

export const gif: FormatDef = {
  id: 'gif',
  name: 'GIF image',
  mime: 'image/gif',
  detect: (b) => startsWith(b, sigOf('GIF87a')) || startsWith(b, sigOf('GIF89a')),
  parse(bytes): ParseResult {
    const regions: Region[] = []
    const warnings: string[] = []
    const summary: string[] = []
    const version = latin1(bytes.subarray(3, 6))

    regions.push(
      region('Header', 0, 6, {
        value: `GIF${version}`,
        note: '"GIF" plus the spec version: 87a (1987) or 89a (1989, adds animation + transparency).',
        flag: 'ok',
      }),
    )

    const r = new ByteReader(bytes, 6)
    let frames = 0
    let loops: number | null = null
    let transparent = false

    const skipSubBlocks = (): number => {
      // GIF stores variable data as sub-blocks: [size u8][data…] repeated, terminated by size 0.
      let total = 0
      for (;;) {
        const size = r.u8()
        total += 1
        if (size === 0) return total
        r.skip(size)
        total += size
      }
    }

    try {
      const w = r.u16le()
      const h = r.u16le()
      const packed = r.u8()
      const bg = r.u8()
      const aspect = r.u8()
      const hasGct = (packed & 0x80) !== 0
      const gctSize = 2 << (packed & 0x07)
      regions.push(
        region('Logical Screen Descriptor', 6, 7, {
          value: `${w} × ${h}`,
          children: [
            region('Width', 6, 2, { value: `${w} px`, note: 'Little-endian u16 — GIF is a little-endian format.' }),
            region('Height', 8, 2, { value: `${h} px` }),
            region('Packed flags', 10, 1, {
              value: `GCT=${hasGct ? 'yes' : 'no'}${hasGct ? `, ${gctSize} colors` : ''}`,
              note: 'Bit 7: global color table present. Bits 0-2: table size as 2^(n+1) entries.',
            }),
            region('Background color index', 11, 1, { value: String(bg) }),
            region('Pixel aspect ratio', 12, 1, { value: aspect === 0 ? '0 — square' : String(aspect) }),
          ],
        }),
      )
      summary.push(`${w} × ${h} px, GIF${version}`)

      if (hasGct) {
        regions.push(
          region('Global Color Table', r.pos, gctSize * 3, {
            value: `${gctSize} × RGB`,
            note: 'Every pixel in a GIF is an index into a color table — that is why GIFs max out at 256 colors per frame.',
          }),
        )
        r.skip(gctSize * 3)
      }

      let blocks = 0
      loop: while (!r.eof() && blocks++ < 100000) {
        const start = r.pos
        const introducer = r.u8()
        switch (introducer) {
          case 0x21: {
            const label = r.u8()
            if (label === 0xf9) {
              const size = r.u8()
              const flagsPos = r.pos
              const flags = r.u8()
              const delay = r.u16le()
              const tIndex = r.u8()
              r.u8() // terminator
              const hasT = (flags & 1) !== 0
              if (hasT) transparent = true
              regions.push(
                region('Graphic Control Extension', start, r.pos - start, {
                  value: `delay ${delay * 10} ms`,
                  note: 'Controls the next frame: delay time (in 1/100 s), disposal method, transparency.',
                  children: [
                    region('Flags', flagsPos, 1, { value: `disposal=${(flags >> 2) & 7}, transparency=${hasT ? 'yes' : 'no'}` }),
                    region('Delay', flagsPos + 1, 2, { value: `${delay} × 1/100 s` }),
                    region('Transparent index', flagsPos + 3, 1, { value: hasT ? String(tIndex) : '(unused)' }),
                  ],
                }),
              )
            } else if (label === 0xff) {
              const size = r.u8()
              const ident = r.ascii(Math.min(size, 11))
              if (size > 11) r.skip(size - 11)
              if (ident.startsWith('NETSCAPE') || ident.startsWith('ANIMEXTS')) {
                const sub = r.u8()
                if (sub >= 3) {
                  r.u8()
                  loops = r.u16le()
                  if (sub > 3) r.skip(sub - 3)
                } else {
                  r.skip(sub)
                }
                r.u8() // terminator (0)
                regions.push(
                  region('Application Extension', start, r.pos - start, {
                    value: `${ident.replace(/\0.*/, '')} — loop ${loops === 0 ? 'forever' : `${loops}×`}`,
                    note: 'The NETSCAPE2.0 extension is what makes a GIF loop. It was invented for Netscape Navigator 2.0 and never standardized — everyone just copied it.',
                  }),
                )
              } else {
                skipSubBlocks()
                regions.push(region('Application Extension', start, r.pos - start, { value: ident.replace(/\0.*$/, '') }))
              }
            } else if (label === 0xfe) {
              const commentStart = r.pos
              const size0 = bytes[r.pos]
              skipSubBlocks()
              const preview = size0 ? latin1(bytes.subarray(commentStart + 1, commentStart + 1 + Math.min(size0, 60))) : ''
              regions.push(region('Comment Extension', start, r.pos - start, { value: preview }))
            } else {
              skipSubBlocks()
              regions.push(region('Extension 0x' + label.toString(16).toUpperCase(), start, r.pos - start, {}))
            }
            break
          }
          case 0x2c: {
            frames++
            const left = r.u16le()
            const top = r.u16le()
            const fw = r.u16le()
            const fh = r.u16le()
            const fpacked = r.u8()
            const hasLct = (fpacked & 0x80) !== 0
            const interlaced = (fpacked & 0x40) !== 0
            const lctSize = 2 << (fpacked & 0x07)
            if (hasLct) r.skip(lctSize * 3)
            r.u8() // LZW minimum code size
            skipSubBlocks()
            if (frames <= 50) {
              regions.push(
                region(`Image Descriptor (frame ${frames})`, start, r.pos - start, {
                  value: `${fw} × ${fh} @ ${left},${top}${interlaced ? ', interlaced' : ''}`,
                  note: 'A frame: position + size, optional local color table, then LZW-compressed pixel indices in sub-blocks.',
                }),
              )
            }
            break
          }
          case 0x3b:
            regions.push(region('Trailer', start, 1, { value: '3B', note: 'End of GIF stream.', flag: 'ok' }))
            break loop
          default:
            warnings.push(`unknown block introducer 0x${introducer.toString(16)} at offset ${start}`)
            break loop
        }
      }
    } catch (e) {
      warnings.push(`file truncated: ${e instanceof Error ? e.message : String(e)}`)
    }

    if (frames > 50) summary.push(`(showing first 50 of ${frames} frame descriptors)`)
    summary.push(`${frames} frame${frames === 1 ? '' : 's'}${loops !== null ? `, loops ${loops === 0 ? 'forever' : loops + '×'}` : ''}${transparent ? ', has transparency' : ''}`)

    return { format: 'GIF image', summary, regions, warnings }
  },
}
