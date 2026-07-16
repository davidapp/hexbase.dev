import { ByteReader, formatSize, hex, latin1 } from '../bytes'
import { region, type ParseResult, type Region } from '../region'
import { startsWith, type FormatDef } from './def'

const MARKERS: Record<number, [string, string]> = {
  0xd8: ['SOI', 'Start of image'],
  0xd9: ['EOI', 'End of image'],
  0xc0: ['SOF0', 'Start of frame — baseline DCT (the common sequential JPEG)'],
  0xc1: ['SOF1', 'Start of frame — extended sequential DCT'],
  0xc2: ['SOF2', 'Start of frame — progressive DCT (renders in passes)'],
  0xc3: ['SOF3', 'Start of frame — lossless'],
  0xc4: ['DHT', 'Define Huffman table(s)'],
  0xc5: ['SOF5', 'Start of frame — differential sequential'],
  0xc6: ['SOF6', 'Start of frame — differential progressive'],
  0xc7: ['SOF7', 'Start of frame — differential lossless'],
  0xc9: ['SOF9', 'Start of frame — arithmetic coded sequential'],
  0xca: ['SOF10', 'Start of frame — arithmetic coded progressive'],
  0xcc: ['DAC', 'Define arithmetic coding conditioning'],
  0xdb: ['DQT', 'Define quantization table(s) — these control the quality/size trade-off'],
  0xdd: ['DRI', 'Define restart interval'],
  0xda: ['SOS', 'Start of scan — entropy-coded image data follows'],
  0xfe: ['COM', 'Comment'],
  0xe0: ['APP0', 'Application segment 0 — usually JFIF'],
  0xe1: ['APP1', 'Application segment 1 — usually EXIF or XMP'],
  0xe2: ['APP2', 'Application segment 2 — often an ICC color profile'],
  0xe3: ['APP3', 'Application segment 3'],
  0xe4: ['APP4', 'Application segment 4'],
  0xe5: ['APP5', 'Application segment 5'],
  0xe6: ['APP6', 'Application segment 6'],
  0xe7: ['APP7', 'Application segment 7'],
  0xe8: ['APP8', 'Application segment 8'],
  0xe9: ['APP9', 'Application segment 9'],
  0xea: ['APP10', 'Application segment 10'],
  0xeb: ['APP11', 'Application segment 11'],
  0xec: ['APP12', 'Application segment 12 — often "Ducky" (Photoshop Save for Web)'],
  0xed: ['APP13', 'Application segment 13 — often Photoshop IRB/IPTC'],
  0xee: ['APP14', 'Application segment 14 — often Adobe color transform info'],
  0xef: ['APP15', 'Application segment 15'],
}

export const jpeg: FormatDef = {
  id: 'jpeg',
  name: 'JPEG image',
  mime: 'image/jpeg',
  detect: (b) => startsWith(b, [0xff, 0xd8, 0xff]),
  parse(bytes): ParseResult {
    const regions: Region[] = []
    const warnings: string[] = []
    const summary: string[] = []
    let dims = ''
    let progressive = false
    let hasExif = false
    let hasIcc = false

    regions.push(region('SOI marker', 0, 2, { value: 'FF D8', note: 'Start of image. Every JPEG begins with these two bytes.', flag: 'ok' }))

    const r = new ByteReader(bytes, 2)
    let segments = 1
    try {
      scan: while (!r.eof() && segments < 5000) {
        const start = r.pos
        let b = r.u8()
        if (b !== 0xff) {
          warnings.push(`expected marker byte FF at offset 0x${hex(start, 4)}, found ${hex(b)} — stream may be corrupt`)
          break
        }
        let id = r.u8()
        while (id === 0xff) id = r.u8() // fill bytes are legal
        const [name, note] = MARKERS[id] ?? [`0x${hex(id)}`, 'Unknown marker']
        segments++

        if (id === 0xd9) {
          regions.push(region('EOI marker', start, 2, { value: 'FF D9', note: 'End of image.', flag: 'ok' }))
          break
        }
        if ((id >= 0xd0 && id <= 0xd7) || id === 0x01) {
          regions.push(region(`${name}`, start, 2, { value: `FF ${hex(id)}`, note }))
          continue
        }

        const len = r.u16be()
        const dataStart = r.pos
        const dataLen = len - 2
        const children: Region[] = [
          region('Marker', start, 2, { value: `FF ${hex(id)}` }),
          region('Length', start + 2, 2, { value: String(len), note: 'Segment length including these two bytes but not the marker.' }),
        ]
        const sub = new ByteReader(bytes, dataStart)

        if ((id >= 0xc0 && id <= 0xcf) && id !== 0xc4 && id !== 0xc8 && id !== 0xcc && dataLen >= 6) {
          const precision = sub.u8()
          const h = sub.u16be()
          const w = sub.u16be()
          const comps = sub.u8()
          dims = `${w} × ${h}`
          if (id === 0xc2 || id === 0xc6 || id === 0xca) progressive = true
          children.push(
            region('Precision', dataStart, 1, { value: `${precision} bits/sample` }),
            region('Height', dataStart + 1, 2, { value: `${h} px` }),
            region('Width', dataStart + 3, 2, { value: `${w} px` }),
            region('Components', dataStart + 5, 1, { value: comps === 3 ? '3 — YCbCr (color)' : comps === 1 ? '1 — grayscale' : String(comps) }),
          )
        } else if (id === 0xe0 && dataLen >= 5) {
          const ident = latin1(bytes.subarray(dataStart, dataStart + 5))
          if (ident === 'JFIF\0' && dataLen >= 14) {
            const maj = bytes[dataStart + 5]
            const min = bytes[dataStart + 6]
            const units = bytes[dataStart + 7]
            const xd = (bytes[dataStart + 8] << 8) | bytes[dataStart + 9]
            const yd = (bytes[dataStart + 10] << 8) | bytes[dataStart + 11]
            const unitName = units === 1 ? 'DPI' : units === 2 ? 'dots/cm' : '(aspect ratio only)'
            children.push(
              region('Identifier', dataStart, 5, { value: 'JFIF\\0' }),
              region('Version', dataStart + 5, 2, { value: `${maj}.${String(min).padStart(2, '0')}` }),
              region('Density', dataStart + 7, 5, { value: `${xd} × ${yd} ${unitName}` }),
            )
          }
        } else if (id === 0xe1 && dataLen >= 6) {
          const ident6 = latin1(bytes.subarray(dataStart, dataStart + 6))
          if (ident6 === 'Exif\0\0') {
            hasExif = true
            const endian = latin1(bytes.subarray(dataStart + 6, dataStart + 8))
            children.push(
              region('Identifier', dataStart, 6, { value: 'Exif\\0\\0' }),
              region('TIFF header', dataStart + 6, Math.min(8, dataLen - 6), {
                value: endian === 'II' ? '"II" — little-endian (Intel)' : endian === 'MM' ? '"MM" — big-endian (Motorola)' : endian,
                note: 'EXIF embeds a little TIFF file: byte-order mark, magic 42, then IFD offsets.',
              }),
            )
          } else if (latin1(bytes.subarray(dataStart, dataStart + Math.min(28, dataLen))).startsWith('http://ns.adobe.com/xap/')) {
            children.push(region('Identifier', dataStart, 28, { value: 'XMP metadata (RDF/XML)' }))
          }
        } else if (id === 0xe2 && dataLen >= 12 && latin1(bytes.subarray(dataStart, dataStart + 12)) === 'ICC_PROFILE\0') {
          hasIcc = true
          children.push(region('Identifier', dataStart, 12, { value: 'ICC_PROFILE\\0' }))
        } else if (id === 0xfe && dataLen > 0) {
          children.push(region('Comment text', dataStart, dataLen, { value: latin1(bytes.subarray(dataStart, dataStart + Math.min(dataLen, 80))) }))
        } else if (id === 0xdb && dataLen > 0) {
          const tables = Math.floor(dataLen / 65)
          children.push(region('Table data', dataStart, dataLen, { value: `${tables >= 1 ? tables : 1} quantization table(s)` }))
        }

        regions.push(
          region(name, start, 4 + dataLen, {
            value: formatSize(dataLen),
            note,
            children,
          }),
        )

        if (id === 0xda) {
          // Entropy-coded data runs until EOI; find the last FF D9.
          let end = -1
          for (let i = bytes.length - 2; i > dataStart; i--) {
            if (bytes[i] === 0xff && bytes[i + 1] === 0xd9) {
              end = i
              break
            }
          }
          const scanStart = dataStart + dataLen
          if (end === -1) {
            regions.push(region('Entropy-coded data', scanStart, bytes.length - scanStart, { value: formatSize(bytes.length - scanStart), note: 'Huffman-coded image data (no EOI found — truncated?).', flag: 'warn' }))
            warnings.push('no EOI (FF D9) marker found')
            break scan
          }
          regions.push(
            region('Entropy-coded data', scanStart, end - scanStart, {
              value: formatSize(end - scanStart),
              note: 'The Huffman-coded pixel data. Any literal FF byte inside is escaped as FF 00 so it can never look like a marker.',
            }),
          )
          regions.push(region('EOI marker', end, 2, { value: 'FF D9', note: 'End of image.', flag: 'ok' }))
          if (end + 2 < bytes.length) {
            regions.push(
              region('Trailing data', end + 2, bytes.length - end - 2, {
                value: formatSize(bytes.length - end - 2),
                note: 'Bytes after EOI — often nothing, sometimes an embedded thumbnail, sometimes a hidden payload.',
                flag: 'warn',
              }),
            )
          }
          break scan
        }
        r.seek(dataStart + dataLen)
      }
    } catch (e) {
      warnings.push(`file truncated: ${e instanceof Error ? e.message : String(e)}`)
    }

    if (dims) summary.push(`${dims} px, ${progressive ? 'progressive' : 'baseline'} DCT`)
    summary.push(`${segments} segments${hasExif ? ', EXIF metadata' : ''}${hasIcc ? ', ICC profile' : ''}`)

    return { format: 'JPEG image', summary, regions, warnings }
  },
}
