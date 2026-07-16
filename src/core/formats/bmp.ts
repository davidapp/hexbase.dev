import { ByteReader, formatSize } from '../bytes'
import { region, type ParseResult, type Region } from '../region'
import { startsWith, type FormatDef } from './def'

const COMPRESSION: Record<number, string> = {
  0: 'BI_RGB (none)',
  1: 'BI_RLE8',
  2: 'BI_RLE4',
  3: 'BI_BITFIELDS',
  4: 'BI_JPEG',
  5: 'BI_PNG',
}

const DIB_NAMES: Record<number, string> = {
  12: 'BITMAPCOREHEADER (OS/2, 1987)',
  40: 'BITMAPINFOHEADER (Windows 3.0, 1990)',
  108: 'BITMAPV4HEADER (Windows 95)',
  124: 'BITMAPV5HEADER (Windows 98 — adds ICC color profiles)',
}

export const bmp: FormatDef = {
  id: 'bmp',
  name: 'BMP image',
  mime: 'image/bmp',
  detect: (b) => startsWith(b, [0x42, 0x4d]) && b.length >= 26,
  parse(bytes): ParseResult {
    const regions: Region[] = []
    const warnings: string[] = []
    const summary: string[] = []
    try {
      const r = new ByteReader(bytes, 2)
      const fileSize = r.u32le()
      r.skip(4)
      const dataOffset = r.u32le()
      regions.push(
        region('File header', 0, 14, {
          value: `"BM", ${formatSize(fileSize)}`,
          children: [
            region('Magic', 0, 2, { value: '"BM"', flag: 'ok' }),
            region('File size', 2, 4, { value: formatSize(fileSize), flag: fileSize === bytes.length ? 'ok' : 'warn' }),
            region('Reserved', 6, 4, {}),
            region('Pixel data offset', 10, 4, { value: '0x' + dataOffset.toString(16).toUpperCase() }),
          ],
        }),
      )

      const dibSize = r.u32le()
      const core = dibSize === 12
      const width = core ? r.u16le() : r.view.getInt32(r.pos, true)
      if (!core) r.skip(4)
      const heightRaw = core ? r.u16le() : r.view.getInt32(r.pos, true)
      if (!core) r.skip(4)
      const planes = r.u16le()
      const bpp = r.u16le()
      const compression = core ? 0 : r.u32le()
      const topDown = !core && heightRaw < 0
      const height = Math.abs(heightRaw)

      const children: Region[] = [
        region('DIB header size', 14, 4, { value: `${dibSize} — ${DIB_NAMES[dibSize] ?? 'unknown variant'}`, note: 'BMP is versioned by the size of this header.' }),
        region('Width', 18, core ? 2 : 4, { value: `${width} px` }),
        region('Height', 18 + (core ? 2 : 4), core ? 2 : 4, {
          value: `${height} px${topDown ? ' (negative = top-down)' : ''}`,
          note: core ? undefined : 'Positive height means rows are stored bottom-up — the first row in the file is the bottom of the image.',
        }),
        region('Planes', core ? 22 : 26, 2, { value: String(planes) }),
        region('Bits per pixel', core ? 24 : 28, 2, { value: String(bpp) }),
      ]
      if (!core) {
        children.push(region('Compression', 30, 4, { value: `${compression} — ${COMPRESSION[compression] ?? 'unknown'}` }))
      }
      regions.push(region('DIB header', 14, dibSize, { value: `${width} × ${height}, ${bpp} bpp`, children }))

      if (dataOffset > 14 + dibSize) {
        regions.push(region('Color table / masks', 14 + dibSize, dataOffset - 14 - dibSize, { note: 'Palette entries (BGRA order) or bitfield masks.' }))
      }
      const rowSize = Math.floor((bpp * width + 31) / 32) * 4
      regions.push(
        region('Pixel data', dataOffset, Math.max(0, Math.min(bytes.length, dataOffset + rowSize * height) - dataOffset), {
          value: formatSize(rowSize * height),
          note: `Rows are padded to 4-byte boundaries (row stride ${rowSize} B). Colors are stored as BGR, not RGB — a 1990 VGA hardware convention that never went away.`,
        }),
      )

      summary.push(`${width} × ${height} px, ${bpp} bpp, ${COMPRESSION[compression] ?? '?'}${topDown ? ', top-down' : ', bottom-up'}`)
      summary.push(DIB_NAMES[dibSize] ?? `DIB header ${dibSize} bytes`)
    } catch (e) {
      warnings.push(`file truncated: ${e instanceof Error ? e.message : String(e)}`)
    }
    return { format: 'BMP image', summary, regions, warnings }
  },
}
