import { ByteReader, formatSize, latin1 } from '../bytes'
import { region, type ParseResult, type Region } from '../region'
import { startsWith, sigOf, type FormatDef } from './def'

const WAV_FORMATS: Record<number, string> = {
  1: 'PCM (uncompressed)',
  3: 'IEEE float',
  6: 'A-law',
  7: 'µ-law',
  0x11: 'IMA ADPCM',
  0x55: 'MP3',
  0xfffe: 'Extensible',
}

export const riff: FormatDef = {
  id: 'riff',
  name: 'RIFF container',
  detect: (b) => startsWith(b, sigOf('RIFF')),
  parse(bytes): ParseResult {
    const regions: Region[] = []
    const warnings: string[] = []
    const summary: string[] = []

    const r = new ByteReader(bytes, 0)
    try {
      r.skip(4)
      const riffSize = r.u32le()
      const form = r.ascii(4)
      const formName = form === 'WAVE' ? 'WAV audio' : form === 'AVI ' ? 'AVI video' : form === 'WEBP' ? 'WebP image' : `RIFF (${form})`

      regions.push(
        region('RIFF header', 0, 12, {
          value: `${form}, ${formSize(riffSize)}`,
          note: 'Resource Interchange File Format (Microsoft/IBM, 1991). A little-endian chunk container — WAV, AVI and WebP all live inside it.',
          children: [
            region('Magic', 0, 4, { value: '"RIFF"', flag: 'ok' }),
            region('Size', 4, 4, { value: formSize(riffSize), note: 'Everything after this field (file size − 8).' }),
            region('Form type', 8, 4, { value: `"${form}"` }),
          ],
        }),
      )

      let sampleRate = 0
      let byteRate = 0
      let channels = 0
      let bits = 0
      let fmtName = ''
      let dataSize = 0
      let count = 0

      while (r.remaining() >= 8 && count++ < 1000) {
        const start = r.pos
        const id = r.ascii(4)
        const size = r.u32le()
        const dataStart = r.pos
        const children: Region[] = []
        let value = formSize(size)
        let note: string | undefined

        if (form === 'WAVE' && id === 'fmt ' && size >= 16) {
          const fmt = r.u16le()
          channels = r.u16le()
          sampleRate = r.u32le()
          byteRate = r.u32le()
          const blockAlign = r.u16le()
          bits = r.u16le()
          fmtName = WAV_FORMATS[fmt] ?? `format ${fmt}`
          value = `${fmtName}, ${channels} ch, ${sampleRate} Hz, ${bits}-bit`
          note = 'The decoder contract: how to interpret the bytes in the data chunk.'
          children.push(
            region('Audio format', dataStart, 2, { value: `${fmt} — ${fmtName}` }),
            region('Channels', dataStart + 2, 2, { value: String(channels) }),
            region('Sample rate', dataStart + 4, 4, { value: `${sampleRate} Hz` }),
            region('Byte rate', dataStart + 8, 4, { value: `${byteRate} B/s`, note: 'sampleRate × channels × bits/8 — lets players compute duration instantly.' }),
            region('Block align', dataStart + 12, 2, { value: String(blockAlign) }),
            region('Bits per sample', dataStart + 14, 2, { value: String(bits) }),
          )
          r.seek(dataStart)
        } else if (form === 'WAVE' && id === 'data') {
          dataSize = size
          note = 'The raw samples. For PCM: interleaved channels, each sample little-endian.'
        } else if (id === 'LIST' && size >= 4) {
          const listType = latin1(bytes.subarray(dataStart, dataStart + 4))
          value = `${listType}, ${formSize(size)}`
          note = listType === 'INFO' ? 'Metadata: artist (IART), title (INAM), software (ISFT)…' : undefined
        } else if (form === 'WEBP' && (id === 'VP8 ' || id === 'VP8L' || id === 'VP8X')) {
          note = id === 'VP8 ' ? 'Lossy WebP bitstream.' : id === 'VP8L' ? 'Lossless WebP bitstream.' : 'Extended WebP: feature flags + canvas size (alpha, animation, EXIF…).'
          if (id === 'VP8X' && size >= 10) {
            const w = 1 + (bytes[dataStart + 4] | (bytes[dataStart + 5] << 8) | (bytes[dataStart + 6] << 16))
            const h = 1 + (bytes[dataStart + 7] | (bytes[dataStart + 8] << 8) | (bytes[dataStart + 9] << 16))
            value = `${w} × ${h} px`
            summary.push(`${w} × ${h} px WebP (extended)`)
          }
        }

        regions.push(region(`${id} chunk`, start, 8 + size, { value, note, children: children.length ? children : undefined }))
        r.seek(dataStart + size + (size % 2)) // chunks are word-aligned
      }

      if (form === 'WAVE' && byteRate > 0 && dataSize > 0) {
        const secs = dataSize / byteRate
        summary.push(`${fmtName}, ${channels} channel${channels === 1 ? '' : 's'}, ${sampleRate} Hz, ${bits}-bit`)
        summary.push(`duration ≈ ${secs >= 60 ? `${Math.floor(secs / 60)}m ${Math.round(secs % 60)}s` : `${secs.toFixed(2)}s`}`)
      }

      return { format: formName, summary, regions, warnings }
    } catch (e) {
      warnings.push(`file truncated: ${e instanceof Error ? e.message : String(e)}`)
      return { format: 'RIFF container', summary, regions, warnings }
    }

    function formSize(n: number) {
      return formatSize(n)
    }
  },
}
