import { ByteReader, formatSize, latin1 } from '../bytes'
import { region, type ParseResult, type Region } from '../region'
import type { FormatDef } from './def'

const BOX_NOTES: Record<string, string> = {
  ftyp: 'File type — brand identifies the flavor (isom, mp42, avif, heic…).',
  moov: 'Movie metadata container: track list, timescale, duration. Needed before playback can start.',
  mvhd: 'Movie header: global timescale + duration.',
  trak: 'One track (video, audio, subtitles…).',
  tkhd: 'Track header: id, duration, dimensions.',
  mdia: 'Track media information container.',
  hdlr: 'Handler: declares the track type (vide = video, soun = audio, text…).',
  minf: 'Media information container.',
  stbl: 'Sample table: where every frame lives and how to time it.',
  stsd: 'Sample descriptions (codec configuration, e.g. avc1/hvc1/mp4a).',
  mdat: 'Media data — the actual encoded frames. Opaque without the moov index.',
  free: 'Free space (padding, often left by editors).',
  skip: 'Free space.',
  wide: 'QuickTime 64-bit size placeholder.',
  moof: 'Movie fragment (streaming/DASH files interleave moof+mdat).',
  mfra: 'Fragment random-access index.',
  udta: 'User data (often ©-prefixed metadata).',
  meta: 'Metadata container (iTunes tags, HEIF image properties…).',
  uuid: 'Vendor-specific extension box.',
  sidx: 'Segment index (DASH streaming).',
  styp: 'Segment type (DASH streaming).',
}

const CONTAINERS = new Set(['moov', 'trak', 'mdia', 'minf', 'stbl', 'edts', 'mvex', 'moof', 'traf', 'dinf', 'udta'])

export const mp4: FormatDef = {
  id: 'mp4',
  name: 'MP4 / ISO media',
  mime: 'video/mp4',
  detect: (b) => b.length >= 12 && latin1(b.subarray(4, 8)) === 'ftyp',
  parse(bytes): ParseResult {
    const warnings: string[] = []
    const summary: string[] = []
    const handlers: string[] = []
    let brand = ''
    let durationText = ''

    const walk = (start: number, end: number, depth: number): Region[] => {
      const out: Region[] = []
      let pos = start
      let guard = 0
      while (pos + 8 <= end && guard++ < 500) {
        const r = new ByteReader(bytes, pos)
        let size: number
        try {
          size = r.u32be()
        } catch {
          break
        }
        const type = r.ascii(4)
        let headerLen = 8
        let boxEnd: number
        if (size === 1) {
          const big = r.u64be()
          headerLen = 16
          boxEnd = pos + Number(big)
        } else if (size === 0) {
          boxEnd = end // box extends to end of file
        } else {
          boxEnd = pos + size
        }
        if (boxEnd > end || boxEnd <= pos) {
          warnings.push(`box "${type}" at offset ${pos} has an invalid size — stopping`)
          break
        }

        let value = formatSize(boxEnd - pos)
        let children: Region[] | undefined

        if (type === 'ftyp') {
          const major = r.ascii(4)
          r.skip(4)
          const brands: string[] = []
          while (r.pos + 4 <= boxEnd) brands.push(r.ascii(4).trim())
          brand = major.trim()
          value = `${brand} (+ ${brands.join(', ')})`
          if (brand === 'avif' || brands.includes('avif')) summary.push('AVIF image (ISO-BMFF container)')
          else if (brand.startsWith('hei') || brand === 'mif1') summary.push('HEIF/HEIC image (ISO-BMFF container)')
        } else if (type === 'mvhd' && boxEnd - pos >= 20) {
          const version = r.u8()
          r.skip(3)
          if (version === 1) {
            r.skip(16)
            const timescale = r.u32be()
            const duration = Number(r.u64be())
            durationText = formatDuration(duration / timescale)
          } else {
            r.skip(8)
            const timescale = r.u32be()
            const duration = r.u32be()
            durationText = formatDuration(duration / timescale)
          }
          value = durationText
        } else if (type === 'hdlr' && boxEnd - pos >= 24) {
          r.skip(8)
          const handler = r.ascii(4)
          handlers.push(handler)
          value = `"${handler}"${handler === 'vide' ? ' — video' : handler === 'soun' ? ' — audio' : handler === 'text' || handler === 'sbtl' ? ' — subtitles' : ''}`
        } else if (type === 'meta') {
          // meta is a "full box": 4 bytes of version/flags before its children
          children = walk(pos + headerLen + 4, boxEnd, depth + 1)
        }

        if (CONTAINERS.has(type) && depth < 6) {
          children = walk(pos + headerLen, boxEnd, depth + 1)
        }

        out.push(
          region(`${type}`, pos, boxEnd - pos, {
            value,
            note: BOX_NOTES[type],
            children: children && children.length ? children : undefined,
          }),
        )
        pos = boxEnd
      }
      return out
    }

    const regions = walk(0, bytes.length, 0)

    if (brand) summary.unshift(`brand ${brand}${durationText ? `, duration ${durationText}` : ''}`)
    if (handlers.length) summary.push(`tracks: ${handlers.map((h) => (h === 'vide' ? 'video' : h === 'soun' ? 'audio' : h)).join(', ')}`)
    summary.push('Structure: a tree of length-prefixed "boxes" (a.k.a. atoms), a design inherited from QuickTime (1991)')

    return { format: 'MP4 / ISO Base Media', summary, regions, warnings }

    function formatDuration(secs: number): string {
      if (!Number.isFinite(secs)) return ''
      if (secs >= 3600) return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m ${Math.round(secs % 60)}s`
      if (secs >= 60) return `${Math.floor(secs / 60)}m ${Math.round(secs % 60)}s`
      return `${secs.toFixed(2)}s`
    }
  },
}
