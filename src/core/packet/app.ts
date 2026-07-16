import { latin1 } from '../bytes'
import { region, type Region } from '../region'
import type { LayerFn, LayerResult } from './net'

export const httpLayer: LayerFn = (bytes, off, ctx): LayerResult => {
  const end = Math.min(ctx.declaredEnd ?? bytes.length, bytes.length)
  const text = latin1(bytes.subarray(off, end))
  const headerEnd = text.indexOf('\r\n\r\n')
  const headText = headerEnd === -1 ? text : text.slice(0, headerEnd)
  const lines = headText.split('\r\n')
  const children: Region[] = []
  let pos = off
  for (let i = 0; i < lines.length && i < 40; i++) {
    const line = lines[i]
    const len = line.length + 2
    if (i === 0) {
      children.push(
        region('Start line', pos, Math.min(line.length, end - pos), {
          value: line,
          note: line.startsWith('HTTP/') ? 'Status line: version, status code, reason phrase.' : 'Request line: method, target, version. HTTP/1.x is plain ASCII — you can speak it by hand over netcat.',
        }),
      )
      ctx.summary.push(`HTTP: ${line}`)
    } else if (line) {
      const colon = line.indexOf(':')
      children.push(region(colon > 0 ? line.slice(0, colon) : 'Header', pos, Math.min(line.length, end - pos), { value: colon > 0 ? line.slice(colon + 1).trim() : line }))
    }
    pos += len
  }
  if (headerEnd !== -1 && off + headerEnd + 4 < end) {
    children.push(region('Body', off + headerEnd + 4, end - off - headerEnd - 4, { note: 'Entity body — length governed by Content-Length or chunked transfer coding.' }))
  }
  return {
    region: region('HTTP/1.x', off, end - off, {
      value: lines[0]?.slice(0, 60),
      note: 'Layer 7. Human-readable request/response protocol, CRLF line endings, header:value pairs.',
      children,
    }),
  }
}

const NTP_MODES: Record<number, string> = {
  1: 'symmetric active',
  2: 'symmetric passive',
  3: 'client',
  4: 'server',
  5: 'broadcast',
  6: 'control message',
}

const NTP_UNIX_OFFSET = 2208988800

function ntpTime(bytes: Uint8Array, off: number): string {
  const secs = ((bytes[off] << 24) | (bytes[off + 1] << 16) | (bytes[off + 2] << 8) | bytes[off + 3]) >>> 0
  if (secs === 0) return '0 (unset)'
  const frac = (((bytes[off + 4] << 24) | (bytes[off + 5] << 16) | (bytes[off + 6] << 8) | bytes[off + 7]) >>> 0) / 2 ** 32
  const ms = (secs - NTP_UNIX_OFFSET + frac) * 1000
  return new Date(ms).toISOString()
}

export const ntpLayer: LayerFn = (bytes, off, ctx): LayerResult => {
  const b0 = bytes[off]
  const li = b0 >> 6
  const vn = (b0 >> 3) & 7
  const mode = b0 & 7
  const stratum = bytes[off + 1]
  ctx.summary.push(`NTPv${vn} ${NTP_MODES[mode] ?? `mode ${mode}`}${stratum ? `, stratum ${stratum}` : ''}`)
  return {
    region: region('NTP', off, Math.min(48, bytes.length - off), {
      value: `v${vn}, ${NTP_MODES[mode] ?? `mode ${mode}`}`,
      note: 'Network Time Protocol. Timestamps are 64-bit: 32 bits of seconds since 1900-01-01 + 32 bits of fraction (~233 ps resolution).',
      children: [
        region('LI / VN / Mode', off, 1, { value: `leap=${li}, version=${vn}, mode=${mode} (${NTP_MODES[mode] ?? '?'})` }),
        region('Stratum', off + 1, 1, { value: stratum === 0 ? '0 (unspecified)' : `${stratum}${stratum === 1 ? ' — primary (atomic clock/GPS)' : ''}`, note: 'Distance from the reference clock: 1 = has one attached, 2 = syncs from a stratum 1, …' }),
        region('Poll / Precision', off + 2, 2, {}),
        region('Root delay / dispersion', off + 4, 8, { note: '16.16 fixed-point seconds to/at the reference clock.' }),
        region('Reference ID', off + 12, 4, { value: stratum === 1 ? `"${latin1(bytes.subarray(off + 12, off + 16)).replace(/\0+$/, '')}"` : undefined }),
        region('Reference timestamp', off + 16, 8, { value: ntpTime(bytes, off + 16) }),
        region('Origin timestamp', off + 24, 8, { value: ntpTime(bytes, off + 24) }),
        region('Receive timestamp', off + 32, 8, { value: ntpTime(bytes, off + 32) }),
        region('Transmit timestamp', off + 40, 8, { value: ntpTime(bytes, off + 40), note: 'The four timestamps let the client solve for both offset and round-trip delay.' }),
      ],
    }),
  }
}

export const payloadLayer: LayerFn = (bytes, off, ctx): LayerResult => {
  const end = Math.min(ctx.declaredEnd ?? bytes.length, bytes.length)
  const len = end - off
  if (len <= 0) {
    return { region: region('Payload', off, 0, { value: 'empty' }) }
  }
  let printableCount = 0
  for (let i = off; i < end; i++) {
    const b = bytes[i]
    if ((b >= 0x20 && b <= 0x7e) || b === 0x0a || b === 0x0d || b === 0x09) printableCount++
  }
  const ratio = printableCount / len
  if (ratio > 0.85) {
    const preview = latin1(bytes.subarray(off, Math.min(off + 120, end))).replace(/[\r\n]+/g, ' ⏎ ')
    ctx.summary.push(`payload: ${len} B, looks like text ("${preview.slice(0, 60)}${preview.length > 60 ? '…' : ''}")`)
    return { region: region('Payload (text)', off, len, { value: preview, note: `${Math.round(ratio * 100)}% printable ASCII.` }) }
  }
  ctx.summary.push(`payload: ${len} B (binary)`)
  return { region: region('Payload', off, len, { value: `${len} B binary data`, note: `${Math.round(ratio * 100)}% printable — likely binary or encrypted.` }) }
}
