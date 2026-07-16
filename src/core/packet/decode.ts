import { region, type ParseResult } from '../region'
import { arpLayer, ethLayer } from './ethernet'
import { icmpLayer, icmpv6Layer, ipv4Layer, ipv6Layer } from './ip'
import { dnsLayer } from './dns'
import { tcpLayer, udpLayer } from './transport'
import { tlsLayer } from './tls'
import { httpLayer, ntpLayer, payloadLayer } from './app'
import type { Ctx, LayerFn, LayerId } from './net'

const LAYERS: Record<LayerId, LayerFn> = {
  eth: ethLayer,
  arp: arpLayer,
  ipv4: ipv4Layer,
  ipv6: ipv6Layer,
  tcp: tcpLayer,
  udp: udpLayer,
  icmp: icmpLayer,
  icmpv6: icmpv6Layer,
  dns: dnsLayer,
  tls: tlsLayer,
  http: httpLayer,
  ntp: ntpLayer,
  payload: payloadLayer,
}

export const FIRST_LAYER_CHOICES: { id: LayerId | 'auto'; label: string }[] = [
  { id: 'auto', label: 'Auto-detect' },
  { id: 'eth', label: 'Ethernet II' },
  { id: 'ipv4', label: 'IPv4' },
  { id: 'ipv6', label: 'IPv6' },
  { id: 'tcp', label: 'TCP' },
  { id: 'udp', label: 'UDP' },
  { id: 'arp', label: 'ARP' },
  { id: 'dns', label: 'DNS message' },
  { id: 'tls', label: 'TLS record' },
]

/** Guess the outermost layer of a raw byte blob. */
export function sniffFirstLayer(bytes: Uint8Array): LayerId {
  if (bytes.length >= 14) {
    const etherType = (bytes[12] << 8) | bytes[13]
    if ([0x0800, 0x0806, 0x86dd, 0x8100, 0x88a8, 0x88cc].includes(etherType)) return 'eth'
  }
  if (bytes.length >= 20 && bytes[0] >> 4 === 4 && (bytes[0] & 0x0f) >= 5) {
    const totalLen = (bytes[2] << 8) | bytes[3]
    if (totalLen >= 20) return 'ipv4'
  }
  if (bytes.length >= 40 && bytes[0] >> 4 === 6) return 'ipv6'
  if (bytes.length >= 5 && bytes[0] >= 20 && bytes[0] <= 23 && bytes[1] === 3 && bytes[2] <= 4) return 'tls'
  if (bytes.length >= 12 && bytes.length < 600) {
    // could be a bare DNS message: sane counts?
    const qd = (bytes[4] << 8) | bytes[5]
    const an = (bytes[6] << 8) | bytes[7]
    if (qd >= 1 && qd <= 4 && an <= 50) return 'dns'
  }
  return bytes.length >= 14 ? 'eth' : 'payload'
}

export function decodePacket(bytes: Uint8Array, first: LayerId | 'auto' = 'auto'): ParseResult {
  const ctx: Ctx = { summary: [], warnings: [] }
  const regions: ParseResult['regions'] = []
  let layer: LayerId = first === 'auto' ? sniffFirstLayer(bytes) : first
  let off = 0
  let guard = 0
  let topLabel = ''

  while (off < bytes.length && guard++ < 12) {
    try {
      const result = LAYERS[layer](bytes, off, ctx)
      regions.push(result.region)
      if (!topLabel) topLabel = result.region.name
      if (!result.next || result.next.offset >= bytes.length) break
      layer = result.next.layer
      off = result.next.offset
    } catch (e) {
      ctx.warnings.push(`${layer} layer: ${e instanceof Error ? e.message : String(e)} — packet appears truncated`)
      if (off < bytes.length) {
        regions.push(region(`${layer} (truncated)`, off, bytes.length - off, { flag: 'warn' }))
      }
      break
    }
  }

  // Ethernet frames are padded to 60 bytes; anything past the IP total length is padding/FCS.
  if (ctx.declaredEnd !== undefined && ctx.declaredEnd < bytes.length) {
    const padLen = bytes.length - ctx.declaredEnd
    regions.push(
      region('Trailer / padding', ctx.declaredEnd, padLen, {
        value: `${padLen} B`,
        note: 'Bytes beyond the IP total length. Usually Ethernet minimum-frame padding (frames must be ≥ 60 bytes) or the 4-byte FCS if the capture kept it.',
      }),
    )
  }

  const deepest = ctx.summary[ctx.summary.length - 1] ?? ''
  return {
    format: `Decoded packet (${bytes.length} bytes)`,
    summary: ctx.summary.length ? ctx.summary : [deepest || 'nothing decoded'],
    regions,
    warnings: ctx.warnings,
  }
}
