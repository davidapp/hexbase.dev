import { ByteReader, hex } from '../bytes'
import { region, type Region } from '../region'
import { inetChecksum, ipv4Kind, ipv4Str, ipv6Str, IP_PROTOCOLS, type Ctx, type LayerFn, type LayerId, type LayerResult } from './net'

function nextForProto(proto: number): LayerId {
  switch (proto) {
    case 1:
      return 'icmp'
    case 6:
      return 'tcp'
    case 17:
      return 'udp'
    case 58:
      return 'icmpv6'
    default:
      return 'payload'
  }
}

export const ipv4Layer: LayerFn = (bytes, off, ctx): LayerResult => {
  const r = new ByteReader(bytes, off)
  const vihl = r.u8()
  const version = vihl >> 4
  const ihl = (vihl & 0x0f) * 4
  const tos = r.u8()
  const dscp = tos >> 2
  const ecn = tos & 3
  const totalLen = r.u16be()
  const ident = r.u16be()
  const flagsFrag = r.u16be()
  const evil = (flagsFrag & 0x8000) !== 0
  const df = (flagsFrag & 0x4000) !== 0
  const mf = (flagsFrag & 0x2000) !== 0
  const fragOff = (flagsFrag & 0x1fff) * 8
  const ttl = r.u8()
  const proto = r.u8()
  const cksum = r.u16be()
  const srcStr = ipv4Str(bytes, off + 12)
  const dstStr = ipv4Str(bytes, off + 16)

  if (version !== 4) ctx.warnings.push(`IP version field is ${version}, expected 4 — wrong starting layer?`)
  const available = bytes.length - off
  let checksumOk: boolean | null = null
  if (available >= ihl) {
    checksumOk = inetChecksum([bytes.subarray(off, off + ihl)]) === 0
  }
  if (totalLen > available) ctx.warnings.push(`IPv4 total length says ${totalLen} bytes but only ${available} are present — packet truncated`)
  ctx.declaredEnd = off + Math.min(totalLen, available)

  const srcKind = ipv4Kind(bytes, off + 12)
  const dstKind = ipv4Kind(bytes, off + 16)
  const protoName = IP_PROTOCOLS[proto] ?? `protocol ${proto}`

  const flagBits: string[] = []
  if (evil) flagBits.push('reserved bit SET (the RFC 3514 "evil bit" — should always be 0)')
  if (df) flagBits.push("DF don't-fragment")
  if (mf) flagBits.push('MF more-fragments')

  const children: Region[] = [
    region('Version / IHL', off, 1, {
      value: `v${version}, header ${ihl} B`,
      note: 'Low nibble = header length in 32-bit words; 5 (20 bytes) unless IP options are present.',
    }),
    region('DSCP / ECN', off + 1, 1, {
      value: `DSCP ${dscp}, ECN ${ecn}`,
      note: 'Quality-of-service class + explicit congestion notification bits.',
    }),
    region('Total length', off + 2, 2, { value: `${totalLen} B`, note: 'Header + payload. Max 65535 — this field is why jumbo IP packets need IPv6 jumbograms.' }),
    region('Identification', off + 4, 2, { value: '0x' + hex(ident, 4), note: 'Groups fragments of the same original packet back together.' }),
    region('Flags / Fragment offset', off + 6, 2, {
      value: flagBits.length ? flagBits.join(', ') : 'no flags' + (fragOff ? '' : ''),
      note: fragOff ? `fragment offset ${fragOff} bytes` : 'DF set is the norm today — path-MTU discovery relies on it.',
      flag: evil ? 'warn' : undefined,
    }),
    region('TTL', off + 8, 1, {
      value: String(ttl),
      note: 'Decremented by every router; at 0 the packet dies and an ICMP Time Exceeded goes back — exactly the mechanism traceroute abuses. Common initial values: 64 (Linux/macOS), 128 (Windows), 255 (network gear).',
    }),
    region('Protocol', off + 9, 1, { value: `${proto} — ${protoName}`, note: 'What is inside the payload.' }),
    region('Header checksum', off + 10, 2, {
      value: '0x' + hex(cksum, 4) + (checksumOk === null ? '' : checksumOk ? ' — valid' : ' — INVALID'),
      note: 'Covers the header only (payload protocols carry their own). Recomputed at every hop because TTL changes.',
      flag: checksumOk === null ? undefined : checksumOk ? 'ok' : 'bad',
    }),
    region('Source address', off + 12, 4, { value: srcStr + (srcKind ? ` (${srcKind})` : ''), note: srcKind ?? 'public address' }),
    region('Destination address', off + 16, 4, { value: dstStr + (dstKind ? ` (${dstKind})` : ''), note: dstKind ?? 'public address' }),
  ]
  if (ihl > 20) {
    children.push(region('IP options', off + 20, ihl - 20, { note: 'Rare in the wild — many networks drop packets with IP options outright.' }))
  }
  if (checksumOk === false) ctx.warnings.push('IPv4 header checksum is invalid')

  const payloadLen = Math.min(totalLen, available) - ihl
  ctx.ipPseudo = {
    src: bytes.subarray(off + 12, off + 16),
    dst: bytes.subarray(off + 16, off + 20),
    proto,
    length: payloadLen,
    v6: false,
  }
  ctx.summary.push(`IPv4: ${srcStr} → ${dstStr} (${protoName}, TTL ${ttl})`)

  return {
    region: region('IPv4', off, ihl, {
      value: `${srcStr} → ${dstStr}`,
      note: 'Layer 3. Routing between networks: addresses, fragmentation and time-to-live.',
      children,
    }),
    next: { layer: nextForProto(proto), offset: off + ihl },
  }
}

const EXT_HEADERS: Record<number, string> = {
  0: 'Hop-by-Hop Options',
  43: 'Routing',
  44: 'Fragment',
  60: 'Destination Options',
}

export const ipv6Layer: LayerFn = (bytes, off, ctx): LayerResult => {
  const r = new ByteReader(bytes, off)
  const first = r.u32be()
  const version = first >>> 28
  const trafficClass = (first >>> 20) & 0xff
  const flowLabel = first & 0xfffff
  const payloadLen = r.u16be()
  let nextHeader = r.u8()
  const hopLimit = r.u8()
  const srcStr = ipv6Str(bytes, off + 8)
  const dstStr = ipv6Str(bytes, off + 24)

  if (version !== 6) ctx.warnings.push(`IP version field is ${version}, expected 6 — wrong starting layer?`)

  const children: Region[] = [
    region('Version / Traffic class / Flow label', off, 4, {
      value: `v${version}, TC ${trafficClass}, flow 0x${flowLabel.toString(16)}`,
      note: 'The flow label lets routers keep packets of one flow on one path without inspecting layer 4.',
    }),
    region('Payload length', off + 4, 2, { value: `${payloadLen} B`, note: 'Everything after this fixed 40-byte header.' }),
    region('Next header', off + 6, 1, {
      value: `${nextHeader} — ${IP_PROTOCOLS[nextHeader] ?? EXT_HEADERS[nextHeader] ?? '?'}`,
      note: 'IPv6 has no variable header: options are chained as separate "extension headers", each naming the next.',
    }),
    region('Hop limit', off + 7, 1, { value: String(hopLimit), note: 'Same job as the IPv4 TTL, honest name.' }),
    region('Source address', off + 8, 16, { value: srcStr }),
    region('Destination address', off + 24, 16, { value: dstStr }),
  ]

  // Walk extension headers
  let pos = off + 40
  let guard = 0
  while (EXT_HEADERS[nextHeader] !== undefined && pos + 8 <= bytes.length && guard++ < 8) {
    const hdrName = EXT_HEADERS[nextHeader]
    const nh = bytes[pos]
    const len = nextHeader === 44 ? 8 : (bytes[pos + 1] + 1) * 8
    children.push(region(`Extension: ${hdrName}`, pos, len, { value: `next: ${IP_PROTOCOLS[nh] ?? nh}` }))
    nextHeader = nh
    pos += len
  }

  ctx.declaredEnd = off + 40 + Math.min(payloadLen, Math.max(0, bytes.length - off - 40))
  ctx.ipPseudo = {
    src: bytes.subarray(off + 8, off + 24),
    dst: bytes.subarray(off + 24, off + 40),
    proto: nextHeader,
    length: Math.min(payloadLen - (pos - off - 40), bytes.length - pos),
    v6: true,
  }
  ctx.summary.push(`IPv6: ${srcStr} → ${dstStr} (${IP_PROTOCOLS[nextHeader] ?? nextHeader}, hop limit ${hopLimit})`)

  return {
    region: region('IPv6', off, pos - off, {
      value: `${srcStr} → ${dstStr}`,
      note: 'Layer 3. Fixed 40-byte header — no checksum (layer 2 and 4 already have them), no router fragmentation.',
      children,
    }),
    next: { layer: nextForProto(nextHeader), offset: pos },
  }
}

const ICMP_TYPES: Record<number, string> = {
  0: 'Echo reply (pong)',
  3: 'Destination unreachable',
  5: 'Redirect',
  8: 'Echo request (ping)',
  9: 'Router advertisement',
  10: 'Router solicitation',
  11: 'Time exceeded',
  12: 'Parameter problem',
  13: 'Timestamp request',
  14: 'Timestamp reply',
}

const ICMP_UNREACH: Record<number, string> = {
  0: 'network unreachable',
  1: 'host unreachable',
  2: 'protocol unreachable',
  3: 'port unreachable',
  4: 'fragmentation needed but DF set (path-MTU discovery)',
  13: 'communication administratively prohibited (a firewall said no)',
}

export const icmpLayer: LayerFn = (bytes, off, ctx): LayerResult => {
  const r = new ByteReader(bytes, off)
  const type = r.u8()
  const code = r.u8()
  const cksum = r.u16be()
  const end = ctx.declaredEnd ?? bytes.length
  const len = Math.max(4, end - off)
  const typeName = ICMP_TYPES[type] ?? `type ${type}`
  const checksumOk = inetChecksum([bytes.subarray(off, end)]) === 0

  const children: Region[] = [
    region('Type', off, 1, { value: `${type} — ${typeName}` }),
    region('Code', off + 1, 1, {
      value: type === 3 ? `${code} — ${ICMP_UNREACH[code] ?? code}` : String(code),
      note: type === 11 ? (code === 0 ? 'TTL expired in transit — a traceroute hop.' : 'fragment reassembly timeout') : undefined,
    }),
    region('Checksum', off + 2, 2, { value: '0x' + hex(cksum, 4) + (checksumOk ? ' — valid' : ' — INVALID'), flag: checksumOk ? 'ok' : 'bad' }),
  ]
  if (type === 0 || type === 8) {
    const id = (bytes[off + 4] << 8) | bytes[off + 5]
    const seq = (bytes[off + 6] << 8) | bytes[off + 7]
    children.push(
      region('Identifier', off + 4, 2, { value: String(id), note: 'Matches replies to the pinging process.' }),
      region('Sequence number', off + 6, 2, { value: String(seq), note: 'Increments per ping — how "icmp_seq=" in ping output gets its value.' }),
    )
    if (end > off + 8) {
      children.push(region('Payload', off + 8, end - off - 8, { note: 'Ping payloads are arbitrary. Classic Unix ping sends an ASCII ramp (!"#$%&\'()*+…); the reply must echo it byte-for-byte.' }))
    }
  } else if (end > off + 8) {
    children.push(region('Rest of message', off + 4, end - off - 4, { note: 'Error messages quote the IP header + first 8 bytes of the packet that caused them.' }))
  }
  if (!checksumOk) ctx.warnings.push('ICMP checksum is invalid')
  ctx.summary.push(`ICMP: ${typeName}${type === 3 ? ` (${ICMP_UNREACH[code] ?? 'code ' + code})` : ''}`)

  return {
    region: region('ICMP', off, len, { value: typeName, note: 'The Internet Control Message Protocol — the network talking about itself: errors, ping, path discovery.', children }),
  }
}

const ICMP6_TYPES: Record<number, string> = {
  1: 'Destination unreachable',
  2: 'Packet too big',
  3: 'Time exceeded',
  4: 'Parameter problem',
  128: 'Echo request (ping)',
  129: 'Echo reply (pong)',
  133: 'Router solicitation (NDP)',
  134: 'Router advertisement (NDP)',
  135: 'Neighbor solicitation (NDP — IPv6\'s ARP)',
  136: 'Neighbor advertisement (NDP)',
}

export const icmpv6Layer: LayerFn = (bytes, off, ctx): LayerResult => {
  const type = bytes[off]
  const code = bytes[off + 1]
  const end = ctx.declaredEnd ?? bytes.length
  const typeName = ICMP6_TYPES[type] ?? `type ${type}`
  const children: Region[] = [
    region('Type', off, 1, { value: `${type} — ${typeName}` }),
    region('Code', off + 1, 1, { value: String(code) }),
    region('Checksum', off + 2, 2, { note: 'Unlike ICMPv4, computed over a pseudo-header including the IPv6 addresses.' }),
  ]
  if (type === 135 && end >= off + 24) {
    children.push(region('Target address', off + 8, 16, { value: ipv6Str(bytes, off + 8), note: 'The address being resolved — NDP replaces ARP in IPv6.' }))
  }
  ctx.summary.push(`ICMPv6: ${typeName}`)
  return {
    region: region('ICMPv6', off, Math.max(4, end - off), { value: typeName, note: 'Control + neighbor discovery. IPv6 cannot function without it — never blanket-block ICMPv6.', children }),
  }
}
