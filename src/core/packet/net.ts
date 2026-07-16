import { hex } from '../bytes'
import type { Region } from '../region'

export type LayerId =
  | 'eth'
  | 'arp'
  | 'ipv4'
  | 'ipv6'
  | 'tcp'
  | 'udp'
  | 'icmp'
  | 'icmpv6'
  | 'dns'
  | 'tls'
  | 'http'
  | 'ntp'
  | 'payload'

export interface Ctx {
  summary: string[]
  warnings: string[]
  /** Set by the IP layer so TCP/UDP can verify their pseudo-header checksum. */
  ipPseudo?: { src: Uint8Array; dst: Uint8Array; proto: number; length: number; v6: boolean }
  /** Where the packet really ends according to the IP total-length field. */
  declaredEnd?: number
}

export interface LayerResult {
  region: Region
  next?: { layer: LayerId; offset: number }
}

export type LayerFn = (bytes: Uint8Array, off: number, ctx: Ctx) => LayerResult

export function macStr(b: Uint8Array, off: number): string {
  const parts: string[] = []
  for (let i = 0; i < 6; i++) parts.push(hex(b[off + i]).toLowerCase())
  return parts.join(':')
}

export function ipv4Str(b: Uint8Array, off: number): string {
  return `${b[off]}.${b[off + 1]}.${b[off + 2]}.${b[off + 3]}`
}

export function ipv6Str(b: Uint8Array, off: number): string {
  const groups: number[] = []
  for (let i = 0; i < 8; i++) groups.push((b[off + i * 2] << 8) | b[off + i * 2 + 1])
  // find the longest run of zero groups (must be ≥ 2) for :: compression
  let bestStart = -1
  let bestLen = 0
  let i = 0
  while (i < 8) {
    if (groups[i] === 0) {
      let j = i
      while (j < 8 && groups[j] === 0) j++
      if (j - i > bestLen) {
        bestLen = j - i
        bestStart = i
      }
      i = j
    } else i++
  }
  if (bestLen < 2) return groups.map((g) => g.toString(16)).join(':')
  const left = groups.slice(0, bestStart).map((g) => g.toString(16)).join(':')
  const right = groups.slice(bestStart + bestLen).map((g) => g.toString(16)).join(':')
  return `${left}::${right}`
}

export function ipv4Kind(b: Uint8Array, off: number): string | null {
  const a = b[off]
  const c = b[off + 1]
  if (a === 10 || (a === 172 && c >= 16 && c <= 31) || (a === 192 && c === 168)) return 'private, RFC 1918'
  if (a === 127) return 'loopback'
  if (a === 169 && c === 254) return 'link-local (APIPA)'
  if (a === 100 && c >= 64 && c <= 127) return 'CGNAT, RFC 6598'
  if (a >= 224 && a <= 239) return 'multicast'
  if (a === 255 && c === 255 && b[off + 2] === 255 && b[off + 3] === 255) return 'limited broadcast'
  if (a === 192 && c === 0 && b[off + 2] === 2) return 'documentation range (TEST-NET-1)'
  if (a === 198 && c === 51 && b[off + 2] === 100) return 'documentation range (TEST-NET-2)'
  if (a === 203 && c === 0 && b[off + 2] === 113) return 'documentation range (TEST-NET-3)'
  return null
}

/** RFC 1071 Internet checksum over one contiguous buffer. Returns the 16-bit result. */
export function inetChecksum(parts: Uint8Array[]): number {
  let sum = 0
  for (const part of parts) {
    // parts other than the last must have even length for correct 16-bit alignment
    for (let i = 0; i + 1 < part.length; i += 2) sum += (part[i] << 8) | part[i + 1]
    if (part.length % 2 === 1) sum += part[part.length - 1] << 8
  }
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16)
  return ~sum & 0xffff
}

export function pseudoHeader(src: Uint8Array, dst: Uint8Array, proto: number, length: number, v6: boolean): Uint8Array {
  if (v6) {
    const p = new Uint8Array(40)
    p.set(src, 0)
    p.set(dst, 16)
    p[32] = (length >>> 24) & 0xff
    p[33] = (length >>> 16) & 0xff
    p[34] = (length >>> 8) & 0xff
    p[35] = length & 0xff
    p[39] = proto
    return p
  }
  const p = new Uint8Array(12)
  p.set(src, 0)
  p.set(dst, 4)
  p[9] = proto
  p[10] = (length >>> 8) & 0xff
  p[11] = length & 0xff
  return p
}

export const SERVICES: Record<number, string> = {
  20: 'FTP data',
  21: 'FTP control',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  67: 'DHCP server',
  68: 'DHCP client',
  69: 'TFTP',
  80: 'HTTP',
  110: 'POP3',
  123: 'NTP',
  137: 'NetBIOS name',
  143: 'IMAP',
  161: 'SNMP',
  179: 'BGP',
  389: 'LDAP',
  443: 'HTTPS',
  445: 'SMB',
  465: 'SMTPS',
  514: 'syslog',
  587: 'SMTP submission',
  636: 'LDAPS',
  853: 'DNS over TLS',
  993: 'IMAPS',
  995: 'POP3S',
  1433: 'MS SQL',
  1521: 'Oracle',
  3128: 'HTTP proxy',
  3306: 'MySQL',
  3389: 'RDP',
  5060: 'SIP',
  5353: 'mDNS',
  5432: 'PostgreSQL',
  5672: 'AMQP',
  6379: 'Redis',
  8080: 'HTTP alt',
  8443: 'HTTPS alt',
  9092: 'Kafka',
  11211: 'memcached',
  27017: 'MongoDB',
}

export function portLabel(port: number): string {
  return SERVICES[port] ? `${port} (${SERVICES[port]})` : String(port)
}

export const IP_PROTOCOLS: Record<number, string> = {
  1: 'ICMP',
  2: 'IGMP',
  6: 'TCP',
  17: 'UDP',
  41: 'IPv6 encapsulation',
  47: 'GRE',
  50: 'ESP (IPsec)',
  51: 'AH (IPsec)',
  58: 'ICMPv6',
  89: 'OSPF',
  132: 'SCTP',
}
