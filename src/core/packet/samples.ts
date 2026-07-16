/**
 * Built-in sample packets, constructed programmatically so every length and
 * checksum is genuinely valid (the decoder verifies them live).
 */
import { inetChecksum, pseudoHeader } from './net'

function cat(...parts: (Uint8Array | number[])[]): Uint8Array {
  const arrays = parts.map((p) => (p instanceof Uint8Array ? p : new Uint8Array(p)))
  const total = arrays.reduce((n, a) => n + a.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const a of arrays) {
    out.set(a, off)
    off += a.length
  }
  return out
}

const u16 = (v: number): number[] => [(v >> 8) & 0xff, v & 0xff]
const u32 = (v: number): number[] => [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]
const ascii = (s: string): number[] => [...s].map((c) => c.charCodeAt(0))

function eth(dst: number[], src: number[], type: number, payload: Uint8Array): Uint8Array {
  return cat(dst, src, u16(type), payload)
}

function ipv4(src: number[], dst: number[], proto: number, payload: Uint8Array, ttl = 64, id = 0x1c46): Uint8Array {
  const header = new Uint8Array(20)
  header[0] = 0x45
  header.set(u16(20 + payload.length), 2)
  header.set(u16(id), 4)
  header.set(u16(0x4000), 6) // DF
  header[8] = ttl
  header[9] = proto
  header.set(src, 12)
  header.set(dst, 16)
  const ck = inetChecksum([header])
  header.set(u16(ck), 10)
  return cat(header, payload)
}

function tcp(srcIp: number[], dstIp: number[], srcPort: number, dstPort: number, seq: number, ack: number, flags: number, payload: Uint8Array, options: number[] = [], window = 64240): Uint8Array {
  const optPadded = [...options]
  while (optPadded.length % 4 !== 0) optPadded.push(0x01)
  const dataOffset = (20 + optPadded.length) / 4
  const header = cat(u16(srcPort), u16(dstPort), u32(seq), u32(ack), [(dataOffset << 4) | 0, flags], u16(window), u16(0), u16(0), optPadded)
  const segment = cat(header, payload)
  const ck = inetChecksum([pseudoHeader(new Uint8Array(srcIp), new Uint8Array(dstIp), 6, segment.length, false), segment])
  segment.set(u16(ck), 16)
  return segment
}

function udp(srcIp: number[], dstIp: number[], srcPort: number, dstPort: number, payload: Uint8Array): Uint8Array {
  const len = 8 + payload.length
  const dgram = cat(u16(srcPort), u16(dstPort), u16(len), u16(0), payload)
  const ck = inetChecksum([pseudoHeader(new Uint8Array(srcIp), new Uint8Array(dstIp), 17, len, false), dgram])
  dgram.set(u16(ck === 0 ? 0xffff : ck), 6)
  return dgram
}

function dnsName(name: string): number[] {
  const out: number[] = []
  for (const label of name.split('.')) {
    out.push(label.length, ...ascii(label))
  }
  out.push(0)
  return out
}

function icmpEcho(type: number, id: number, seq: number, payload: number[]): Uint8Array {
  const msg = cat([type, 0], u16(0), u16(id), u16(seq), payload)
  const ck = inetChecksum([msg])
  msg.set(u16(ck), 2)
  return msg
}

const MAC_ROUTER = [0x3c, 0x7c, 0x3f, 0x1a, 0x2b, 0x3c]
const MAC_HOST = [0xa4, 0x83, 0xe7, 0x4e, 0x5f, 0x60]
const IP_HOST = [192, 168, 1, 23]
const IP_DNS = [1, 1, 1, 1]
const IP_WEB = [93, 184, 216, 34]

function buildDnsQuery(): Uint8Array {
  const dns = cat(
    u16(0x5ca1), // transaction id
    u16(0x0100), // standard query, recursion desired
    u16(1), u16(0), u16(0), u16(1), // 1 question, 1 additional (EDNS)
    dnsName('example.com'), u16(1), u16(1), // A, IN
    [0], u16(41), u16(1232), u32(0), u16(0), // OPT: root, type 41, udp size 1232
  )
  return eth(MAC_ROUTER, MAC_HOST, 0x0800, ipv4(IP_HOST, IP_DNS, 17, udp(IP_HOST, IP_DNS, 54321, 53, dns)))
}

function buildDnsResponse(): Uint8Array {
  const dns = cat(
    u16(0x5ca1),
    u16(0x8180), // response, RD+RA
    u16(1), u16(2), u16(0), u16(0),
    dnsName('example.com'), u16(1), u16(1),
    [0xc0, 0x0c], u16(5), u16(1), u32(300), u16(dnsName('www.example.org').length), dnsName('www.example.org'), // CNAME
    [0xc0, 0x0c], u16(1), u16(1), u32(300), u16(4), IP_WEB, // A record (compressed name pointer)
  )
  return ipv4(IP_DNS, IP_HOST, 17, udp(IP_DNS, IP_HOST, 53, 54321, dns), 58)
}

function buildTcpSyn(): Uint8Array {
  const options = [
    2, 4, ...u16(1460), // MSS
    4, 2, // SACK permitted
    8, 10, ...u32(0x0f00ba5e), ...u32(0), // timestamps
    1, // NOP
    3, 3, 7, // window scale ×128
  ]
  return eth(MAC_ROUTER, MAC_HOST, 0x0800, ipv4(IP_HOST, IP_WEB, 6, tcp(IP_HOST, IP_WEB, 51742, 443, 0x1e6f00d1, 0, 0x02, new Uint8Array(0), options)))
}

function buildHttpGet(): Uint8Array {
  const body = new Uint8Array(ascii('GET /tools/ HTTP/1.1\r\nHost: hexbase.dev\r\nUser-Agent: curl/8.9.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n'))
  return ipv4(IP_HOST, IP_WEB, 6, tcp(IP_HOST, IP_WEB, 51744, 80, 0x00000001, 0x00000001, 0x18, body))
}

function buildPing(): Uint8Array {
  // the classic ascii-ramp ping payload
  const ramp: number[] = []
  for (let i = 0; i < 48; i++) ramp.push(0x08 + i)
  const icmp = icmpEcho(8, 0x2a17, 1, ramp)
  return eth(MAC_ROUTER, MAC_HOST, 0x0800, ipv4(IP_HOST, [8, 8, 8, 8], 1, icmp))
}

function buildArp(): Uint8Array {
  const arp = cat(u16(1), u16(0x0800), [6, 4], u16(1), MAC_HOST, IP_HOST, [0, 0, 0, 0, 0, 0], [192, 168, 1, 1])
  return eth([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], MAC_HOST, 0x0806, arp)
}

function buildTlsClientHello(): Uint8Array {
  const sni = 'hexbase.dev'
  const sniExt = cat(u16(0), u16(sni.length + 5), u16(sni.length + 3), [0], u16(sni.length), ascii(sni))
  const alpn = cat([2], ascii('h2'), [8], ascii('http/1.1'))
  const alpnExt = cat(u16(16), u16(alpn.length + 2), u16(alpn.length), alpn)
  const versionsExt = cat(u16(43), u16(5), [4], u16(0x0304), u16(0x0303))
  const groupsExt = cat(u16(10), u16(6), u16(4), u16(0x001d), u16(0x0017))
  const extensions = cat(sniExt, alpnExt, versionsExt, groupsExt)
  const ciphers = cat(u16(0x1301), u16(0x1302), u16(0x1303), u16(0xc02f), u16(0xcca8))
  const random = new Uint8Array(32)
  for (let i = 0; i < 32; i++) random[i] = (i * 41 + 7) & 0xff
  const helloBody = cat(
    u16(0x0303), // legacy version
    random,
    [0], // empty session id
    u16(ciphers.length), ciphers,
    [1, 0], // compression: null only
    u16(extensions.length), extensions,
  )
  const handshake = cat([1], [0, (helloBody.length >> 8) & 0xff, helloBody.length & 0xff], helloBody)
  const record = cat([22], u16(0x0301), u16(handshake.length), handshake)
  return ipv4(IP_HOST, IP_WEB, 6, tcp(IP_HOST, IP_WEB, 51746, 443, 0x00000001, 0x00000001, 0x18, record))
}

export interface SamplePacket {
  id: string
  label: string
  desc: string
  build(): Uint8Array
}

export const SAMPLE_PACKETS: SamplePacket[] = [
  { id: 'dns-query', label: 'DNS query', desc: 'Ethernet → IPv4 → UDP → DNS: A-record lookup for example.com with EDNS0', build: buildDnsQuery },
  { id: 'dns-response', label: 'DNS response', desc: 'IPv4 → UDP → DNS: CNAME + A answer using name compression', build: buildDnsResponse },
  { id: 'tcp-syn', label: 'TCP SYN', desc: 'Ethernet → IPv4 → TCP: connection open with MSS, SACK, timestamps, window-scale options', build: buildTcpSyn },
  { id: 'http-get', label: 'HTTP GET', desc: 'IPv4 → TCP → HTTP/1.1 request in plain ASCII', build: buildHttpGet },
  { id: 'ping', label: 'ICMP ping', desc: 'Ethernet → IPv4 → ICMP echo request with the classic ASCII-ramp payload', build: buildPing },
  { id: 'arp', label: 'ARP request', desc: 'Ethernet broadcast → ARP: who has 192.168.1.1?', build: buildArp },
  { id: 'tls-hello', label: 'TLS ClientHello', desc: 'IPv4 → TCP → TLS 1.3 ClientHello with SNI and ALPN', build: buildTlsClientHello },
]
