import { describe, expect, it } from 'vitest'
import { decodePacket, sniffFirstLayer } from '../src/core/packet/decode'
import { SAMPLE_PACKETS } from '../src/core/packet/samples'

const sample = (id: string) => SAMPLE_PACKETS.find((s) => s.id === id)!.build()

describe('sample packets decode with valid checksums', () => {
  for (const s of SAMPLE_PACKETS) {
    it(`${s.id} produces no warnings`, () => {
      const out = decodePacket(s.build())
      expect(out.warnings).toEqual([])
    })
  }
})

describe('layer decoding', () => {
  it('DNS query: full ethernet → ipv4 → udp → dns chain', () => {
    const out = decodePacket(sample('dns-query'))
    const text = out.summary.join('\n')
    expect(text).toContain('Ethernet II')
    expect(text).toContain('IPv4: 192.168.1.23 → 1.1.1.1 (UDP')
    expect(text).toContain('UDP: 54321 → 53')
    expect(text).toContain('DNS query: example.com A')
    const ipv4 = out.regions.find((r) => r.name === 'IPv4')
    expect(ipv4?.children?.find((c) => c.name === 'Header checksum')?.flag).toBe('ok')
  })

  it('DNS response: decompresses names and reads answers', () => {
    const out = decodePacket(sample('dns-response'))
    const text = out.summary.join('\n')
    expect(text).toContain('DNS response: example.com A')
    expect(text).toContain('93.184.216.34')
    expect(text).toContain('CNAME www.example.org')
  })

  it('TCP SYN: flags and options', () => {
    const out = decodePacket(sample('tcp-syn'))
    const text = out.summary.join('\n')
    expect(text).toContain('[SYN]')
    const tcp = out.regions.find((r) => r.name === 'TCP')
    const opts = tcp?.children?.find((c) => c.name === 'Options')
    expect(opts?.value).toContain('MSS=1460')
    expect(opts?.value).toContain('WS=7')
    expect(tcp?.children?.find((c) => c.name === 'Checksum')?.flag).toBe('ok')
  })

  it('HTTP GET: parses the request line and headers', () => {
    const out = decodePacket(sample('http-get'))
    expect(out.summary.join('\n')).toContain('HTTP: GET /tools/ HTTP/1.1')
    const http = out.regions.find((r) => r.name === 'HTTP/1.x')
    expect(http?.children?.some((c) => c.name === 'Host')).toBe(true)
  })

  it('ICMP ping: echo request with id/seq', () => {
    const out = decodePacket(sample('ping'))
    expect(out.summary.join('\n')).toContain('Echo request (ping)')
    const icmp = out.regions.find((r) => r.name === 'ICMP')
    expect(icmp?.children?.find((c) => c.name === 'Checksum')?.flag).toBe('ok')
  })

  it('ARP: who-has summary', () => {
    const out = decodePacket(sample('arp'))
    expect(out.summary.join('\n')).toContain('who has 192.168.1.1? Tell 192.168.1.23')
  })

  it('TLS ClientHello: SNI, ALPN and version extensions', () => {
    const out = decodePacket(sample('tls-hello'))
    const text = out.summary.join('\n')
    expect(text).toContain('TLS ClientHello')
    expect(text).toContain('SNI: hexbase.dev')
    expect(text).toContain('offers TLS 1.3')
    const tls = out.regions.find((r) => r.name.startsWith('TLS'))
    const record = tls?.children?.[0]
    expect(record?.children?.some((c) => c.name === 'Extension: ALPN' && c.value === 'h2, http/1.1')).toBe(true)
  })
})

describe('sniffFirstLayer', () => {
  it('detects bare IPv4', () => {
    expect(sniffFirstLayer(sample('dns-response'))).toBe('ipv4')
  })
  it('detects ethernet', () => {
    expect(sniffFirstLayer(sample('dns-query'))).toBe('eth')
  })
})

describe('corruption is reported', () => {
  it('flags a bad IPv4 checksum', () => {
    const pkt = sample('dns-response').slice()
    pkt[10] ^= 0xff
    const out = decodePacket(pkt)
    expect(out.warnings.join(' ')).toMatch(/IPv4 header checksum is invalid/)
  })
  it('flags a truncated packet', () => {
    const pkt = sample('dns-query').slice(0, 30)
    const out = decodePacket(pkt)
    expect(out.warnings.length).toBeGreaterThan(0)
  })
})
