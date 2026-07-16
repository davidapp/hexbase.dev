import { ByteReader, latin1 } from '../bytes'
import { region, type Region } from '../region'
import { ipv4Str, ipv6Str, type LayerFn, type LayerResult } from './net'

const RTYPES: Record<number, string> = {
  1: 'A',
  2: 'NS',
  5: 'CNAME',
  6: 'SOA',
  12: 'PTR',
  15: 'MX',
  16: 'TXT',
  28: 'AAAA',
  33: 'SRV',
  35: 'NAPTR',
  41: 'OPT',
  43: 'DS',
  46: 'RRSIG',
  47: 'NSEC',
  48: 'DNSKEY',
  50: 'NSEC3',
  64: 'SVCB',
  65: 'HTTPS',
  255: 'ANY',
  252: 'AXFR',
  257: 'CAA',
}

const RCODES: Record<number, string> = {
  0: 'NoError',
  1: 'FormErr',
  2: 'ServFail',
  3: 'NXDomain (name does not exist)',
  4: 'NotImp',
  5: 'Refused',
}

const OPCODES: Record<number, string> = { 0: 'QUERY', 1: 'IQUERY', 2: 'STATUS', 4: 'NOTIFY', 5: 'UPDATE' }

/** Read a possibly-compressed DNS name. `base` = start of the DNS message. */
function readName(bytes: Uint8Array, pos: number, base: number): { name: string; size: number } {
  const labels: string[] = []
  let size = 0
  let jumped = false
  let p = pos
  let guard = 0
  while (guard++ < 128) {
    if (p >= bytes.length) throw new RangeError('truncated DNS name')
    const len = bytes[p]
    if (len === 0) {
      if (!jumped) size = p - pos + 1
      break
    }
    if ((len & 0xc0) === 0xc0) {
      if (p + 1 >= bytes.length) throw new RangeError('truncated DNS compression pointer')
      const ptr = ((len & 0x3f) << 8) | bytes[p + 1]
      if (!jumped) size = p - pos + 2
      jumped = true
      p = base + ptr
      continue
    }
    labels.push(latin1(bytes.subarray(p + 1, p + 1 + len)))
    p += len + 1
  }
  return { name: labels.length ? labels.join('.') : '.', size }
}

function rdataText(bytes: Uint8Array, type: number, pos: number, len: number, base: number): string {
  try {
    switch (type) {
      case 1:
        return len >= 4 ? ipv4Str(bytes, pos) : '?'
      case 28:
        return len >= 16 ? ipv6Str(bytes, pos) : '?'
      case 2:
      case 5:
      case 12:
        return readName(bytes, pos, base).name
      case 15: {
        const pref = (bytes[pos] << 8) | bytes[pos + 1]
        return `${pref} ${readName(bytes, pos + 2, base).name}`
      }
      case 16: {
        const parts: string[] = []
        let p = pos
        while (p < pos + len) {
          const l = bytes[p]
          parts.push(`"${latin1(bytes.subarray(p + 1, p + 1 + l))}"`)
          p += l + 1
        }
        return parts.join(' ')
      }
      case 6: {
        const m = readName(bytes, pos, base)
        const r = readName(bytes, pos + m.size, base)
        const v = new DataView(bytes.buffer, bytes.byteOffset)
        const serial = v.getUint32(pos + m.size + r.size)
        return `mname=${m.name} serial=${serial}`
      }
      case 33: {
        const v = new DataView(bytes.buffer, bytes.byteOffset)
        return `prio=${v.getUint16(pos)} weight=${v.getUint16(pos + 2)} port=${v.getUint16(pos + 4)} ${readName(bytes, pos + 6, base).name}`
      }
      default:
        return `${len} bytes`
    }
  } catch {
    return '(truncated)'
  }
}

export const dnsLayer: LayerFn = (bytes, off, ctx): LayerResult => {
  let base = off
  // DNS over TCP prefixes the message with a 2-byte length.
  const avail = bytes.length - off
  if (avail >= 2) {
    const maybeLen = (bytes[off] << 8) | bytes[off + 1]
    if (maybeLen === avail - 2 && maybeLen >= 12) base = off + 2
  }

  const r = new ByteReader(bytes, base)
  const id = r.u16be()
  const flags = r.u16be()
  const qd = r.u16be()
  const an = r.u16be()
  const ns = r.u16be()
  const ar = r.u16be()

  const qr = (flags >> 15) & 1
  const opcode = (flags >> 11) & 0xf
  const aa = (flags >> 10) & 1
  const tc = (flags >> 9) & 1
  const rd = (flags >> 8) & 1
  const ra = (flags >> 7) & 1
  const ad = (flags >> 5) & 1
  const rcode = flags & 0xf

  const flagParts: string[] = [qr ? 'response' : 'query', OPCODES[opcode] ?? `opcode ${opcode}`]
  if (aa) flagParts.push('AA authoritative')
  if (tc) flagParts.push('TC truncated — retry over TCP')
  if (rd) flagParts.push('RD recursion desired')
  if (ra) flagParts.push('RA recursion available')
  if (ad) flagParts.push('AD DNSSEC-validated')
  if (qr) flagParts.push(RCODES[rcode] ?? `rcode ${rcode}`)

  const children: Region[] = []
  if (base !== off) {
    children.push(region('TCP length prefix', off, 2, { value: `${(bytes[off] << 8) | bytes[off + 1]} B`, note: 'DNS over TCP prefixes each message with its length — TCP is a byte stream with no message boundaries of its own.' }))
  }
  children.push(
    region('Transaction ID', base, 2, { value: '0x' + id.toString(16).padStart(4, '0').toUpperCase(), note: 'Matches responses to queries. Its 16 bits of entropy are part of the defense against off-path spoofing (see: Kaminsky attack, 2008).' }),
    region('Flags', base + 2, 2, { value: flagParts.join(', ') }),
    region('Counts', base + 4, 8, { value: `${qd} question, ${an} answer, ${ns} authority, ${ar} additional` }),
  )

  const questions: string[] = []
  const answers: string[] = []
  try {
    let p = base + 12
    for (let i = 0; i < Math.min(qd, 32); i++) {
      const start = p
      const n = readName(bytes, p, base)
      p += n.size
      const v = new DataView(bytes.buffer, bytes.byteOffset)
      const qtype = v.getUint16(p)
      const qclass = v.getUint16(p + 2)
      p += 4
      const typeName = RTYPES[qtype] ?? `type ${qtype}`
      questions.push(`${n.name} ${typeName}`)
      children.push(
        region(`Question: ${n.name}`, start, p - start, {
          value: `${typeName}, class ${qclass === 1 ? 'IN' : qclass}`,
          note: 'Names are length-prefixed labels ("7example3com0"), no dots on the wire.',
        }),
      )
    }
    const sections: [number, string][] = [
      [an, 'Answer'],
      [ns, 'Authority'],
      [ar, 'Additional'],
    ]
    for (const [count, label] of sections) {
      for (let i = 0; i < Math.min(count, 64); i++) {
        const start = p
        const n = readName(bytes, p, base)
        p += n.size
        const v = new DataView(bytes.buffer, bytes.byteOffset)
        const rtype = v.getUint16(p)
        const rclass = v.getUint16(p + 2)
        const ttl = v.getUint32(p + 4)
        const rdlen = v.getUint16(p + 8)
        p += 10
        const typeName = RTYPES[rtype] ?? `type ${rtype}`
        if (rtype === 41) {
          children.push(
            region(`${label}: OPT (EDNS0)`, start, p - start + rdlen, {
              value: `UDP payload size ${rclass}`,
              note: 'Pseudo-record extending classic DNS: bigger UDP messages, DNSSEC OK bit, cookies. The "class" field is repurposed as buffer size.',
            }),
          )
        } else {
          const rd = rdataText(bytes, rtype, p, rdlen, base)
          if (label === 'Answer') answers.push(`${typeName} ${rd}`)
          children.push(
            region(`${label}: ${n.name}`, start, p - start + rdlen, {
              value: `${typeName} → ${rd}`,
              note: `TTL ${ttl}s — resolvers may cache this record for that long. Compressed name pointers (0xC0xx) refer back into the message.`,
            }),
          )
        }
        p += rdlen
      }
    }
  } catch (e) {
    ctx.warnings.push(`DNS message truncated: ${e instanceof Error ? e.message : String(e)}`)
  }

  if (qr === 0) ctx.summary.push(`DNS query: ${questions.join(', ') || '(no question)'}`)
  else ctx.summary.push(`DNS response: ${questions.join(', ')} → ${answers.slice(0, 3).join(', ') || RCODES[rcode] || 'rcode ' + rcode}${answers.length > 3 ? ` (+${answers.length - 3} more)` : ''}`)

  return {
    region: region(`DNS ${qr ? 'response' : 'query'}`, off, bytes.length - off, {
      value: questions.join(', '),
      note: 'The phone book of the internet, still running on a 1983 wire format (RFC 1035).',
      children,
    }),
  }
}
