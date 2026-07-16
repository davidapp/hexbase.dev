import { ByteReader, hex, latin1 } from '../bytes'
import { region, type Region } from '../region'
import type { LayerFn, LayerResult } from './net'

const RECORD_TYPES: Record<number, string> = {
  20: 'ChangeCipherSpec',
  21: 'Alert',
  22: 'Handshake',
  23: 'ApplicationData',
}

const VERSIONS: Record<number, string> = {
  0x0300: 'SSL 3.0',
  0x0301: 'TLS 1.0',
  0x0302: 'TLS 1.1',
  0x0303: 'TLS 1.2',
  0x0304: 'TLS 1.3',
}

const HANDSHAKE_TYPES: Record<number, string> = {
  1: 'ClientHello',
  2: 'ServerHello',
  4: 'NewSessionTicket',
  8: 'EncryptedExtensions',
  11: 'Certificate',
  12: 'ServerKeyExchange',
  14: 'ServerHelloDone',
  16: 'ClientKeyExchange',
  20: 'Finished',
}

const CIPHERS: Record<number, string> = {
  0x1301: 'TLS_AES_128_GCM_SHA256',
  0x1302: 'TLS_AES_256_GCM_SHA384',
  0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
  0x009c: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
  0x009d: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
  0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
  0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
  0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  0xcca8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
  0xcca9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
  0x00ff: 'EMPTY_RENEGOTIATION_INFO_SCSV',
}

const EXTENSIONS: Record<number, string> = {
  0: 'server_name (SNI)',
  5: 'status_request (OCSP)',
  10: 'supported_groups',
  11: 'ec_point_formats',
  13: 'signature_algorithms',
  16: 'ALPN',
  18: 'signed_certificate_timestamp',
  21: 'padding',
  23: 'extended_master_secret',
  27: 'compress_certificate',
  35: 'session_ticket',
  43: 'supported_versions',
  45: 'psk_key_exchange_modes',
  51: 'key_share',
  65281: 'renegotiation_info',
}

const GROUPS: Record<number, string> = {
  0x0017: 'secp256r1',
  0x0018: 'secp384r1',
  0x0019: 'secp521r1',
  0x001d: 'x25519',
  0x001e: 'x448',
  0x0100: 'ffdhe2048',
  0x11ec: 'X25519MLKEM768 (post-quantum hybrid)',
}

const ALERTS: Record<number, string> = {
  0: 'close_notify',
  10: 'unexpected_message',
  20: 'bad_record_mac',
  40: 'handshake_failure',
  42: 'bad_certificate',
  45: 'certificate_expired',
  46: 'certificate_unknown',
  47: 'illegal_parameter',
  48: 'unknown_ca',
  70: 'protocol_version',
  112: 'unrecognized_name',
  116: 'certificate_required',
}

const isGrease = (v: number) => (v & 0x0f0f) === 0x0a0a && (v >> 8) === (v & 0xff)

function parseHello(bytes: Uint8Array, pos: number, end: number, isClient: boolean, children: Region[], summary: string[]): void {
  const r = new ByteReader(bytes, pos)
  const legacyVersion = r.u16be()
  children.push(region('Legacy version', pos, 2, { value: VERSIONS[legacyVersion] ?? '0x' + hex(legacyVersion, 4), note: 'Frozen at TLS 1.2 for middlebox compatibility — the real version hides in the supported_versions extension.' }))
  children.push(region('Random', r.pos, 32, { note: '32 bytes of client/server randomness mixed into the key derivation.' }))
  r.skip(32)
  const sidLen = r.u8()
  children.push(region('Session ID', r.pos - 1, 1 + sidLen, { value: sidLen ? `${sidLen} bytes` : 'empty', note: 'Legacy resumption mechanism; TLS 1.3 sends a fake one for middlebox compatibility.' }))
  r.skip(sidLen)

  if (isClient) {
    const csLen = r.u16be()
    const csStart = r.pos
    const names: string[] = []
    for (let i = 0; i < csLen / 2; i++) {
      const cs = r.u16be()
      if (isGrease(cs)) names.push(`GREASE (0x${hex(cs, 4)})`)
      else names.push(CIPHERS[cs] ?? `0x${hex(cs, 4)}`)
    }
    children.push(
      region('Cipher suites', csStart - 2, 2 + csLen, {
        value: `${csLen / 2} offered`,
        note: 'What the client can do, in preference order. GREASE values are deliberate junk (RFC 8701) that keeps servers honest about ignoring unknown values. ' + names.slice(0, 8).join(', ') + (names.length > 8 ? ', …' : ''),
      }),
    )
    const compLen = r.u8()
    r.skip(compLen)
  } else {
    const cs = r.u16be()
    children.push(region('Cipher suite (chosen)', r.pos - 2, 2, { value: CIPHERS[cs] ?? `0x${hex(cs, 4)}` }))
    summary.push(`TLS cipher: ${CIPHERS[cs] ?? '0x' + hex(cs, 4)}`)
    r.skip(1) // compression
  }

  if (r.pos + 2 > end) return
  const extTotal = r.u16be()
  const extEnd = Math.min(end, r.pos + extTotal)
  while (r.pos + 4 <= extEnd) {
    const extStart = r.pos
    const extType = r.u16be()
    const extLen = r.u16be()
    const dataStart = r.pos
    const name = isGrease(extType) ? `GREASE (0x${hex(extType, 4)})` : (EXTENSIONS[extType] ?? `extension ${extType}`)
    let value = extLen ? `${extLen} B` : 'empty'
    let note: string | undefined

    try {
      if (extType === 0 && extLen >= 5) {
        const nameLen = (bytes[dataStart + 3] << 8) | bytes[dataStart + 4]
        const sni = latin1(bytes.subarray(dataStart + 5, dataStart + 5 + nameLen))
        value = sni
        note = 'Server Name Indication — the hostname travels in PLAINTEXT here, visible to any on-path observer. Encrypted ClientHello (ECH) is the fix in progress.'
        summary.push(`SNI: ${sni}`)
      } else if (extType === 16 && extLen >= 3) {
        const protos: string[] = []
        let p = dataStart + 2
        while (p < dataStart + extLen) {
          const l = bytes[p]
          protos.push(latin1(bytes.subarray(p + 1, p + 1 + l)))
          p += 1 + l
        }
        value = protos.join(', ')
        note = 'Application-Layer Protocol Negotiation: agree on h2 vs http/1.1 during the handshake, saving a round-trip.'
      } else if (extType === 43 && extLen >= 2) {
        const vers: string[] = []
        if (isClient) {
          const listLen = bytes[dataStart]
          for (let p = dataStart + 1; p < dataStart + 1 + listLen; p += 2) {
            const v = (bytes[p] << 8) | bytes[p + 1]
            vers.push(isGrease(v) ? 'GREASE' : (VERSIONS[v] ?? '0x' + hex(v, 4)))
          }
        } else {
          const v = (bytes[dataStart] << 8) | bytes[dataStart + 1]
          vers.push(VERSIONS[v] ?? '0x' + hex(v, 4))
        }
        value = vers.join(', ')
        note = 'The REAL protocol version negotiation for TLS 1.3.'
        if (vers.includes('TLS 1.3')) summary.push('offers TLS 1.3')
      } else if (extType === 10 && extLen >= 2) {
        const groups: string[] = []
        for (let p = dataStart + 2; p + 1 < dataStart + extLen; p += 2) {
          const g = (bytes[p] << 8) | bytes[p + 1]
          groups.push(isGrease(g) ? 'GREASE' : (GROUPS[g] ?? '0x' + hex(g, 4)))
        }
        value = groups.join(', ')
        note = 'Elliptic curves / DH groups supported for key exchange.'
      } else if (extType === 51) {
        note = 'Key share: the client guesses the group and sends its public key immediately — this is how TLS 1.3 achieves a 1-RTT handshake.'
      }
    } catch {
      /* keep generic value on truncation */
    }

    children.push(region(`Extension: ${name}`, extStart, 4 + extLen, { value, note }))
    r.seek(dataStart + extLen)
  }
}

export const tlsLayer: LayerFn = (bytes, off, ctx): LayerResult => {
  const children: Region[] = []
  const end = Math.min(ctx.declaredEnd ?? bytes.length, bytes.length)
  let pos = off
  let label = 'TLS'
  let guard = 0

  while (pos + 5 <= end && guard++ < 16) {
    const type = bytes[pos]
    const version = (bytes[pos + 1] << 8) | bytes[pos + 2]
    const recLen = (bytes[pos + 3] << 8) | bytes[pos + 4]
    if (!RECORD_TYPES[type] || !VERSIONS[version]) break
    const recEnd = Math.min(end, pos + 5 + recLen)
    const truncated = pos + 5 + recLen > end
    const typeName = RECORD_TYPES[type]

    const recChildren: Region[] = [
      region('Content type', pos, 1, { value: `${type} — ${typeName}` }),
      region('Legacy record version', pos + 1, 2, { value: VERSIONS[version] ?? '?' }),
      region('Length', pos + 3, 2, { value: `${recLen} B${truncated ? ' (record truncated in this capture)' : ''}` }),
    ]

    if (type === 22 && recEnd - pos >= 9) {
      const hsType = bytes[pos + 5]
      const hsLen = (bytes[pos + 6] << 16) | (bytes[pos + 7] << 8) | bytes[pos + 8]
      const hsName = HANDSHAKE_TYPES[hsType] ?? `handshake type ${hsType}`
      label = `TLS ${hsName}`
      recChildren.push(region('Handshake type', pos + 5, 1, { value: `${hsType} — ${hsName}` }), region('Handshake length', pos + 6, 3, { value: `${hsLen} B` }))
      if (hsType === 1 || hsType === 2) {
        parseHello(bytes, pos + 9, Math.min(recEnd, pos + 9 + hsLen), hsType === 1, recChildren, ctx.summary)
      }
      ctx.summary.push(`TLS ${hsName}${VERSIONS[version] ? ` (record version ${VERSIONS[version]})` : ''}`)
    } else if (type === 21 && recEnd - pos >= 7) {
      const level = bytes[pos + 5]
      const desc = bytes[pos + 6]
      recChildren.push(
        region('Alert', pos + 5, 2, {
          value: `${level === 2 ? 'fatal' : 'warning'}: ${ALERTS[desc] ?? `code ${desc}`}`,
          flag: level === 2 ? 'bad' : 'warn',
        }),
      )
      ctx.summary.push(`TLS alert: ${level === 2 ? 'fatal' : 'warning'} ${ALERTS[desc] ?? desc}`)
      label = 'TLS Alert'
    } else if (type === 23) {
      recChildren.push(region('Encrypted payload', pos + 5, recEnd - pos - 5, { note: 'Application data — encrypted with the negotiated cipher. Nothing to see without the keys.' }))
      if (label === 'TLS') label = 'TLS ApplicationData'
      ctx.summary.push(`TLS application data, ${recLen} B (encrypted)`)
    }

    children.push(region(`Record: ${typeName}`, pos, recEnd - pos, { value: `${recLen} B`, children: recChildren }))
    pos = pos + 5 + recLen
  }

  if (children.length === 0) {
    return { region: region('Payload (not valid TLS)', off, end - off, {}) }
  }

  return {
    region: region(label, off, Math.min(pos, end) - off, {
      note: 'TLS records: 5-byte header (type, legacy version, length), then the record body. Everything after the handshake is opaque ciphertext.',
      children,
    }),
  }
}
